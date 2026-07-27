/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static software.amazon.encryption.s3.TestUtils.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import software.amazon.encryption.s3.TestUtils.LanguageServerTarget;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

/**
 * Every language must reject an object with tampered metadata cleanly, not crash.
 *
 * Encrypt one object, corrupt its metadata, then confirm every language returns
 * an error instead of blowing up. Done for both message formats, V2 and V3.
 */
public class MaterialDescriptionTamperTests {

    // V2 keeps the material description in x-amz-matdesc; V3 keeps it in x-amz-t.
    // Both are fed to the decoder.
    private static final String V2_MATERIAL_DESCRIPTION_HEADER = "x-amz-matdesc";
    private static final String V3_ENCRYPTION_CONTEXT_HEADER = "x-amz-t";

    // Corrupt metadata values that decode to bytes the decoder mishandles.
    private static final Map<String, String> MALICIOUS_MATERIAL_DESCRIPTIONS;
    static {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("single-0x80", "=?utf-8?B?gA==?=");
        m.put("single-0xff", "=?utf-8?B?/w==?=");
        m.put("trailing-high-byte", "=?utf-8?B?YWJj/w==?=");
        MALICIOUS_MATERIAL_DESCRIPTIONS = Collections.unmodifiableMap(m);
    }

    private static final KeyMaterial KMS_KEY = KeyMaterial.builder()
        .kmsKeyId(KMS_KEY_ARN)
        .build();

    private static List<String> tamperedV2Keys;
    private static List<String> tamperedV3Keys;

    @BeforeAll
    static void encryptOnceAndTamper() {
        validateServersRunning();

        LanguageServerTarget encryptor = improvedEncryptor();
        S3ECTestServerClient client = testServerClientFor(encryptor);

        // One V2 object.
        String v2ClientId = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(KMS_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build())
            .build()).getClientId();
        String baseV2Key = appendTestSuffix("test-matdesc-tamper-v2-" + encryptor.getLanguageName());
        Encrypt(client, v2ClientId, baseV2Key, new ArrayList<>(),
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);

        // One V3 object.
        String v3ClientId = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(KMS_KEY)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                .build())
            .build()).getClientId();
        String baseV3Key = appendTestSuffix("test-matdesc-tamper-v3-" + encryptor.getLanguageName());
        Encrypt(client, v3ClientId, baseV3Key, new ArrayList<>(),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);

        try (S3Client s3 = S3Client.create()) {
            tamperedV2Keys = writeTamperedCopies(s3, baseV2Key, V2_MATERIAL_DESCRIPTION_HEADER);
            tamperedV3Keys = writeTamperedCopies(s3, baseV3Key, V3_ENCRYPTION_CONTEXT_HEADER);
        }
    }

    @ParameterizedTest(name = "{0}: rejects a tampered V2 material description without crashing")
    @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
    void v2TamperedMaterialDescriptionIsRejected(LanguageServerTarget language) {
        Decrypt_fails(testServerClientFor(language), decryptClientId(language), tamperedV2Keys,
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }

    @ParameterizedTest(name = "{0}: rejects a tampered V3 material description without crashing")
    @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
    void v3TamperedMaterialDescriptionIsRejected(LanguageServerTarget language) {
        Decrypt_fails(testServerClientFor(language), decryptClientId(language), tamperedV3Keys,
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    // This policy lets every language read both objects, so decryption reaches the decoder.
    private static String decryptClientId(LanguageServerTarget language) {
        return testServerClientFor(language).createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(KMS_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build())
            .build()).getClientId();
    }

    private static List<String> writeTamperedCopies(S3Client s3, String baseKey, String header) {
        ResponseBytes<GetObjectResponse> encrypted = s3.getObjectAsBytes(b -> b
            .bucket(BUCKET)
            .key(baseKey));
        List<String> tampered = new ArrayList<>();
        for (Map.Entry<String, String> payload : MALICIOUS_MATERIAL_DESCRIPTIONS.entrySet()) {
            Map<String, String> metadata = new HashMap<>(encrypted.response().metadata());
            metadata.put(header, payload.getValue());
            String tamperedKey = baseKey + "-" + payload.getKey();
            s3.putObject(
                b -> b.bucket(BUCKET).key(tamperedKey).metadata(metadata),
                RequestBody.fromBytes(encrypted.asByteArray()));
            tampered.add(tamperedKey);
        }
        return tampered;
    }

    private static LanguageServerTarget improvedEncryptor() {
        Map<String, LanguageServerTarget> servers = getServerMap();
        LanguageServerTarget java = servers.get(JAVA_V4);
        if (java != null) {
            return java;
        }
        return servers.values().stream()
            .filter(t -> IMPROVED_VERSIONS.contains(t.getLanguageName()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException(
                "No improved-version server available to encrypt base objects"));
    }
}
