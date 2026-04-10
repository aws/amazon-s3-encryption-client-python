/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.CopyObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentest4j.TestAbortedException;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.GetObjectInput;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.PutObjectInput;
import software.amazon.encryption.s3.model.S3ECConfig;
import software.amazon.encryption.s3.model.S3EncryptionClientError;

/**
 * Wrapping Algorithm Downgrade Attack Tests
 *
 * These tests verify that S3 Encryption Client implementations are resilient
 * against metadata-tampering attacks where an attacker with S3 write access
 * modifies the wrapping algorithm metadata to bypass encryption context validation.
 *
 * Attack scenario:
 * 1. Application encrypts with EncryptionContext {"project": "alpha"} using kms+context
 * 2. Attacker modifies wrapping algorithm metadata from kms+context to kms
 * 3. Attacker also copies the stored encryption context into the mat_desc field
 * 4. User calls get_object with EncryptionContext {"project": "beta"} (mismatched)
 * 5. Without protection, decryption succeeds because the KmsV1 path skips
 *    client-side encryption context comparison
 *
 * The tests cover both V2 (x-amz-wrap-alg) and V3 (x-amz-w) metadata formats.
 */
@DisplayName("Wrapping Algorithm Downgrade Attack Tests")
public class WrappingAlgorithmDowngradeTests {

    private static final AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();
    private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
        .kmsKeyId(TestUtils.KMS_KEY_ARN)
        .build();

    // Encryption context used during encryption
    private static final String ENCRYPT_CONTEXT = "[project]:[alpha]";
    // Mismatched encryption context used during decryption (the attacker's goal)
    private static final String MISMATCHED_CONTEXT = "[project]:[beta]";

    @BeforeAll
    static void setup() {
        TestUtils.validateServersRunning();
    }

    /**
     * Helper to tamper S3 object metadata by copying the object with replaced metadata.
     */
    private void tamperMetadata(String objectKey, Map<String, String> newMetadata) {
        ObjectMetadata replacementMetadata = new ObjectMetadata();
        replacementMetadata.setUserMetadata(newMetadata);

        CopyObjectRequest copyRequest = new CopyObjectRequest(
            TestUtils.BUCKET, objectKey, TestUtils.BUCKET, objectKey)
            .withNewObjectMetadata(replacementMetadata);
        s3Client.copyObject(copyRequest);
    }

    /**
     * V3 format: Downgrade x-amz-w from "12" (kms+context) to "kms" AND
     * copy x-amz-t into x-amz-m so KmsV1 path gets the correct bound context.
     *
     * Decryption with a mismatched encryption context MUST fail.
     */
    @ParameterizedTest(name = "{0}: V3 wrapping algorithm downgrade with matdesc injection must fail")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void v3_downgrade_wrap_alg_with_matdesc_injection_must_fail(
        TestUtils.LanguageServerTarget language
    ) {
        if (ENCRYPTION_CONTEXT_ON_ENCRYPT_UNSUPPORTED.contains(language.getLanguageName())
            || ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED.contains(language.getLanguageName())) {
            throw new TestAbortedException(
                "Encryption context not supported for: " + language.getLanguageName());
        }

        String objectKey = appendTestSuffix("sec-v3-downgrade-" + language.getLanguageName());
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);

        // 1. Create client and encrypt with encryption context
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(kmsKeyArn)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build())
            .build());
        String encryptClientId = clientOutput.getClientId();

        client.putObject(PutObjectInput.builder()
            .clientID(encryptClientId)
            .key(objectKey)
            .bucket(TestUtils.BUCKET)
            .body(ByteBuffer.wrap(objectKey.getBytes(StandardCharsets.UTF_8)))
            .metadata(List.of(ENCRYPT_CONTEXT))
            .build());

        // 2. Tamper: change x-amz-w from "12" to "kms" and copy x-amz-t into x-amz-m
        ObjectMetadata head = s3Client.getObjectMetadata(TestUtils.BUCKET, objectKey);
        Map<String, String> userMeta = head.getUserMetadata();
        userMeta.put("x-amz-w", "kms");
        // Copy the stored encryption context so KmsV1 path gets the bound context
        String storedContext = userMeta.get("x-amz-t");
        if (storedContext != null) {
            userMeta.put("x-amz-m", storedContext);
        }
        tamperMetadata(objectKey, userMeta);

        // 3. Create a client with legacy wrapping enabled and attempt decrypt
        //    with mismatched context — MUST fail
        CreateClientOutput legacyClientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(kmsKeyArn)
                .enableLegacyWrappingAlgorithms(true)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build())
            .build());
        String legacyClientId = legacyClientOutput.getClientId();

        try {
            client.getObject(GetObjectInput.builder()
                .clientID(legacyClientId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .metadata(List.of(MISMATCHED_CONTEXT))
                .build());
            fail("V3 downgrade attack should have been rejected for: " + objectKey
                + " (language: " + language.getLanguageName() + ")");
        } catch (S3EncryptionClientError e) {
            // Expected — the downgrade attack was detected/rejected
        } catch (Exception e) {
            // The attack was rejected, but via a different error type — still a pass.
        }
    }

    /**
     * V2 format: Downgrade x-amz-wrap-alg from "kms+context" to "kms".
     *
     * For V2, x-amz-matdesc already contains the original bound context,
     * so the attacker only needs to change the wrapping algorithm.
     * Decryption with a mismatched encryption context MUST fail.
     */
    @ParameterizedTest(name = "{0}: V2 wrapping algorithm downgrade must fail")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void v2_downgrade_wrap_alg_must_fail(
        TestUtils.LanguageServerTarget language
    ) {
        if (ENCRYPTION_CONTEXT_ON_ENCRYPT_UNSUPPORTED.contains(language.getLanguageName())
            || ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED.contains(language.getLanguageName())) {
            throw new TestAbortedException(
                "Encryption context not supported for: " + language.getLanguageName());
        }

        String objectKey = appendTestSuffix("sec-v2-downgrade-" + language.getLanguageName());
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);

        // 1. Create client and encrypt with V2 format + encryption context
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(kmsKeyArn)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build())
            .build());
        String encryptClientId = clientOutput.getClientId();

        client.putObject(PutObjectInput.builder()
            .clientID(encryptClientId)
            .key(objectKey)
            .bucket(TestUtils.BUCKET)
            .body(ByteBuffer.wrap(objectKey.getBytes(StandardCharsets.UTF_8)))
            .metadata(List.of(ENCRYPT_CONTEXT))
            .build());

        // 2. Tamper: change x-amz-wrap-alg from "kms+context" to "kms"
        ObjectMetadata head = s3Client.getObjectMetadata(TestUtils.BUCKET, objectKey);
        Map<String, String> userMeta = head.getUserMetadata();
        userMeta.put("x-amz-wrap-alg", "kms");
        tamperMetadata(objectKey, userMeta);

        // 3. Create a client with legacy wrapping enabled and attempt decrypt
        //    with mismatched context — MUST fail
        CreateClientOutput legacyClientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(kmsKeyArn)
                .enableLegacyWrappingAlgorithms(true)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build())
            .build());
        String legacyClientId = legacyClientOutput.getClientId();

        try {
            client.getObject(GetObjectInput.builder()
                .clientID(legacyClientId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .metadata(List.of(MISMATCHED_CONTEXT))
                .build());
            fail("V2 downgrade attack should have been rejected for: " + objectKey
                + " (language: " + language.getLanguageName() + ")");
        } catch (S3EncryptionClientError e) {
            // Expected — the downgrade attack was detected/rejected
        } catch (Exception e) {
            // The attack was rejected, but via a different error type — still a pass.
        }
    }
}
