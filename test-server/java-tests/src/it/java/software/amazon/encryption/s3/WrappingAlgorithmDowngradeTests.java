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

import java.util.Set;

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
 * Wrapping Algorithm Downgrade Tests
 *
 * These tests verify S3 Encryption Client behavior when the wrapping algorithm
 * metadata is modified from kms+context to kms. This simulates a scenario where
 * an attacker with S3 write access tampers with object metadata to attempt to
 * bypass encryption context validation.
 *
 * V3 format: All implementations MUST reject the downgrade because "kms" is not
 * a valid V3 compressed wrapping algorithm code.
 *
 * V2 format: Implementations that validate encryption context at the pipeline
 * layer (Go, C++) reject the downgrade. Implementations that delegate context
 * validation to the keyring may not catch the downgrade in V2 format.
 */
@DisplayName("Wrapping Algorithm Downgrade Tests")
public class WrappingAlgorithmDowngradeTests {

    private static final AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();
    private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
        .kmsKeyId(TestUtils.KMS_KEY_ARN)
        .build();

    // Languages that validate encryption context at the pipeline layer,
    // making them resilient to V2 wrapping algorithm downgrade.
    private static final Set<String> V2_DOWNGRADE_RESILIENT = Set.of(
        TestUtils.GO_V4,
        TestUtils.CPP_V3
    );

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
     * V3 format: Changing x-amz-w from "12" (kms+context) to "kms" AND
     * copying x-amz-t into x-amz-m MUST be rejected.
     *
     * "kms" is not a valid V3 compressed wrapping algorithm code, so all
     * implementations MUST reject this.
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
        // Copy the stored encryption context into x-amz-m
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
            fail("V3 downgrade should have been rejected for: " + objectKey
                + " (language: " + language.getLanguageName() + ")");
        } catch (S3EncryptionClientError e) {
            // Expected — tampered wrapping algorithm was rejected
        } catch (Exception e) {
            // Rejected via a different error type — still a pass.
        }
    }

    /**
     * V2 format: Changing x-amz-wrap-alg from "kms+context" to "kms".
     *
     * For V2, x-amz-matdesc already contains the original bound context,
     * so only the wrapping algorithm needs to change.
     *
     * Languages that validate encryption context at the pipeline layer (Go, C++)
     * reject this regardless of wrapping algorithm. Other languages delegate
     * context validation to the keyring, where the KmsV1 path does not
     * perform the comparison.
     */
    @ParameterizedTest(name = "{0}: V2 wrapping algorithm downgrade")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void v2_downgrade_wrap_alg(
        TestUtils.LanguageServerTarget language
    ) {
        if (ENCRYPTION_CONTEXT_ON_ENCRYPT_UNSUPPORTED.contains(language.getLanguageName())
            || ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED.contains(language.getLanguageName())) {
            throw new TestAbortedException(
                "Encryption context not supported for: " + language.getLanguageName());
        }

        boolean expectRejection = V2_DOWNGRADE_RESILIENT.contains(language.getLanguageName());

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
        //    with mismatched context
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
            // Decryption succeeded with mismatched context
            if (expectRejection) {
                fail("V2 downgrade should have been rejected for: " + objectKey
                    + " (language: " + language.getLanguageName() + ")");
            }
            // For non-resilient languages, this is the expected (known) behavior
        } catch (S3EncryptionClientError | Exception e) {
            if (!expectRejection) {
                fail("V2 downgrade was unexpectedly rejected for: " + objectKey
                    + " (language: " + language.getLanguageName() + "): " + e.getMessage());
            }
            // For resilient languages, rejection is expected
        }
    }
}
