/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import static software.amazon.encryption.s3.TestUtils.appendTestSuffix;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

/**
 * V3 Header Spoofing Tests
 *
 * This suite validates that S3 Encryption Client runtimes correctly reject decryption
 * when V2 envelope headers (x-amz-key-v2, x-amz-cek-alg, x-amz-iv, x-amz-wrap-alg,
 * x-amz-matdesc, x-amz-tag-len) are injected into V3-committed objects.
 *
 * This simulates a downgrade attack where an adversary injects fake V2 metadata to
 * trick the client into the V2 decryption path, bypassing key commitment validation.
 *
 * Phases:
 * 1. EncryptTests - Encrypts V3 committed objects, then injects spoofed V2 headers
 * 2. DecryptTests - Waits for encrypt phase to complete, then verifies decryption rejection
 *
 * Coordination is achieved using a CountDownLatch that EncryptTests signals upon completion
 * and DecryptTests awaits before proceeding.
 */
public class V3HeaderSpoofingTests {
    // Synchronization latch - released when encrypt phase and header spoofing completes
    private static final CountDownLatch encryptPhaseComplete = new CountDownLatch(1);

    // Suffix appended to create spoofed object keys
    private static final String SUFFIX_SPOOFED = "-spoofed";

    /**
     * Encryption Tests - Encrypt Phase
     *
     * These tests encrypt V3 committed objects using KMS key material.
     * After all encrypt tests complete, @AfterAll injects spoofed V2 headers
     * onto the encrypted objects and signals the latch.
     */
    @Nested
    @DisplayName("V3HeaderSpoofingTests - Encrypt")
    class EncryptTests {
        private static final String sharedObjectKeyBase = "test-v3-spoof";
        private static KeyMaterial kmsKeyArn = KeyMaterial.builder()
            .kmsKeyId(TestUtils.KMS_KEY_ARN)
            .build();

        // Thread-safe list for storing encrypted V3 object keys
        private static final List<String> crossLanguageObjects =
            Collections.synchronizedList(new ArrayList<>());

        // Thread-safe list for storing spoofed object keys after manipulation
        private static final List<String> spoofedObjectKeys =
            Collections.synchronizedList(new ArrayList<>());

        /**
         * Returns a defensive copy of the encrypted V3 object keys.
         */
        static List<String> getCrossLanguageObjects() {
            return new ArrayList<>(crossLanguageObjects);
        }

        /**
         * Returns a defensive copy of the spoofed object keys.
         */
        static List<String> getSpoofedObjectKeys() {
            return new ArrayList<>(spoofedObjectKeys);
        }

        @ParameterizedTest(name = "{0}: Encrypt V3 committed object for spoofing test")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void encrypt_v3_committed(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Encrypt(
                client,
                S3ECId,
                appendTestSuffix(sharedObjectKeyBase + "-" + language.getLanguageName()),
                crossLanguageObjects,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        /**
         * Injects spoofed V2 headers onto each V3 committed object.
         * Uses a plaintext S3 client to read each V3 object, add fake V2 envelope
         * headers to the metadata, and upload a spoofed copy.
         */
        static void spoofV2Headers() {
            SecureRandom random = new SecureRandom();

            try (S3Client ptS3Client = S3Client.create()) {
                for (String objectKey : crossLanguageObjects) {
                    // Read the original V3 committed object
                    ResponseBytes<GetObjectResponse> encryptedObject = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(objectKey)
                        .build());

                    Map<String, String> originalMetadata = encryptedObject.response().metadata();

                    // Construct spoofed metadata: original V3 metadata + injected V2 headers
                    Map<String, String> spoofedMetadata = new HashMap<>(originalMetadata);

                    // Inject fake V2 envelope headers to simulate downgrade attack
                    byte[] fakeEdk = new byte[32];
                    random.nextBytes(fakeEdk);
                    spoofedMetadata.put("x-amz-key-v2", Base64.getEncoder().encodeToString(fakeEdk));

                    spoofedMetadata.put("x-amz-cek-alg", "AES/GCM/NoPadding");

                    byte[] fakeIv = new byte[12];
                    random.nextBytes(fakeIv);
                    spoofedMetadata.put("x-amz-iv", Base64.getEncoder().encodeToString(fakeIv));

                    spoofedMetadata.put("x-amz-wrap-alg", "kms+context");
                    spoofedMetadata.put("x-amz-matdesc", "{}");
                    spoofedMetadata.put("x-amz-tag-len", "128");

                    // Upload spoofed copy with original ciphertext body
                    String spoofedKey = objectKey + SUFFIX_SPOOFED;
                    ptS3Client.putObject(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(spoofedKey)
                        .metadata(spoofedMetadata)
                        .build(),
                        software.amazon.awssdk.core.sync.RequestBody.fromBytes(encryptedObject.asByteArray()));

                    spoofedObjectKeys.add(spoofedKey);
                }
            }
        }

        @AfterAll
        static void signalEncryptionComplete() {
            spoofV2Headers();

            // Signal that all encryption tests and header spoofing have completed
            encryptPhaseComplete.countDown();
        }
    }

    /**
     * Decryption Tests - Decrypt Phase
     *
     * These tests verify that all language servers reject decryption of spoofed objects
     * (V3 committed objects with injected V2 headers) across all commitment policies.
     * Also verifies that unmodified V3 objects still decrypt successfully.
     */
    @Nested
    @DisplayName("V3HeaderSpoofingTests - Decrypt")
    class DecryptTests {
        private static List<String> spoofedObjectKeys;
        private static List<String> originalObjectKeys;
        private static KeyMaterial kmsKeyArn;

        @BeforeAll
        static void setup() throws InterruptedException {
            // Wait for all encryption tests and header spoofing to complete
            encryptPhaseComplete.await();

            // Import object keys from the encrypt phase
            spoofedObjectKeys = EncryptTests.getSpoofedObjectKeys();
            originalObjectKeys = EncryptTests.getCrossLanguageObjects();
            kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

            // Verify we have objects to test
            if (spoofedObjectKeys.isEmpty()) {
                throw new IllegalStateException(
                    "No spoofed objects found. Ensure EncryptTests runs first and at least one server is available.");
            }
            if (originalObjectKeys.isEmpty()) {
                throw new IllegalStateException(
                    "No original V3 objects found. Ensure EncryptTests runs first and at least one server is available.");
            }
        }

        /**
         * Provides both improved and transition language servers for decrypt tests.
         */
        public static Stream<Arguments> improvedAndTransitionClients() {
            return Stream.concat(
                TestUtils.improvedClientsForTest(),
                TestUtils.transitionClientsForTest()
            );
        }

        @ParameterizedTest(name = "{0}: Reject spoofed V2 headers with REQUIRE_ENCRYPT_REQUIRE_DECRYPT")
        @MethodSource("software.amazon.encryption.s3.V3HeaderSpoofingTests$DecryptTests#improvedAndTransitionClients")
        void reject_spoofed_require_encrypt_require_decrypt(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                spoofedObjectKeys,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Reject spoofed V2 headers with REQUIRE_ENCRYPT_ALLOW_DECRYPT")
        @MethodSource("software.amazon.encryption.s3.V3HeaderSpoofingTests$DecryptTests#improvedAndTransitionClients")
        void reject_spoofed_require_encrypt_allow_decrypt(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                spoofedObjectKeys,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Reject spoofed V2 headers with FORBID_ENCRYPT_ALLOW_DECRYPT")
        @MethodSource("software.amazon.encryption.s3.V3HeaderSpoofingTests$DecryptTests#improvedAndTransitionClients")
        void reject_spoofed_forbid_encrypt_allow_decrypt(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                spoofedObjectKeys,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Original V3 committed objects decrypt successfully")
        @MethodSource("software.amazon.encryption.s3.V3HeaderSpoofingTests$DecryptTests#improvedAndTransitionClients")
        void original_v3_decrypts_successfully(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt(
                client,
                S3ECId,
                originalObjectKeys,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }
    }
}
