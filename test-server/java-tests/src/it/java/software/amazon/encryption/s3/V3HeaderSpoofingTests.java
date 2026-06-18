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
 * This suite validates that S3EC runtimes correctly reject decryption when V3 key
 * commitment headers (x-amz-c, x-amz-d, x-amz-i) are injected into V2-encrypted objects.
 * This simulates an upgrade spoofing attack where an adversary adds fake V3 commitment
 * headers to a legitimate V2 object (which has NO real key commitment).
 *
 * Execution order:
 * 1. EncryptTests - Encrypts V2 objects and injects spoofed V3 headers in @AfterAll
 * 2. DecryptTests - Waits for encrypt phase, then verifies decryption rejection
 *
 * Coordination is achieved using a CountDownLatch that EncryptTests signals upon completion
 * and DecryptTests awaits before proceeding.
 */
public class V3HeaderSpoofingTests {
    // Synchronization latch - released when encrypt phase completes
    private static final CountDownLatch encryptPhaseComplete = new CountDownLatch(1);

    // Suffix appended to create spoofed object keys
    private static final String SUFFIX_V3_SPOOFED = "-v3spoofed";

    /**
     * Encryption Tests - Encrypt Phase
     *
     * These tests encrypt V2 objects (no key commitment) across improved language servers.
     * After all encrypt tests complete, @AfterAll injects V3 headers into the V2 metadata
     * and uploads spoofed copies to S3.
     */
    @Nested
    @DisplayName("V3HeaderSpoofingTests - Encrypt")
    class EncryptTests {
        private static final String sharedObjectKeyBase = "test-v3-header-spoof";
        private static KeyMaterial kmsKeyArn = KeyMaterial.builder()
            .kmsKeyId(TestUtils.KMS_KEY_ARN)
            .build();

        // Thread-safe lists for storing object keys
        private static final List<String> crossLanguageObjects =
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> spoofedObjectKeys =
            Collections.synchronizedList(new ArrayList<>());

        static List<String> getCrossLanguageObjects() {
            return new ArrayList<>(crossLanguageObjects);
        }

        static List<String> getSpoofedObjectKeys() {
            return new ArrayList<>(spoofedObjectKeys);
        }

        @ParameterizedTest(name = "{0}: Encrypt V2 object for V3 header spoofing test")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void encrypt_v2_object(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Encrypt(
                client,
                S3ECId,
                appendTestSuffix(sharedObjectKeyBase + "-" + language.getLanguageName()),
                crossLanguageObjects,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        /**
         * Reads each V2 object, injects fake V3 key commitment headers into the
         * existing V2 metadata, and uploads spoofed copies to S3.
         */
        static void spoofV3Headers() {
            SecureRandom random = new SecureRandom();
            try (S3Client ptS3Client = S3Client.create()) {
                for (String objectKey : crossLanguageObjects) {
                    // Read the V2 encrypted object
                    ResponseBytes<GetObjectResponse> encryptedObject = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(objectKey)
                        .build());

                    Map<String, String> originalMetadata = encryptedObject.response().metadata();

                    // Construct spoofed metadata: preserve all V2 headers and inject V3 headers
                    Map<String, String> spoofedMetadata = new HashMap<>(originalMetadata);

                    // Generate random bytes for fake V3 commitment values
                    byte[] fakeKeyCommitment = new byte[32];
                    random.nextBytes(fakeKeyCommitment);
                    byte[] fakeMessageId = new byte[28];
                    random.nextBytes(fakeMessageId);

                    // Inject V3 headers
                    spoofedMetadata.put("x-amz-c", "115");  // V3 algorithm suite ID (KC-GCM)
                    spoofedMetadata.put("x-amz-d", Base64.getEncoder().encodeToString(fakeKeyCommitment));  // Fake key commitment
                    spoofedMetadata.put("x-amz-i", Base64.getEncoder().encodeToString(fakeMessageId));  // Fake message ID

                    // Upload spoofed copy with original ciphertext body and modified metadata
                    String spoofedKey = objectKey + SUFFIX_V3_SPOOFED;
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
            spoofV3Headers();

            // Signal that all encryption tests and metadata manipulation have completed
            encryptPhaseComplete.countDown();
        }
    }

    /**
     * Decryption Tests - Decrypt Phase
     *
     * These tests verify that all S3EC runtimes reject decryption of spoofed objects
     * (V2 objects with injected V3 headers) across all commitment policies.
     * A control test confirms unmodified V2 objects still decrypt successfully.
     *
     * Execution waits for EncryptTests to complete via CountDownLatch.
     */
    @Nested
    @DisplayName("V3HeaderSpoofingTests - Decrypt")
    class DecryptTests {
        private static List<String> spoofedObjectKeys;
        private static List<String> originalObjectKeys;
        private static KeyMaterial kmsKeyArn;

        @BeforeAll
        static void setup() throws InterruptedException {
            // Wait for all encryption tests and metadata manipulation to complete
            encryptPhaseComplete.await();

            // Import object keys from the encrypt phase
            spoofedObjectKeys = EncryptTests.getSpoofedObjectKeys();
            originalObjectKeys = EncryptTests.getCrossLanguageObjects();
            kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

            // Verify we have objects to decrypt
            if (spoofedObjectKeys.isEmpty()) {
                throw new IllegalStateException(
                    "No spoofed objects found. Ensure EncryptTests runs first and spoofV3Headers() succeeds.");
            }
            if (originalObjectKeys.isEmpty()) {
                throw new IllegalStateException(
                    "No original V2 objects found. Ensure EncryptTests runs first.");
            }
        }

        public static Stream<Arguments> improvedAndTransitionClients() {
            return Stream.concat(
                TestUtils.improvedClientsForTest(),
                TestUtils.transitionClientsForTest()
            );
        }

        @ParameterizedTest(name = "{0}: Reject spoofed V3 headers with REQUIRE_ENCRYPT_REQUIRE_DECRYPT")
        @MethodSource("software.amazon.encryption.s3.V3HeaderSpoofingTests$DecryptTests#improvedAndTransitionClients")
        void reject_spoofed_require_encrypt_require_decrypt(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                spoofedObjectKeys,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Reject spoofed V3 headers with REQUIRE_ENCRYPT_ALLOW_DECRYPT")
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
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Reject spoofed V3 headers with FORBID_ENCRYPT_ALLOW_DECRYPT")
        @MethodSource("software.amazon.encryption.s3.V3HeaderSpoofingTests$DecryptTests#improvedAndTransitionClients")
        void reject_spoofed_forbid_encrypt_allow_decrypt(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                spoofedObjectKeys,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Original V2 objects decrypt successfully")
        @MethodSource("software.amazon.encryption.s3.V3HeaderSpoofingTests$DecryptTests#improvedAndTransitionClients")
        void original_v2_decrypts_successfully(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt(
                client,
                S3ECId,
                originalObjectKeys,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }
    }
}
