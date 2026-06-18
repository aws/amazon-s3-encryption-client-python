/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestClassOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import static software.amazon.encryption.s3.TestUtils.Decrypt;
import static software.amazon.encryption.s3.TestUtils.Decrypt_fails;
import static software.amazon.encryption.s3.TestUtils.Encrypt;
import static software.amazon.encryption.s3.TestUtils.appendTestSuffix;
import static software.amazon.encryption.s3.TestUtils.testServerClientFor;
import static software.amazon.encryption.s3.TestUtils.validateServersRunning;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

/**
 * Validates that S3EC runtimes reject decryption when V3 key commitment headers
 * (x-amz-c, x-amz-w) are injected into V2-encrypted objects, simulating an
 * upgrade spoofing attack.
 *
 * EncryptTests runs first (@Order(1)), encrypts V2 objects, then injects spoofed
 * V3 headers in @AfterAll. DecryptTests (@Order(2)) verifies decryption rejection.
 */
@TestClassOrder(ClassOrderer.OrderAnnotation.class)
public class V3HeaderSpoofingTests {

    private static final String SUFFIX_V3_SPOOFED = "-v3spoofed";
    private static final KeyMaterial KMS_KEY = KeyMaterial.builder()
        .kmsKeyId(TestUtils.KMS_KEY_ARN)
        .build();

    @Nested
    @Order(1)
    @DisplayName("V3HeaderSpoofingTests - Encrypt")
    class EncryptTests {
        private static final String SHARED_OBJECT_KEY_BASE = "test-v3-header-spoof";
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

        @BeforeAll
        static void setup() {
            validateServersRunning();
        }

        @ParameterizedTest(name = "{0}: Encrypt V2 object for V3 header spoofing test")
        @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
        void encryptV2Object(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = testServerClientFor(language);
            String clientId = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder().keyMaterial(KMS_KEY).build())
                .build()).getClientId();

            Encrypt(
                client,
                clientId,
                appendTestSuffix(SHARED_OBJECT_KEY_BASE + "-" + language.getLanguageName()),
                crossLanguageObjects,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        /**
         * Reads each V2 object, injects fake V3 key commitment headers, and uploads
         * spoofed copies to S3.
         *
         * Attack vector:
         * - x-amz-c ("115"): triggers IsV3Object()=true, bypassing the commitment policy gate
         * - x-amz-w ("12"): valid V3 compressed wrap algorithm to prevent ExpandV3WrapAlgorithm crash
         */
        @AfterAll
        static void spoofV3Headers() {
            try (S3Client s3 = S3Client.create()) {
                for (String objectKey : crossLanguageObjects) {
                    ResponseBytes<GetObjectResponse> encrypted = s3.getObjectAsBytes(b -> b
                        .bucket(TestUtils.BUCKET)
                        .key(objectKey));

                    Map<String, String> spoofedMetadata = new HashMap<>(encrypted.response().metadata());
                    spoofedMetadata.put("x-amz-c", "115");
                    spoofedMetadata.put("x-amz-w", "12");

                    String spoofedKey = objectKey + SUFFIX_V3_SPOOFED;
                    s3.putObject(
                        b -> b.bucket(TestUtils.BUCKET).key(spoofedKey).metadata(spoofedMetadata),
                        RequestBody.fromBytes(encrypted.asByteArray()));

                    spoofedObjectKeys.add(spoofedKey);
                }
            }
        }
    }

    @Nested
    @Order(2)
    @DisplayName("V3HeaderSpoofingTests - Decrypt")
    class DecryptTests {
        private static List<String> spoofedObjectKeys;
        private static List<String> originalObjectKeys;

        @BeforeAll
        static void setup() {
            spoofedObjectKeys = EncryptTests.getSpoofedObjectKeys();
            originalObjectKeys = EncryptTests.getCrossLanguageObjects();

            if (spoofedObjectKeys.isEmpty()) {
                throw new IllegalStateException(
                    "No spoofed objects found. Ensure EncryptTests ran and spoofV3Headers() succeeded.");
            }
            if (originalObjectKeys.isEmpty()) {
                throw new IllegalStateException(
                    "No original V2 objects found. Ensure EncryptTests ran.");
            }
        }

        @ParameterizedTest(name = "{0}: Reject spoofed V3 headers with REQUIRE_ENCRYPT_REQUIRE_DECRYPT")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void rejectSpoofedRequireEncryptRequireDecrypt(TestUtils.LanguageServerTarget language) {
            String clientId = createClient(language, CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, null);

            // Expected algorithm is V3 committed because spoofed x-amz-c makes
            // GetEncryptionAlgorithm classify these as committed objects.
            Decrypt_fails(
                testServerClientFor(language),
                clientId,
                spoofedObjectKeys,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Original V2 objects decrypt successfully")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void originalV2DecryptsSuccessfully(TestUtils.LanguageServerTarget language) {
            // REQUIRE_ENCRYPT_ALLOW_DECRYPT allows decrypting non-committed V2 objects
            String clientId = createClient(language,
                CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);

            Decrypt(
                testServerClientFor(language),
                clientId,
                originalObjectKeys,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        private String createClient(TestUtils.LanguageServerTarget language,
                                    CommitmentPolicy policy,
                                    EncryptionAlgorithm algorithm) {
            S3ECConfig.Builder configBuilder = S3ECConfig.builder()
                .keyMaterial(KMS_KEY)
                .commitmentPolicy(policy);
            if (algorithm != null) {
                configBuilder.encryptionAlgorithm(algorithm);
            }
            return testServerClientFor(language)
                .createClient(CreateClientInput.builder().config(configBuilder.build()).build())
                .getClientId();
        }
    }
}
