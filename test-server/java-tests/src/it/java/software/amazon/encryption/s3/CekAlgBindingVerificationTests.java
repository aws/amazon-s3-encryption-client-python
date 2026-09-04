/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import java.util.ArrayList;
import java.util.Base64;
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
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import org.opentest4j.TestAbortedException;
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
 * Verifies the content-encryption algorithm in the object metadata matches
 * the KMS-authenticated encryption context on decrypt:
 * an attacker with S3 write access who rewrites the unauthenticated
 * x-amz-cek-alg (V2) or x-amz-c (V3) header to downgrade a GCM or
 * committing-suite object to unauthenticated AES-CBC must be rejected.
 */
@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@Execution(ExecutionMode.SAME_THREAD)
public class CekAlgBindingVerificationTests {

    private static final String SUFFIX_V2_GCM_TO_CBC = "-v2-gcm-to-cbc";
    private static final String SUFFIX_V3_COMMITTED_TO_CBC = "-v3-committed-to-cbc";

    private static final String CEK_ALG_CBC = "AES/CBC/PKCS5Padding";
    private static final String WRAP_ALG_KMS_CONTEXT = "kms+context";

    private static final String CBC_IV = Base64.getEncoder().encodeToString(new byte[16]);

    private static final KeyMaterial KMS_KEY = KeyMaterial.builder()
        .kmsKeyId(TestUtils.KMS_KEY_ARN)
        .build();

    @Nested
    @Order(1)
    @DisplayName("CekAlgBindingVerificationTests - Encrypt")
    class EncryptTests {
        private static final String V2_KEY_BASE = "test-cek-binding-v2";
        private static final String V3_KEY_BASE = "test-cek-binding-v3";

        private static final List<String> v2Objects = Collections.synchronizedList(new ArrayList<>());
        private static final List<String> v3Objects = Collections.synchronizedList(new ArrayList<>());
        private static final List<String> tamperedV2ToCbc = Collections.synchronizedList(new ArrayList<>());
        private static final List<String> tamperedV3ToCbc = Collections.synchronizedList(new ArrayList<>());

        @BeforeAll
        static void setup() {
            validateServersRunning();
        }

        @ParameterizedTest(name = "{0}: Encrypt V2 object for CEK-alg binding test")
        @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
        void encryptV2Object(TestUtils.LanguageServerTarget language) {
            // Encrypt a V2 GCM object to serve as the pre-modification baseline object
            S3ECTestServerClient client = testServerClientFor(language);
            String clientId = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(KMS_KEY)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .build())
                .build()).getClientId();

            Encrypt(
                client,
                clientId,
                appendTestSuffix(V2_KEY_BASE + "-" + language.getLanguageName()),
                v2Objects,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Encrypt V3 object for CEK-alg binding test")
        @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
        void encryptV3Object(TestUtils.LanguageServerTarget language) {
            // Encrypt a V3 key-committing object: only improved clients support this suite
            if (!TestUtils.IMPROVED_VERSIONS.contains(language.getLanguageName())) {
                throw new TestAbortedException(
                    "Key commitment (V3) not supported by: " + language.getLanguageName());
            }
            S3ECTestServerClient client = testServerClientFor(language);
            String clientId = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(KMS_KEY)
                    .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                    .build())
                .build()).getClientId();

            Encrypt(
                client,
                clientId,
                appendTestSuffix(V3_KEY_BASE + "-" + language.getLanguageName()),
                v3Objects,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        // Simulates the attack: uses a raw S3 client to rewrite the CEK-algorithm in each object's
        // metadata to CBC while leaving the ciphertext and KMS-authenticated context intact.
        @AfterAll
        static void modifyCekAlgToCbc() {
            try (S3Client s3 = S3Client.create()) {
                for (String objectKey : v2Objects) {
                    ResponseBytes<GetObjectResponse> storedObject =
                        s3.getObjectAsBytes(b -> b.bucket(TestUtils.BUCKET).key(objectKey));
                    Map<String, String> objectMetadata =
                        modifyV2MetadataToCbc(storedObject.response().metadata());

                    String modifiedObjectKey = objectKey + SUFFIX_V2_GCM_TO_CBC;
                    s3.putObject(
                        b -> b.bucket(TestUtils.BUCKET).key(modifiedObjectKey).metadata(objectMetadata),
                        RequestBody.fromBytes(storedObject.asByteArray()));
                    tamperedV2ToCbc.add(modifiedObjectKey);
                }

                for (String objectKey : v3Objects) {
                    ResponseBytes<GetObjectResponse> storedObject =
                        s3.getObjectAsBytes(b -> b.bucket(TestUtils.BUCKET).key(objectKey));
                    Map<String, String> objectMetadata =
                        modifyV3MetadataToV2Cbc(storedObject.response().metadata());

                    String modifiedObjectKey = objectKey + SUFFIX_V3_COMMITTED_TO_CBC;
                    s3.putObject(
                        b -> b.bucket(TestUtils.BUCKET).key(modifiedObjectKey).metadata(objectMetadata),
                        RequestBody.fromBytes(storedObject.asByteArray()));
                    tamperedV3ToCbc.add(modifiedObjectKey);
                }
            }
        }

        // Modifies a V2 GCM object's metadata: only the content algorithm
        // (x-amz-cek-alg) and IV (x-amz-iv) change. The EDK, wrap algorithm, and KMS-authenticated
        // context are left intact.
        private static Map<String, String> modifyV2MetadataToCbc(Map<String, String> original) {
            Map<String, String> objectMetadata = new HashMap<>(original);
            objectMetadata.put("x-amz-cek-alg", CEK_ALG_CBC);
            objectMetadata.put("x-amz-iv", CBC_IV);
            return objectMetadata;
        }

        // Modifies a V3 object's metadata to look like a V2 kms+context CBC object.
        // The V3 encrypted data key (x-amz-3) and KMS-authenticated context (x-amz-t) are
        // copied into their respective V2 header names, then the V2 wrap algorithm, content
        // algorithm, and IV headers are set.
        //
        // These four V3 headers (x-amz-3, x-amz-c, x-amz-d, x-amz-i) MUST be removed
        // or the object is rejected before decryption.
        //
        // The remaining V3 headers (x-amz-w, x-amz-t, x-amz-m) can be omitted.
        private static Map<String, String> modifyV3MetadataToV2Cbc(Map<String, String> original) {
            Map<String, String> objectMetadata = new HashMap<>(original);
            objectMetadata.put("x-amz-key-v2", original.get("x-amz-3"));
            objectMetadata.put("x-amz-matdesc", original.get("x-amz-t"));
            objectMetadata.put("x-amz-wrap-alg", WRAP_ALG_KMS_CONTEXT);
            objectMetadata.put("x-amz-cek-alg", CEK_ALG_CBC);
            objectMetadata.put("x-amz-iv", CBC_IV);
            objectMetadata.remove("x-amz-3");
            objectMetadata.remove("x-amz-c");
            objectMetadata.remove("x-amz-d");
            objectMetadata.remove("x-amz-i");
            return objectMetadata;
        }
    }

    @Nested
    @Order(2)
    @DisplayName("CekAlgBindingVerificationTests - Decrypt")
    class DecryptTests {
        private static List<String> v2Objects;
        private static List<String> v3Objects;
        private static List<String> tamperedV2ToCbc;
        private static List<String> tamperedV3ToCbc;

        @BeforeAll
        static void setup() {
            v2Objects = new ArrayList<>(EncryptTests.v2Objects);
            v3Objects = new ArrayList<>(EncryptTests.v3Objects);
            tamperedV2ToCbc = new ArrayList<>(EncryptTests.tamperedV2ToCbc);
            tamperedV3ToCbc = new ArrayList<>(EncryptTests.tamperedV3ToCbc);

            if (tamperedV2ToCbc.isEmpty()) {
                throw new IllegalStateException(
                    "No V2 tampered objects: EncryptTests.modifyCekAlgToCbc() did not run.");
            }
        }

        @ParameterizedTest(name = "{0}: Reject GCM->CBC CEK-algorithm downgrade (V2)")
        @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
        void rejectV2GcmToCbcDowngrade(TestUtils.LanguageServerTarget language) {
            // Even under the legacy + ALLOW_DECRYPT config, the CBC-downgraded object must be rejected
            requireImproved(language);
            String clientId = createClient(language,
                CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, true,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);

            Decrypt_fails(
                testServerClientFor(language),
                clientId,
                tamperedV2ToCbc,
                EncryptionAlgorithm.ALG_AES_256_CBC_IV16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Reject V3-committing->CBC CEK-alg downgrade")
        @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
        void rejectV3CommittedToCbcDowngrade(TestUtils.LanguageServerTarget language) {
            // A committing object rewritten into a V2 CBC downgraded object must be rejected
            requireImproved(language);
            if (tamperedV3ToCbc.isEmpty()) {
                throw new AssertionError(
                    "Improved client " + language.getLanguageName() + " produced no V3 objects to test.");
            }
            String clientId = createClient(language,
                CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, true,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);

            Decrypt_fails(
                testServerClientFor(language),
                clientId,
                tamperedV3ToCbc,
                EncryptionAlgorithm.ALG_AES_256_CBC_IV16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Untampered V2 GCM object still decrypts")
        @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
        void originalV2ObjectDecryptsSuccessfully(TestUtils.LanguageServerTarget language) {
            // An untampered V2 GCM object must still decrypt
            String clientId = createClient(language,
                CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, false,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);

            Decrypt(
                testServerClientFor(language),
                clientId,
                v2Objects,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Untampered V3 committed object still decrypts")
        @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
        void originalV3ObjectDecryptsSuccessfully(TestUtils.LanguageServerTarget language) {
            // An untampered V3 committing object must still decrypt
            requireImproved(language);
            if (v3Objects.isEmpty()) {
                throw new AssertionError(
                    "Improved client " + language.getLanguageName() + " produced no V3 objects to test.");
            }
            String clientId = createClient(language,
                CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, false,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);

            Decrypt(
                testServerClientFor(language),
                clientId,
                v3Objects,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        private static void requireImproved(TestUtils.LanguageServerTarget language) {
            if (!TestUtils.IMPROVED_VERSIONS.contains(language.getLanguageName())) {
                throw new TestAbortedException(
                    "CEK-alg binding verification requires an improved (V3/V4) client: "
                        + language.getLanguageName());
            }
        }

        // Builds a decrypt client: enableLegacyUnauthenticatedModes must be true to do CBC decryption
        private String createClient(TestUtils.LanguageServerTarget language,
                                    CommitmentPolicy policy,
                                    boolean enableLegacyUnauthenticatedModes,
                                    EncryptionAlgorithm algorithm) {
            S3ECConfig.Builder configBuilder = S3ECConfig.builder()
                .keyMaterial(KMS_KEY)
                .commitmentPolicy(policy)
                .enableLegacyUnauthenticatedModes(enableLegacyUnauthenticatedModes);
            if (algorithm != null) {
                configBuilder.encryptionAlgorithm(algorithm);
            }
            return testServerClientFor(language)
                .createClient(CreateClientInput.builder().config(configBuilder.build()).build())
                .getClientId();
        }
    }
}
