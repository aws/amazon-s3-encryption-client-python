/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static software.amazon.encryption.s3.TestUtils.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestClassOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.platform.suite.api.Suite;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

/**
 * GCM Test Suite
 * 
 * This suite enforces execution order between GCM encrypt and decrypt phases:
 * 1. EncryptTests (@Order(1)) - All encrypt tests run in parallel (within this phase)
 * 2. DecryptTests (@Order(2)) - All decrypt tests run in parallel (after encrypt phase completes)
 * 
 * This ensures that encrypted objects exist before decryption tests run,
 * while still allowing maximum parallelization within each phase.
 */
@Suite
@TestClassOrder(ClassOrderer.OrderAnnotation.class)
public class GCMTestSuite {
    
    /**
     * GCM Encryption Tests - Encrypt Phase
     * 
     * These tests encrypt objects using GCM encryption algorithm.
     * All tests in this class can run in parallel with each other.
     * The encrypted objects are stored in a thread-safe list for use by DecryptTests.
     */
    @Nested
    @Order(1)
    static class EncryptTests {
        private static final String sharedObjectKeyBase = "test-gcm-kms";
        private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
            .kmsKeyId(TestUtils.KMS_KEY_ARN)
            .build();
        
        // Thread-safe list for storing encrypted object keys
        private static final List<String> crossLanguageObjects = 
            Collections.synchronizedList(new ArrayList<>());
        
        /**
         * Public accessor for decrypt tests to retrieve encrypted object keys
         */
        static List<String> getCrossLanguageObjects() {
            return new ArrayList<>(crossLanguageObjects); // Return defensive copy
        }
        
        @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt should encrypt GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_forbid_encrypt_allow_decrypt_should_encrypt_gcm(
            TestUtils.LanguageServerTarget language
        ) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Encrypt(client, S3ECId, 
                appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()), 
                crossLanguageObjects, 
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
        }
        
        @ParameterizedTest(name = "{0}: Transition configured with the default should encrypt GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
        void transition_configured_with_the_default_should_encrypt_gcm(
            TestUtils.LanguageServerTarget language
        ) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    // .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Encrypt(client, S3ECId, 
                appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()), 
                crossLanguageObjects, 
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
        }

        @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt should encrypt GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
        void transition_configured_with_forbid_encrypt_allow_decrypt_should_encrypt_gcm(
            TestUtils.LanguageServerTarget language
        ) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Encrypt(client, S3ECId, 
                appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()), 
                crossLanguageObjects, 
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
        }
    }
    
    /**
     * GCM Decryption Tests - Decrypt Phase
     * 
     * These tests decrypt objects that were encrypted by EncryptTests.
     * All tests in this class can run fully in parallel with each other.
     * They depend on EncryptTests completing first (enforced by @Order).
     */
    @Nested
    @Order(2)
    static class DecryptTests {
        private static List<String> crossLanguageObjects;
        private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
            .kmsKeyId(TestUtils.KMS_KEY_ARN)
            .build();
        
        @BeforeAll
        static void setup() {
            // Import encrypted objects from the encrypt phase
            crossLanguageObjects = EncryptTests.getCrossLanguageObjects();
            
            // Verify we have objects to decrypt
            if (crossLanguageObjects.isEmpty()) {
                throw new IllegalStateException(
                    "No encrypted objects found. Ensure EncryptTests runs first.");
            }
        }
        
        @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt should decrypt GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_gcm(
            TestUtils.LanguageServerTarget language
        ) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, 
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
        }
        
        @ParameterizedTest(name = "{0}: Transition configured with the default should decrypt GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
        void transition_configured_with_the_default_should_decrypt_gcm(
            TestUtils.LanguageServerTarget language
        ) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    // .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, 
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
        }

        @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt should decrypt GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
        void transition_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_gcm(
            TestUtils.LanguageServerTarget language
        ) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, 
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
        }
        
        @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptAllowDecrypt should decrypt GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_require_encrypt_allow_decrypt_should_decrypt_gcm(
            TestUtils.LanguageServerTarget language
        ) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, 
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
        }
        
        @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should fail to decrypt GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_require_encrypt_require_decrypt_should_fail_to_decrypt_gcm(
            TestUtils.LanguageServerTarget language
        ) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Decrypt_fails(client, S3ECId, crossLanguageObjects, 
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
        }
    }
}
