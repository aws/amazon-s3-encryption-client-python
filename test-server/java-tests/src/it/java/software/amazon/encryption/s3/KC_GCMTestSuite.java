/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentest4j.TestAbortedException;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.InstructionFileConfig;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

/**
 * KC-GCM Test Suite
 * 
 * This suite enforces execution order between KC-GCM encrypt and decrypt phases:
 * 1. EncryptTests - All encrypt tests run in parallel (within this phase)
 * 2. DecryptTests - Waits for encrypt phase to complete, then all decrypt tests run in parallel
 * 
 * Coordination is achieved using a CountDownLatch that EncryptTests signals upon completion
 * and DecryptTests awaits before proceeding.
 */
public class KC_GCMTestSuite {
    // Synchronization latch - released when encrypt phase completes
    private static final CountDownLatch encryptPhaseComplete = new CountDownLatch(1);
    
    /**
     * KC-GCM Encryption Tests - Encrypt Phase
     * 
     * These tests encrypt objects using Key Commitment GCM encryption algorithm.
     * All tests in this class can run in parallel with each other.
     * The encrypted objects are stored in thread-safe lists for use by DecryptTests.
     */
    @Nested
    class EncryptTests {
        private static final String sharedObjectKeyBaseMetaDataMode = "test-kc-gcm-kms";
        private static final String sharedObjectKeyBaseInsFileMode = "test-kc-gcm-kms-instruction-file";
        private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
            .kmsKeyId(TestUtils.KMS_KEY_ARN)
            .build();
        
        // Thread-safe lists for storing encrypted object keys
        private static final List<String> crossLanguageObjectsMetaDataMode = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> crossLanguageObjectsInstructionFiles = 
            Collections.synchronizedList(new ArrayList<>());
        
        private static KeyPair RSA_KEY_PAIR_1;

        @BeforeAll
        static void setupKeys() throws Exception {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            RSA_KEY_PAIR_1 = keyPairGen.generateKeyPair();
        }
        
        /**
         * Public accessors for decrypt tests to retrieve encrypted object keys and RSA key
         */
        static List<String> getCrossLanguageObjectsMetaDataMode() {
            return new ArrayList<>(crossLanguageObjectsMetaDataMode);
        }
        
        static List<String> getCrossLanguageObjectsInstructionFiles() {
            return new ArrayList<>(crossLanguageObjectsInstructionFiles);
        }
        
        static KeyPair getRsaKeyPair() {
            return RSA_KEY_PAIR_1;
        }
        
        @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptAllowDecrypt should encrypt KC-GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_require_encrypt_allow_decrypt_should_encrypt_kc_gcm(
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
            
            TestUtils.Encrypt(client, S3ECId, 
                appendTestSuffix(sharedObjectKeyBaseMetaDataMode + language.getLanguageName()), 
                crossLanguageObjectsMetaDataMode, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should encrypt KC-GCM (instruction file)")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_require_encrypt_require_decrypt_should_encrypt_kc_gcm_ins_file(
            TestUtils.LanguageServerTarget language
        ) {
            if (!RAW_SUPPORTED.contains(language.getLanguageName())) {
                throw new TestAbortedException("Not encrypting raw keyring with: " + language.getLanguageName());
            }

            KeyMaterial rsaKey = KeyMaterial.builder()
                .rsaKey(ByteBuffer.wrap(RSA_KEY_PAIR_1.getPrivate().getEncoded()))
                .build();

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .instructionFileConfig(InstructionFileConfig.builder()
                        .enableInstructionFilePutObject(true)
                        .build())
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                    .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                    .keyMaterial(rsaKey).build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Encrypt(client, S3ECId, 
                appendTestSuffix(sharedObjectKeyBaseInsFileMode + language.getLanguageName()), 
                crossLanguageObjectsInstructionFiles, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should encrypt KC-GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_require_encrypt_require_decrypt_should_encrypt_kc_gcm(
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
            
            TestUtils.Encrypt(client, S3ECId, 
                appendTestSuffix(sharedObjectKeyBaseMetaDataMode + language.getLanguageName()), 
                crossLanguageObjectsMetaDataMode, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Improved configured with the default should encrypt KC-GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_the_default_should_encrypt_kc_gcm(
            TestUtils.LanguageServerTarget language
        ) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    // .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Encrypt(client, S3ECId, 
                appendTestSuffix(sharedObjectKeyBaseMetaDataMode + language.getLanguageName()), 
                crossLanguageObjectsMetaDataMode, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }
        
        @AfterAll
        static void signalEncryptionComplete() {
            // Signal that all encryption tests have completed
            encryptPhaseComplete.countDown();
        }
    }
    
    /**
     * KC-GCM Decryption Tests - Decrypt Phase
     * 
     * These tests decrypt objects that were encrypted by EncryptTests.
     * All tests in this class can run fully in parallel with each other.
     * They depend on EncryptTests completing first (enforced by @Order).
     */
    @Nested
    class DecryptTests {
        private static List<String> crossLanguageObjectsMetaDataMode;
        private static List<String> crossLanguageObjectsInstructionFiles;
        private static KeyPair RSA_KEY_PAIR_1;
        private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
            .kmsKeyId(TestUtils.KMS_KEY_ARN)
            .build();
        
        @BeforeAll
        static void setup() throws InterruptedException {
            // Wait for all encryption tests to complete
            encryptPhaseComplete.await();
            
            // Import encrypted objects and RSA key from the encrypt phase
            crossLanguageObjectsMetaDataMode = EncryptTests.getCrossLanguageObjectsMetaDataMode();
            crossLanguageObjectsInstructionFiles = EncryptTests.getCrossLanguageObjectsInstructionFiles();
            RSA_KEY_PAIR_1 = EncryptTests.getRsaKeyPair();
            
            // Verify we have objects to decrypt
            if (crossLanguageObjectsMetaDataMode.isEmpty()) {
                throw new IllegalStateException(
                    "No encrypted objects found. Ensure EncryptTests runs first.");
            }
        }
        
        @ParameterizedTest(name = "{0}: Transition configured with the default should decrypt KC-GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
        void transition_configured_with_the_default_should_decrypt_kc_gcm(
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
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt should decrypt KC-GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
        void transition_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_kc_gcm(
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
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt should decrypt KC-GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_kc_gcm(
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
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }
        
        @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptAllowDecrypt should decrypt KC-GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_require_encrypt_allow_decrypt_should_decrypt_kc_gcm(
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
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }
        
        @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should decrypt KC-GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_require_encrypt_require_decrypt_should_decrypt_kc_gcm(
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
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Improved configured with the default should decrypt KC-GCM")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_the_default_should_decrypt_kc_gcm(
            TestUtils.LanguageServerTarget language
        ) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    // .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should decrypt KC-GCM (instruction file)")
        @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
        void improved_configured_with_require_encrypt_require_decrypt_should_decrypt_kc_gcm_ins_file(
            final TestUtils.LanguageServerTarget language
        ) {
            if (!RAW_SUPPORTED.contains(language.getLanguageName())) {
                throw new TestAbortedException("Not encrypting raw keyring with: " + language.getLanguageName());
            }

            KeyMaterial rsaKey = KeyMaterial.builder()
                .rsaKey(ByteBuffer.wrap(RSA_KEY_PAIR_1.getPrivate().getEncoded()))
                .build();

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .instructionFileConfig(InstructionFileConfig.builder()
                        .enableInstructionFilePutObject(true)
                        .build())
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                    .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                    .keyMaterial(rsaKey).build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsInstructionFiles, 
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }
    }
}
