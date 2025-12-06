/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Stream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;

import software.amazon.encryption.s3.TestUtils.LanguageServerTarget;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.InstructionFileConfig;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.ReEncryptInput;
import software.amazon.encryption.s3.model.ReEncryptOutput;
import software.amazon.encryption.s3.model.S3ECConfig;
import software.amazon.encryption.s3.model.S3EncryptionClientError;

/**
 * ReEncrypt Instruction File Tests - S3 Encryption Client Cross-Language Compatibility
 * 
 * PURPOSE:
 * This test suite validates that instruction file re-encryption enables key rotation without
 * re-uploading encrypted objects, and that re-encrypted objects maintain cross-language
 * compatibility and commitment validation guarantees.
 * 
 * WHAT IS BEING TESTED:
 * 1. Instruction file re-encryption for KC-GCM algorithm with raw keyrings
 * 2. Re-encryption across different raw keyring types (AES, RSA)
 * 3. Same-type keyring rotation (AES => AES, RSA => RSA)
 * 4. Cross-type keyring rotation (AES => RSA, RSA => AES)
 * 5. Default instruction file suffix (.instruction) and custom suffixes (.instruction-rsa, .instruction-aes)
 * 6. Cross-language compatibility: all languages can decrypt after re-encryption
 * 7. Rotation enforcement to prevent re-encryption with the same key
 * 
 * WHY THIS IS IMPORTANT:
 * - Key rotation is a critical security operation that should not require expensive object re-uploads
 * - ReEncryptInstructionFile enables updating the encrypted data key without touching the ciphertext
 * - Raw keyrings (AES, RSA) provide direct key material access required for re-encryption
 * - Cross-type rotation (e.g., AES to RSA) enables flexibility in key management strategies
 * - Commitment validation must be maintained even when instruction files are re-encrypted
 * - Cross-language compatibility ensures key rotation doesn't break existing clients
 * - Rotation enforcement prevents accidental re-encryption with the same key material
 * - Custom instruction file suffixes enable sharing encrypted objects with partners
 * 
 * TEST STRUCTURE:
 * This suite uses a three-phase approach with enforced ordering:
 * 1. EncryptTests - Encrypts objects with instruction files using AES and RSA keyrings
 *    - All encrypt tests can run in parallel within this phase
 *    - Signals encryptPhaseComplete latch when done
 * 2. ReEncryptTests - Waits for encryption to complete, then re-encrypts instruction files
 *    - Tests same-type rotations (AES => AES, RSA => RSA)
 *    - Tests cross-type rotations (AES => RSA with .instruction-rsa suffix, RSA => AES with .instruction-aes suffix)
 *    - Tests rotation enforcement (same key rejection)
 *    - All re-encrypt tests can run in parallel within this phase
 *    - Tracks which objects were re-encrypted to which keys to prevent conflicts
 *    - Signals reEncryptPhaseComplete latch when done
 * 3. DecryptReEncryptedTests - Waits for re-encryption to complete, then tests decryption
 *    - Tests cross-language decryption compatibility after re-encryption
 *    - Uses tracked object lists to decrypt with correct keys and custom instruction file suffixes
 *    - All decrypt tests can run in parallel within this phase
 * 
 * Coordination uses two CountDownLatches:
 * - encryptPhaseComplete: Ensures all encryption completes before re-encryption begins
 * - reEncryptPhaseComplete: Ensures all re-encryption completes before decryption begins
 * 
 * INPUT DIMENSIONS:
 * - Source Key Material: AES (256-bit), RSA (2048-bit key pairs)
 * - Destination Key Material: Different AES or RSA keys (raw keyrings)
 * - Encryption Algorithm: KC-GCM (ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
 * - Instruction File Suffix: default (.instruction), custom (.instruction-rsa, .instruction-aes)
 * - Language for Re-encryption: Java V3-Transition, Java V4 (RE_ENCRYPT_SUPPORTED)
 * - Language for Decryption: All languages supporting instruction files
 * - Rotation Enforcement: enforceRotation flag (true/false)
 * 
 * EXPECTED RESULTS:
 * - Positive: Re-encryption succeeds with different key material, all languages can decrypt
 * - Negative: Re-encryption fails when enforceRotation detects same key material
 * 
 * REPRESENTATIVE VALUES:
 * - Object keys themselves (short strings) serve as representative small plaintext files
 * - Instruction file suffix: ".instruction" (default), ".instruction-rsa", ".instruction-aes"
 * - Key materials: Generated once per type and reused across tests
 * 
 * FILTERING:
 * - Only languages in RE_ENCRYPT_SUPPORTED can perform re-encryption operations
 * - Languages in INSTRUCTION_FILE_GET_UNSUPPORTED cannot decrypt with instruction files
 * 
 * NOTE: KMS keyrings are NOT supported for re-encryption as the reEncryptInstructionFile
 * method requires RawKeyring instances (AES or RSA) which provide direct access to key material.
 * 
 */
public class ReEncryptTests {
    // Synchronization latches for three-phase coordination
    private static final CountDownLatch encryptPhaseComplete = new CountDownLatch(1);
    private static final CountDownLatch reEncryptPhaseComplete = new CountDownLatch(1);
    
    // Tracking lists for re-encrypted objects - shared across nested test classes
    private static final List<String> reEncryptedAesToAes = Collections.synchronizedList(new ArrayList<>());
    private static final List<String> reEncryptedRsaToRsa = Collections.synchronizedList(new ArrayList<>());
    private static final List<String> reEncryptedAesToRsa = Collections.synchronizedList(new ArrayList<>());
    private static final List<String> reEncryptedRsaToAesDefault = Collections.synchronizedList(new ArrayList<>());
    private static final List<String> reEncryptedAesToRsaDefault = Collections.synchronizedList(new ArrayList<>());

    @Nested
    @DisplayName("ReEncryptTests - Encrypt")
    class EncryptTests {
        private static final String sharedObjectKeyBase = "test-reencrypt";
        
        private static SecretKey aesKey1, aesKey2;
        private static KeyMaterial aesKeyMaterial1, aesKeyMaterial2;
        private static KeyPair rsaKeyPair1, rsaKeyPair2;
        private static KeyMaterial rsaKeyMaterial1, rsaKeyMaterial2;
        
        // Separate object lists for each re-encryption path to avoid conflicts
        private static final List<String> kcGcmObjectsAesToAes = Collections.synchronizedList(new ArrayList<>());
        private static final List<String> kcGcmObjectsAesToRsaCustom = Collections.synchronizedList(new ArrayList<>());
        private static final List<String> kcGcmObjectsAesToRsaDefault = Collections.synchronizedList(new ArrayList<>());
        private static final List<String> kcGcmObjectsRsaToRsa = Collections.synchronizedList(new ArrayList<>());
        private static final List<String> kcGcmObjectsRsaToAesDefault = Collections.synchronizedList(new ArrayList<>());

        @BeforeAll
        static void generateKeys() throws Exception {
            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
            aesKeyGen.init(256);
            aesKey1 = aesKeyGen.generateKey();
            aesKey2 = aesKeyGen.generateKey();
            
            Map<String, String> aesMatDesc1 = new HashMap<>();
            aesMatDesc1.put("keyId", "aes-key-1");
            aesKeyMaterial1 = KeyMaterial.builder()
                .aesKey(ByteBuffer.wrap(aesKey1.getEncoded()))
                .materialsDescription(aesMatDesc1)
                .build();
            
            Map<String, String> aesMatDesc2 = new HashMap<>();
            aesMatDesc2.put("keyId", "aes-key-2");
            aesKeyMaterial2 = KeyMaterial.builder()
                .aesKey(ByteBuffer.wrap(aesKey2.getEncoded()))
                .materialsDescription(aesMatDesc2)
                .build();
            
            KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
            rsaKeyGen.initialize(2048);
            rsaKeyPair1 = rsaKeyGen.generateKeyPair();
            rsaKeyPair2 = rsaKeyGen.generateKeyPair();
            
            Map<String, String> rsaMatDesc1 = new HashMap<>();
            rsaMatDesc1.put("keyId", "rsa-key-1");
            rsaKeyMaterial1 = KeyMaterial.builder()
                .rsaKey(ByteBuffer.wrap(rsaKeyPair1.getPrivate().getEncoded()))
                .materialsDescription(rsaMatDesc1)
                .build();
            
            Map<String, String> rsaMatDesc2 = new HashMap<>();
            rsaMatDesc2.put("keyId", "rsa-key-2");
            rsaKeyMaterial2 = KeyMaterial.builder()
                .rsaKey(ByteBuffer.wrap(rsaKeyPair2.getPrivate().getEncoded()))
                .materialsDescription(rsaMatDesc2)
                .build();
        }

        static List<String> getKcGcmObjectsAesToAes() { return new ArrayList<>(kcGcmObjectsAesToAes); }
        static List<String> getKcGcmObjectsAesToRsaCustom() { return new ArrayList<>(kcGcmObjectsAesToRsaCustom); }
        static List<String> getKcGcmObjectsAesToRsaDefault() { return new ArrayList<>(kcGcmObjectsAesToRsaDefault); }
        static List<String> getKcGcmObjectsRsaToRsa() { return new ArrayList<>(kcGcmObjectsRsaToRsa); }
        static List<String> getKcGcmObjectsRsaToAesDefault() { return new ArrayList<>(kcGcmObjectsRsaToAesDefault); }
        static KeyMaterial getAesKeyMaterial1() { return aesKeyMaterial1; }
        static KeyMaterial getAesKeyMaterial2() { return aesKeyMaterial2; }
        static KeyMaterial getRsaKeyMaterial1() { return rsaKeyMaterial1; }
        static KeyMaterial getRsaKeyMaterial2() { return rsaKeyMaterial2; }

        public static Stream<Arguments> improvedClientsCanPutRawRSAWithInstructionFile() {
            return improvedClientsForTest()
                .filter(target -> !INSTRUCTION_FILE_PUT_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
                .filter(target -> RAW_RSA_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        }

        public static Stream<Arguments> improvedClientsCanPutRawAESWithInstructionFile() {
            return improvedClientsForTest()
                .filter(target -> !INSTRUCTION_FILE_PUT_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
                .filter(target -> RAW_AES_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        }

        @ParameterizedTest(name = "{0}: Encrypt AES objects for AES => AES re-encryption")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$EncryptTests#improvedClientsCanPutRawAESWithInstructionFile")
        void encryptAesForAesToAesReencrypt(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(aesKeyMaterial1)
                    .instructionFileConfig(InstructionFileConfig.builder()
                        .enableInstructionFilePutObject(true)
                        .build())
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Encrypt(client, S3ECId,
                appendTestSuffix(sharedObjectKeyBase + "-aes-to-aes-" + language.getLanguageName()),
                kcGcmObjectsAesToAes, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Encrypt AES objects for AES => RSA custom suffix re-encryption")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$EncryptTests#improvedClientsCanPutRawAESWithInstructionFile")
        void encryptAesForAesToRsaCustomReencrypt(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(aesKeyMaterial1)
                    .instructionFileConfig(InstructionFileConfig.builder()
                        .enableInstructionFilePutObject(true)
                        .build())
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Encrypt(client, S3ECId,
                appendTestSuffix(sharedObjectKeyBase + "-aes-to-rsa-custom-" + language.getLanguageName()),
                kcGcmObjectsAesToRsaCustom, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Encrypt AES objects for AES => RSA default suffix re-encryption")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$EncryptTests#improvedClientsCanPutRawAESWithInstructionFile")
        void encryptAesForAesToRsaDefaultReencrypt(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(aesKeyMaterial1)
                    .instructionFileConfig(InstructionFileConfig.builder()
                        .enableInstructionFilePutObject(true)
                        .build())
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Encrypt(client, S3ECId,
                appendTestSuffix(sharedObjectKeyBase + "-aes-to-rsa-default-" + language.getLanguageName()),
                kcGcmObjectsAesToRsaDefault, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Encrypt RSA objects for RSA => RSA re-encryption")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$EncryptTests#improvedClientsCanPutRawRSAWithInstructionFile")
        void encryptRsaForRsaToRsaReencrypt(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(rsaKeyMaterial1)
                    .instructionFileConfig(InstructionFileConfig.builder()
                        .enableInstructionFilePutObject(true)
                        .build())
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Encrypt(client, S3ECId,
                appendTestSuffix(sharedObjectKeyBase + "-rsa-to-rsa-" + language.getLanguageName()),
                kcGcmObjectsRsaToRsa, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @ParameterizedTest(name = "{0}: Encrypt RSA objects for RSA => AES default suffix re-encryption")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$EncryptTests#improvedClientsCanPutRawRSAWithInstructionFile")
        void encryptRsaForRsaToAesDefaultReencrypt(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(rsaKeyMaterial1)
                    .instructionFileConfig(InstructionFileConfig.builder()
                        .enableInstructionFilePutObject(true)
                        .build())
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.Encrypt(client, S3ECId,
                appendTestSuffix(sharedObjectKeyBase + "-rsa-to-aes-default-" + language.getLanguageName()),
                kcGcmObjectsRsaToAesDefault, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
        }

        @AfterAll
        static void signalEncryptionComplete() {
            encryptPhaseComplete.countDown();
        }
    }

    @Nested
    @DisplayName("ReEncryptTests - ReEncrypt")
    class ReEncryptTestsNested {
        private static List<String> kcGcmObjectsAesToAes, kcGcmObjectsAesToRsaCustom, kcGcmObjectsAesToRsaDefault;
        private static List<String> kcGcmObjectsRsaToRsa, kcGcmObjectsRsaToAesDefault;
        private static KeyMaterial aesKeyMaterial1, aesKeyMaterial2, rsaKeyMaterial1, rsaKeyMaterial2;

        @BeforeAll
        static void setup() throws InterruptedException {
            encryptPhaseComplete.await();
            kcGcmObjectsAesToAes = EncryptTests.getKcGcmObjectsAesToAes();
            kcGcmObjectsAesToRsaCustom = EncryptTests.getKcGcmObjectsAesToRsaCustom();
            kcGcmObjectsAesToRsaDefault = EncryptTests.getKcGcmObjectsAesToRsaDefault();
            kcGcmObjectsRsaToRsa = EncryptTests.getKcGcmObjectsRsaToRsa();
            kcGcmObjectsRsaToAesDefault = EncryptTests.getKcGcmObjectsRsaToAesDefault();
            aesKeyMaterial1 = EncryptTests.getAesKeyMaterial1();
            aesKeyMaterial2 = EncryptTests.getAesKeyMaterial2();
            rsaKeyMaterial1 = EncryptTests.getRsaKeyMaterial1();
            rsaKeyMaterial2 = EncryptTests.getRsaKeyMaterial2();
        }

        public static Stream<Arguments> reencryptSupportedClients() {
            return improvedClientsForTest()
                .filter(target -> RE_ENCRYPT_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        }

        @ParameterizedTest(name = "{0}: ReEncrypt AES => AES instruction file")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$ReEncryptTestsNested#reencryptSupportedClients")
        void reencryptAesToAesInstructionFile(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            
            for (int i = 0; i < kcGcmObjectsAesToAes.size(); i++) {
                String objectKey = kcGcmObjectsAesToAes.get(i);
                CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                    .config(S3ECConfig.builder()
                        .keyMaterial(aesKeyMaterial1)
                        .instructionFileConfig(InstructionFileConfig.builder()
                            .enableInstructionFilePutObject(true)
                            .build())
                        .build())
                    .build());
                String S3ECId = clientOutput.getClientId();

                ReEncryptOutput response = client.reEncrypt(ReEncryptInput.builder()
                        .bucket(TestUtils.BUCKET).key(objectKey).clientID(S3ECId)
                        .newKeyMaterial(aesKeyMaterial2).build());

                assertNotNull(response);
                reEncryptedAesToAes.add(objectKey);
            }
        }

        @ParameterizedTest(name = "{0}: ReEncrypt RSA => RSA instruction file")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$ReEncryptTestsNested#reencryptSupportedClients")
        void reencryptRsaToRsaInstructionFile(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            
            for (int i = 0; i < kcGcmObjectsRsaToRsa.size(); i++) {
                String objectKey = kcGcmObjectsRsaToRsa.get(i);
                CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                    .config(S3ECConfig.builder()
                        .keyMaterial(rsaKeyMaterial1)
                        .instructionFileConfig(InstructionFileConfig.builder()
                            .enableInstructionFilePutObject(true)
                            .build())
                        .build())
                    .build());
                String S3ECId = clientOutput.getClientId();

                ReEncryptOutput response = client.reEncrypt(ReEncryptInput.builder()
                        .bucket(TestUtils.BUCKET).key(objectKey).clientID(S3ECId)
                        .newKeyMaterial(rsaKeyMaterial2).build());

                assertNotNull(response);
                reEncryptedRsaToRsa.add(objectKey);
            }
        }

        @ParameterizedTest(name = "{0}: ReEncrypt AES => RSA instruction file with custom suffix")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$ReEncryptTestsNested#reencryptSupportedClients")
        void reencryptAesToRsaInstructionFile(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            
            for (int i = 0; i < kcGcmObjectsAesToRsaCustom.size(); i++) {
                String objectKey = kcGcmObjectsAesToRsaCustom.get(i);
                CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                    .config(S3ECConfig.builder()
                        .keyMaterial(aesKeyMaterial1)
                        .instructionFileConfig(InstructionFileConfig.builder()
                            .enableInstructionFilePutObject(true)
                            .build())
                        .build())
                    .build());
                String S3ECId = clientOutput.getClientId();

                ReEncryptOutput response = client.reEncrypt(ReEncryptInput.builder()
                        .bucket(TestUtils.BUCKET).key(objectKey).clientID(S3ECId)
                        .newKeyMaterial(rsaKeyMaterial1)
                        // Java always prepends a `.`
                        .instructionFileSuffix("instruction-rsa")
                        .build());

                assertNotNull(response);
                reEncryptedAesToRsa.add(objectKey);
            }
        }

        @ParameterizedTest(name = "{0}: ReEncrypt RSA => AES instruction file (default suffix)")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$ReEncryptTestsNested#reencryptSupportedClients")
        void reencryptRsaToAesDefaultInstructionFile(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            
            for (int i = 0; i < kcGcmObjectsRsaToAesDefault.size(); i++) {
                String objectKey = kcGcmObjectsRsaToAesDefault.get(i);
                CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                    .config(S3ECConfig.builder()
                        .keyMaterial(rsaKeyMaterial1)
                        .instructionFileConfig(InstructionFileConfig.builder()
                            .enableInstructionFilePutObject(true)
                            .build())
                        .build())
                    .build());
                String S3ECId = clientOutput.getClientId();

                ReEncryptOutput response = client.reEncrypt(ReEncryptInput.builder()
                        .bucket(TestUtils.BUCKET).key(objectKey).clientID(S3ECId)
                        .newKeyMaterial(aesKeyMaterial1)
                        .build());

                assertNotNull(response);
                reEncryptedRsaToAesDefault.add(objectKey);
            }
        }

        @ParameterizedTest(name = "{0}: ReEncrypt AES => RSA instruction file (default suffix)")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$ReEncryptTestsNested#reencryptSupportedClients")
        void reencryptAesToRsaDefaultInstructionFile(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            
            for (int i = 0; i < kcGcmObjectsAesToRsaDefault.size(); i++) {
                String objectKey = kcGcmObjectsAesToRsaDefault.get(i);
                CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                    .config(S3ECConfig.builder()
                        .keyMaterial(aesKeyMaterial1)
                        .instructionFileConfig(InstructionFileConfig.builder()
                            .enableInstructionFilePutObject(true)
                            .build())
                        .build())
                    .build());
                String S3ECId = clientOutput.getClientId();

                ReEncryptOutput response = client.reEncrypt(ReEncryptInput.builder()
                        .bucket(TestUtils.BUCKET).key(objectKey).clientID(S3ECId)
                        .newKeyMaterial(rsaKeyMaterial1)
                        .build());

                assertNotNull(response);
                reEncryptedAesToRsaDefault.add(objectKey);
            }
        }

        @AfterAll
        static void signalReEncryptionComplete() {
            reEncryptPhaseComplete.countDown();
        }
    }

    @Nested
    @DisplayName("ReEncryptTests - DecryptReEncrypted")
    class DecryptReEncryptedTests {
        private static KeyMaterial aesKeyMaterial1, aesKeyMaterial2, rsaKeyMaterial1, rsaKeyMaterial2;

        @BeforeAll
        static void setup() throws InterruptedException {
            reEncryptPhaseComplete.await();
            aesKeyMaterial1 = EncryptTests.getAesKeyMaterial1();
            aesKeyMaterial2 = EncryptTests.getAesKeyMaterial2();
            rsaKeyMaterial1 = EncryptTests.getRsaKeyMaterial1();
            rsaKeyMaterial2 = EncryptTests.getRsaKeyMaterial2();
        }

        public static Stream<Arguments> clientsCanGetRawRSAWithInstructionFile() {
            return Stream.concat(
                improvedClientsForTest().filter(target -> RAW_RSA_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName())),
                transitionClientsForTest().filter(target -> RAW_RSA_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
            );
        }

        public static Stream<Arguments> clientsCanGetRawAESWithInstructionFile() {
            return Stream.concat(
                improvedClientsForTest().filter(target -> RAW_AES_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName())),
                transitionClientsForTest().filter(target -> RAW_AES_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
            );
        }

        public static Stream<Arguments> clientsCanGetRawRSAWithInstructionFileAndCustomSuffix() {
            return Stream.concat(
                improvedClientsForTest()
                    .filter(target -> RAW_RSA_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
                    .filter(target -> CUSTOM_INSTRUCTION_SUFFIX_GET_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName())),
                transitionClientsForTest()
                    .filter(target -> RAW_RSA_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
                    .filter(target -> CUSTOM_INSTRUCTION_SUFFIX_GET_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
            );
        }

        public static Stream<Arguments> clientsCanGetRawAESWithInstructionFileAndCustomSuffix() {
            return Stream.concat(
                improvedClientsForTest()
                    .filter(target -> RAW_AES_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
                    .filter(target -> CUSTOM_INSTRUCTION_SUFFIX_GET_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName())),
                transitionClientsForTest()
                    .filter(target -> RAW_AES_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
                    .filter(target -> CUSTOM_INSTRUCTION_SUFFIX_GET_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
            );
        }

        @ParameterizedTest(name = "{0}: Decrypt AES => AES re-encrypted objects")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$DecryptReEncryptedTests#clientsCanGetRawAESWithInstructionFile")
        void decryptReencryptedAesToAesObjects(TestUtils.LanguageServerTarget language) {
            if (reEncryptedAesToAes.isEmpty()) return;
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder().keyMaterial(aesKeyMaterial2).build())
                .build());
            
            // C++ clients require materials description to be passed per-operation
            if (language.getLanguageName().startsWith("CPP")) {
                TestUtils.DecryptWithMaterialsDescription(client, clientOutput.getClientId(), 
                    reEncryptedAesToAes, aesKeyMaterial2,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
            } else {
                TestUtils.Decrypt(client, clientOutput.getClientId(), reEncryptedAesToAes,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
            }
        }

        @ParameterizedTest(name = "{0}: Decrypt RSA => RSA re-encrypted objects")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$DecryptReEncryptedTests#clientsCanGetRawRSAWithInstructionFile")
        void decryptReencryptedRsaToRsaObjects(TestUtils.LanguageServerTarget language) {
            if (reEncryptedRsaToRsa.isEmpty()) return;
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder().keyMaterial(rsaKeyMaterial2).build())
                .build());
            
            // C++ clients require materials description to be passed per-operation
            if (language.getLanguageName().startsWith("CPP")) {
                TestUtils.DecryptWithMaterialsDescription(client, clientOutput.getClientId(), 
                    reEncryptedRsaToRsa, rsaKeyMaterial2,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
            } else {
                TestUtils.Decrypt(client, clientOutput.getClientId(), reEncryptedRsaToRsa,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
            }
        }

        @ParameterizedTest(name = "{0}: Decrypt AES => RSA re-encrypted objects with custom suffix")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$DecryptReEncryptedTests#clientsCanGetRawRSAWithInstructionFileAndCustomSuffix")
        void decryptReencryptedAesToRsaObjects(TestUtils.LanguageServerTarget language) {
            if (reEncryptedAesToRsa.isEmpty()) return;
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(rsaKeyMaterial1)
                    .build())
                .build());
            
            // C++ clients require materials description to be passed per-operation
            if (language.getLanguageName().startsWith("CPP")) {
                TestUtils.DecryptWithMaterialsDescription(client, clientOutput.getClientId(), 
                    reEncryptedAesToRsa, rsaKeyMaterial1,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
            } else {
                TestUtils.Decrypt(client, clientOutput.getClientId(), reEncryptedAesToRsa,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
                    reEncryptedAesToRsa, ".instruction-rsa");
            }
        }

        @ParameterizedTest(name = "{0}: Decrypt RSA => AES re-encrypted objects (default suffix)")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$DecryptReEncryptedTests#clientsCanGetRawAESWithInstructionFile")
        void decryptReencryptedRsaToAesDefaultObjects(TestUtils.LanguageServerTarget language) {
            if (reEncryptedRsaToAesDefault.isEmpty()) return;
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(aesKeyMaterial1)
                    .build())
                .build());
            
            // C++ clients require materials description to be passed per-operation
            if (language.getLanguageName().startsWith("CPP")) {
                TestUtils.DecryptWithMaterialsDescription(client, clientOutput.getClientId(), 
                    reEncryptedRsaToAesDefault, aesKeyMaterial1,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
            } else {
                TestUtils.Decrypt(client, clientOutput.getClientId(), reEncryptedRsaToAesDefault,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
            }
        }

        @ParameterizedTest(name = "{0}: Decrypt AES => RSA re-encrypted objects (default suffix)")
        @MethodSource("software.amazon.encryption.s3.ReEncryptTests$DecryptReEncryptedTests#clientsCanGetRawRSAWithInstructionFile")
        void decryptReencryptedAesToRsaDefaultObjects(TestUtils.LanguageServerTarget language) {
            if (reEncryptedAesToRsaDefault.isEmpty()) return;
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(rsaKeyMaterial1)
                    .build())
                .build());
            
            // C++ clients require materials description to be passed per-operation
            if (language.getLanguageName().startsWith("CPP")) {
                TestUtils.DecryptWithMaterialsDescription(client, clientOutput.getClientId(), 
                    reEncryptedAesToRsaDefault, rsaKeyMaterial1,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
            } else {
                TestUtils.Decrypt(client, clientOutput.getClientId(), reEncryptedAesToRsaDefault,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
            }
        }
    }
}
