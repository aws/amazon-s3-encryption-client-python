/*
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
* SPDX-License-Identifier: Apache-2.0
*/

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;
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

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import software.amazon.encryption.s3.TestUtils.LanguageServerTarget;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.*;

/**
* Instruction File Failures Test Suite
* 
* This suite enforces execution order between encrypt and decrypt phases:
* 1. EncryptTests - Encrypts objects with various key materials and creates test copies
* 2. DecryptTests - Waits for encrypt phase to complete, then tests decryption scenarios
* 
* Coordination is achieved using a CountDownLatch that EncryptTests signals upon completion
* and DecryptTests awaits before proceeding.
*
*/
public class InstructionFileFailures {
    // Synchronization latch - released when encrypt phase completes
    private static final CountDownLatch encryptPhaseComplete = new CountDownLatch(1);
    
    // Object key suffixes for test copies
    private static final String SUFFIX_GOOD_COPY = "-good-copy";
    private static final String SUFFIX_BAD_BOTH_META_AND_INSTRUCTION = "-bad-both-meta-and-instruction";
    private static final String SUFFIX_BAD_ONLY_INSTRUCTION = "-bad-only-instruction";
    private static final String SUFFIX_BAD_JSON_INSTRUCTION = "-manipulated-bad-json-instruction";
    private static final String SUFFIX_MANIPULATED_INSTRUCTION = "-manipuldate-incorrect-key-instruction";

    /**
     * Encryption Tests - Encrypt Phase
     * 
     * These tests encrypt objects using various key materials (KMS, RSA, AES) with instruction files.
     * All tests in this class can run in parallel with each other.
     * The encrypted objects are stored in thread-safe lists for use by DecryptTests.
     */
    @Nested
    @DisplayName("InstructionFileFailures - Encrypt")
    class EncryptTests {
        private static final String sharedObjectKeyBaseMetaDataMode = "test-instruction-files-cases";
        private static KeyMaterial kmsKeyArn = KeyMaterial.builder()
            .kmsKeyId(TestUtils.KMS_KEY_ARN)
            .build();
        
        // Thread-safe lists for storing encrypted object keys
        private static final List<String> crossLanguageObjectsKms = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> crossLanguageObjectsRsa = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> crossLanguageObjectsAes = 
            Collections.synchronizedList(new ArrayList<>());
        
        // Thread-safe lists for envelope merge tests
        private static final List<String> crossLanguageObjectsMetadataOnly = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> crossLanguageObjectsInstructionFileDeleted = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> crossLanguageObjectsV3InstructionFileManipulated =
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> crossLanguageObjectsV2InstructionFileManipulated =
            Collections.synchronizedList(new ArrayList<>());

        private static KeyMaterial RSA_KEY;
        private static KeyMaterial AES_KEY;

        @BeforeAll
        static void setupKeys() throws Exception {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            RSA_KEY = KeyMaterial.builder()
              .rsaKey(ByteBuffer.wrap(keyPair.getPrivate().getEncoded()))
              .build();

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesSecretKey = keyGen.generateKey();

            AES_KEY = KeyMaterial.builder()
                .aesKey(ByteBuffer.wrap(aesSecretKey.getEncoded()))
                .build();
        }

        /**
         * Public accessors for decrypt tests to retrieve encrypted object keys and key materials
         */
        static List<String> getCrossLanguageObjectsKms() {
            return new ArrayList<>(crossLanguageObjectsKms);
        }

        static List<String> getCrossLanguageObjectsRsa() {
            return new ArrayList<>(crossLanguageObjectsRsa);
        }

        static List<String> getCrossLanguageObjectsAes() {
            return new ArrayList<>(crossLanguageObjectsAes);
        }

        static KeyMaterial getRsaKey() {
            return RSA_KEY;
        }

        static KeyMaterial getAesKey() {
            return AES_KEY;
        }

        static KeyMaterial getKmsKeyArn() {
            return kmsKeyArn;
        }

        static List<String> getCrossLanguageObjectsMetadataOnly() {
            return new ArrayList<>(crossLanguageObjectsMetadataOnly);
        }

        static List<String> getCrossLanguageObjectsInstructionFileDeleted() {
            return new ArrayList<>(crossLanguageObjectsInstructionFileDeleted);
        }

        static List<String> getCrossLanguageObjectsInstructionFileManipulatedV3() {
            return new ArrayList<>(crossLanguageObjectsV3InstructionFileManipulated);
        }

        static List<String> getCrossLanguageObjectsInstructionFileManipulatedV2() {
            return new ArrayList<>(crossLanguageObjectsV2InstructionFileManipulated);
        }


        public static Stream<Arguments> improvedClientsCanPutKMSWithInstructionFile() {
            return improvedClientsForTest()
                .filter(target -> !INSTRUCTION_FILE_PUT_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
                .filter(target -> !KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        }

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

        @ParameterizedTest(name = "{0}: Encrypt KMS KC-GCM with instruction files")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$EncryptTests#improvedClientsCanPutKMSWithInstructionFile")
        void encryptWithInstructionFilesKmsKcGcm(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .instructionFileConfig(
              InstructionFileConfig.builder()
              .enableInstructionFilePutObject(true)
              .build()
            )
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Encrypt(
                client,
                S3ECId,
                appendTestSuffix(sharedObjectKeyBaseMetaDataMode + "-kms" + language.getLanguageName()),
                crossLanguageObjectsKms,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Encrypt RSA KC-GCM with instruction files")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$EncryptTests#improvedClientsCanPutRawRSAWithInstructionFile")
        void encryptWithInstructionFilesRsaKcGcm(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
              .config(S3ECConfig.builder()
                .keyMaterial(RSA_KEY)
                .instructionFileConfig(
                    InstructionFileConfig.builder()
                    .enableInstructionFilePutObject(true)
                    .build()
                )
                .build())
              .build());

            String S3ECId = clientOutput.getClientId();

            TestUtils.Encrypt(
                client,
                S3ECId,
                appendTestSuffix(sharedObjectKeyBaseMetaDataMode + "-rsa" + language.getLanguageName()),
                crossLanguageObjectsRsa,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Encrypt AES KC-GCM with instruction files")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$EncryptTests#improvedClientsCanPutRawAESWithInstructionFile")
        void encryptWithInstructionFilesAesKcGcm(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
              .config(S3ECConfig.builder()
                .keyMaterial(AES_KEY)
                .instructionFileConfig(
                    InstructionFileConfig.builder()
                    .enableInstructionFilePutObject(true)
                    .build()
                )
                .build())
              .build());

            String S3ECId = clientOutput.getClientId();

            TestUtils.Encrypt(
                client,
                S3ECId,
                appendTestSuffix(sharedObjectKeyBaseMetaDataMode + "-aes" + language.getLanguageName()),
                crossLanguageObjectsAes,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Encrypt RSA KC-GCM metadata-only for envelope merge test")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$EncryptTests#improvedClientsCanPutRawRSAWithInstructionFile")
        void encryptMetadataOnlyRsaKcGcm(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            // Encrypt with metadata-only (no instruction file)
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
              .config(S3ECConfig.builder()
                .keyMaterial(RSA_KEY)
                .build())
              .build());

            String S3ECId = clientOutput.getClientId();

            TestUtils.Encrypt(
                client,
                S3ECId,
                appendTestSuffix(sharedObjectKeyBaseMetaDataMode + "-envelope-merge-metadata-only-" + language.getLanguageName()),
                crossLanguageObjectsMetadataOnly,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Encrypt RSA KC-GCM with instruction file for deletion test")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$EncryptTests#improvedClientsCanPutRawRSAWithInstructionFile")
        void encryptWithInstructionFileForDeletionRsaKcGcm(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            // Encrypt with instruction file (will be deleted later)
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
              .config(S3ECConfig.builder()
                .keyMaterial(RSA_KEY)
                .instructionFileConfig(
                    InstructionFileConfig.builder()
                    .enableInstructionFilePutObject(true)
                    .build()
                )
                .build())
              .build());

            String S3ECId = clientOutput.getClientId();

            TestUtils.Encrypt(
                client,
                S3ECId,
                appendTestSuffix(sharedObjectKeyBaseMetaDataMode + "-envelope-merge-instruction-deleted-" + language.getLanguageName()),
                crossLanguageObjectsInstructionFileDeleted,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Encrypt KMS KC-GCM (V3) with instruction file for manipulation test")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$EncryptTests#improvedClientsCanPutKMSWithInstructionFile")
        void encryptWithInstructionFileV3ForManipulationKmsKcGcm(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            // Encrypt with instruction file, will be manipulated later on.
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .instructionFileConfig(
                        InstructionFileConfig.builder()
                            .enableInstructionFilePutObject(true)
                            .build()
                    )
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Encrypt(
                client,
                S3ECId,
                appendTestSuffix(sharedObjectKeyBaseMetaDataMode + "-envelope-manipulation-instruction-" + language.getLanguageName()),
                crossLanguageObjectsV3InstructionFileManipulated,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Encrypt KMS (V2) with instruction file for manipulation test")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$EncryptTests#improvedClientsCanPutKMSWithInstructionFile")
        void encryptWithInstructionFileV2ForManipulationKms(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            // Encrypt with instruction file, will be manipulated later on.
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .instructionFileConfig(
                        InstructionFileConfig.builder()
                            .enableInstructionFilePutObject(true)
                            .build()
                    )
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Encrypt(
                client,
                S3ECId,
                appendTestSuffix(sharedObjectKeyBaseMetaDataMode + "-envelope-manipulation-instruction-" + language.getLanguageName()),
                crossLanguageObjectsV2InstructionFileManipulated,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }


        static void makeCopiesToVerifyThings() throws Exception {
            // Create a plaintext S3 client to copy objects with instruction files
            try (S3Client ptS3Client = S3Client.create()) {
                List<String> allCrossLanguageObjects = Stream.of(
                    crossLanguageObjectsKms.stream(),
                    crossLanguageObjectsRsa.stream(),
                    crossLanguageObjectsAes.stream()
                ).flatMap(s -> s).collect(Collectors.toList());
                for (String objectKey : allCrossLanguageObjects) {
                    // Get the encrypted object
                    ResponseBytes<GetObjectResponse> encryptedObject = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(objectKey)
                        .build());

                    // Get the instruction file
                    String instructionFileKey = objectKey + ".instruction";
                    ResponseBytes<GetObjectResponse> instructionFile = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(instructionFileKey)
                        .build());

                    String instructionFileJson = instructionFile.asUtf8String();
                    Map<String, String> objectMetadata = encryptedObject.response().metadata();

                    // Put a strict copy, to verify that we know how to do this
                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + SUFFIX_GOOD_COPY,
                        encryptedObject.asByteArray(),
                        objectMetadata,
                        instructionFileJson
                    );

                    ObjectMapper mapper = new ObjectMapper();
                    Map<String, Object> instructionFileMap = mapper.readValue(instructionFileJson, Map.class);

                    instructionFileMap.put("x-amz-c", objectMetadata.get("x-amz-c"));
                    instructionFileMap.put("x-amz-d", objectMetadata.get("x-amz-d"));
                    instructionFileMap.put("x-amz-i", objectMetadata.get("x-amz-i"));

                    String instructionFileWithCommitmentValues = mapper.writeValueAsString(instructionFileMap);

                    // Put instruction files that should fail:
                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + SUFFIX_BAD_BOTH_META_AND_INSTRUCTION,
                        encryptedObject.asByteArray(),
                        objectMetadata,
                        instructionFileWithCommitmentValues
                    );

                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + SUFFIX_BAD_ONLY_INSTRUCTION,
                        encryptedObject.asByteArray(),
                        Map.of(),
                        instructionFileWithCommitmentValues
                    );

                }
                
                // Delete instruction files for envelope merge tests
                for (String objectKey : crossLanguageObjectsInstructionFileDeleted) {
                    String instructionFileKey = objectKey + ".instruction";
                    try {
                        ptS3Client.deleteObject(builder -> builder
                            .bucket(TestUtils.BUCKET)
                            .key(instructionFileKey)
                            .build());
                    } catch (Exception e) {
                        // Ignore if file doesn't exist
                    }
                }

                // manipulate V3 instruction files
                for (String objectKey: crossLanguageObjectsV3InstructionFileManipulated) {
                    // Get the encrypted object
                    ResponseBytes<GetObjectResponse> encryptedObject = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(objectKey)
                        .build());

                    // Get the instruction file
                    String instructionFileKey = objectKey + ".instruction";
                    ResponseBytes<GetObjectResponse> instructionFile = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(instructionFileKey)
                        .build());

                    String instructionFileJson = instructionFile.asUtf8String();
                    Map<String, String> objectMetadata = encryptedObject.response().metadata();

                    ObjectMapper mapper = new ObjectMapper();
                    Map<String, Object> instructionFileMap = mapper.readValue(instructionFileJson, Map.class);

                    instructionFileMap.put("x-amz-c-v2", objectMetadata.get("x-amz-c"));
                    instructionFileMap.remove("x-amz-c");

                    Map<String, Object> invalidInstructionFileMap = new HashMap<>();
                    invalidInstructionFileMap.put("invalid", "json");

                    String invalidInstructionFile = mapper.writeValueAsString(invalidInstructionFileMap);
                    String badKeyInstructionFile = mapper.writeValueAsString(instructionFileMap);

                    // Put instruction files that should fail:
                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + SUFFIX_BAD_JSON_INSTRUCTION + "-v3",
                        encryptedObject.asByteArray(),
                        objectMetadata,
                        invalidInstructionFile
                    );

                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + SUFFIX_MANIPULATED_INSTRUCTION + "-v3",
                        encryptedObject.asByteArray(),
                        objectMetadata,
                        badKeyInstructionFile
                    );
                }

                // manipulate V2 instruction files
                for (String objectKey: crossLanguageObjectsV2InstructionFileManipulated) {
                    // Get the encrypted object
                    ResponseBytes<GetObjectResponse> encryptedObject = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(objectKey)
                        .build());

                    // Get the instruction file
                    String instructionFileKey = objectKey + ".instruction";
                    ResponseBytes<GetObjectResponse> instructionFile = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(instructionFileKey)
                        .build());

                    String instructionFileJson = instructionFile.asUtf8String();
                    Map<String, String> objectMetadata = encryptedObject.response().metadata();

                    ObjectMapper mapper = new ObjectMapper();
                    Map<String, Object> instructionFileMap = mapper.readValue(instructionFileJson, Map.class);

                    instructionFileMap.replace("x-amz-key-v2", "x-amz-key-v2-tampered");

                    Map<String, Object> invalidInstructionFileMap = new HashMap<>();
                    invalidInstructionFileMap.put("invalid", "json");

                    String invalidInstructionFile = mapper.writeValueAsString(invalidInstructionFileMap);
                    String badKeyInstructionFile = mapper.writeValueAsString(instructionFileMap);

                    // Put instruction files that should fail:
                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + SUFFIX_BAD_JSON_INSTRUCTION + "-v2",
                        encryptedObject.asByteArray(),
                        objectMetadata,
                        invalidInstructionFile
                    );

                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + SUFFIX_MANIPULATED_INSTRUCTION + "-v2",
                        encryptedObject.asByteArray(),
                        objectMetadata,
                        badKeyInstructionFile
                    );
                }
            }
        }

        static void putObjectWithInstructionFile(
            S3Client ptS3Client,
            String newObjectKey,
            byte[] objectData,
            Map<String, String> objectMetadata,
            String instructionFileJson
        ) {

            // Put the encrypted object copy
            ptS3Client.putObject(builder -> builder
                .bucket(TestUtils.BUCKET)
                .key(newObjectKey)
                .metadata(objectMetadata)
                .build(),
                software.amazon.awssdk.core.sync.RequestBody.fromBytes(objectData));

            // Put the instruction file copy
            ptS3Client.putObject(builder -> builder
                .bucket(TestUtils.BUCKET)
                .key(newObjectKey + ".instruction")
                .build(),
                software.amazon.awssdk.core.sync.RequestBody.fromBytes(instructionFileJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        }

        @AfterAll
        static void signalEncryptionComplete() throws Exception {
            makeCopiesToVerifyThings();

            // Signal that all encryption tests have completed
            encryptPhaseComplete.countDown();
        }
    }

    /**
     * Decryption Tests - Decrypt Phase
     * 
     * These tests decrypt objects that were encrypted by EncryptTests.
     * All tests in this class can run fully in parallel with each other.
     * They depend on EncryptTests completing first.
     */
    @Nested
    @DisplayName("InstructionFileFailures - Decrypt")
    class DecryptTests {
        private static List<String> crossLanguageObjectsKms;
        private static List<String> crossLanguageObjectsRsa;
        private static List<String> crossLanguageObjectsAes;
        private static List<String> crossLanguageObjectsMetadataOnly;
        private static List<String> crossLanguageObjectsInstructionFileDeleted;
        private static List<String> crossLanguageObjectsInstructionFileManipulatedV3;
        private static List<String> crossLanguageObjectsInstructionFileManipulatedV2;
        private static KeyMaterial kmsKeyArn;
        private static KeyMaterial RSA_KEY;
        private static KeyMaterial AES_KEY;

        @BeforeAll
        static void setup() throws InterruptedException {
            // Wait for all encryption tests to complete
            encryptPhaseComplete.await();

            // Import encrypted objects and key materials from the encrypt phase
            crossLanguageObjectsKms = EncryptTests.getCrossLanguageObjectsKms();
            crossLanguageObjectsRsa = EncryptTests.getCrossLanguageObjectsRsa();
            crossLanguageObjectsAes = EncryptTests.getCrossLanguageObjectsAes();
            crossLanguageObjectsMetadataOnly = EncryptTests.getCrossLanguageObjectsMetadataOnly();
            crossLanguageObjectsInstructionFileDeleted = EncryptTests.getCrossLanguageObjectsInstructionFileDeleted();
            crossLanguageObjectsInstructionFileManipulatedV3 = EncryptTests.getCrossLanguageObjectsInstructionFileManipulatedV3();
            crossLanguageObjectsInstructionFileManipulatedV2 = EncryptTests.getCrossLanguageObjectsInstructionFileManipulatedV2();
            kmsKeyArn = EncryptTests.getKmsKeyArn();
            RSA_KEY = EncryptTests.getRsaKey();
            AES_KEY = EncryptTests.getAesKey();

            // Verify we have objects to decrypt
            if (crossLanguageObjectsKms.isEmpty() && crossLanguageObjectsRsa.isEmpty() && crossLanguageObjectsAes.isEmpty()) {
                throw new IllegalStateException(
                    "No encrypted objects found. Ensure EncryptTests runs first.");
            }
        }

        public static Stream<Arguments> clientsCanGetKMSWithInstructionFile() {
            Stream<Arguments> improved = improvedClientsForTest()
                .filter(target -> !KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
            
            Stream<Arguments> transition = transitionClientsForTest()
                .filter(target -> !KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
            
            return Stream.concat(improved, transition);
        }

        public static Stream<Arguments> clientsCanGetRawRSAWithInstructionFile() {
            Stream<Arguments> improved = improvedClientsForTest()
                .filter(target -> RAW_RSA_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
            
            Stream<Arguments> transition = transitionClientsForTest()
                .filter(target -> RAW_RSA_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
            
            return Stream.concat(improved, transition);
        }

        public static Stream<Arguments> clientsCanGetRawAESWithInstructionFile() {
            Stream<Arguments> improved = improvedClientsForTest()
                .filter(target -> RAW_AES_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
            
            Stream<Arguments> transition = transitionClientsForTest()
                .filter(target -> RAW_AES_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
            
            return Stream.concat(improved, transition);
        }

        // KMS instruction files decrypt

        @ParameterizedTest(name = "{0}: Successfully decrypt KMS encrypted original and good-copy objects")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetKMSWithInstructionFile")
        void decryptKmsOriginalAndGoodCopyObjectsSucceeds(TestUtils.LanguageServerTarget language) {

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
                crossLanguageObjectsKms,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );

            TestUtils.Decrypt(
                client,
                S3ECId,
                crossLanguageObjectsKms
                    .stream()
                    .map(key -> key + SUFFIX_GOOD_COPY)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
                crossLanguageObjectsKms
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt KMS when commitment is duplicated in metadata and instruction file")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetKMSWithInstructionFile")
        void decryptKmsWithDuplicateCommitmentInMetadataAndInstructionFails(TestUtils.LanguageServerTarget language) {

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
                crossLanguageObjectsKms
                    .stream()
                    .map(key -> key + SUFFIX_BAD_BOTH_META_AND_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt KMS when commitment is only in instruction file")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetKMSWithInstructionFile")
        void decryptKmsWithCommitmentOnlyInInstructionFileFails(TestUtils.LanguageServerTarget language) {

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
                crossLanguageObjectsKms
                    .stream()
                    .map(key -> key + SUFFIX_BAD_ONLY_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt KMS duplicate commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetKMSWithInstructionFile")
        void decryptKmsWithDuplicateCommitmentFailsWithForbidPolicy(TestUtils.LanguageServerTarget language) {

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
                crossLanguageObjectsKms
                    .stream()
                    .map(key -> key + SUFFIX_BAD_BOTH_META_AND_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt KMS instruction file commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetKMSWithInstructionFile")
        void decryptKmsWithInstructionFileCommitmentFailsWithForbidPolicy(TestUtils.LanguageServerTarget language) {

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
                crossLanguageObjectsKms
                    .stream()
                    .map(key -> key + SUFFIX_BAD_ONLY_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        // RSA instruction file decrypt

        @ParameterizedTest(name = "{0}: Successfully decrypt RSA encrypted original and good-copy objects")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawRSAWithInstructionFile")
        void decryptRsaOriginalAndGoodCopyObjectsSucceeds(TestUtils.LanguageServerTarget language) {

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(RSA_KEY)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt(
                client,
                S3ECId,
                crossLanguageObjectsRsa,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );

            TestUtils.Decrypt(
                client,
                S3ECId,
                crossLanguageObjectsRsa
                    .stream()
                    .map(key -> key + SUFFIX_GOOD_COPY)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
                crossLanguageObjectsRsa
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt RSA when commitment is duplicated in metadata and instruction file")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawRSAWithInstructionFile")
        void decryptRsaWithDuplicateCommitmentInMetadataAndInstructionFails(TestUtils.LanguageServerTarget language) {

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(RSA_KEY)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsRsa
                    .stream()
                    .map(key -> key + SUFFIX_BAD_BOTH_META_AND_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt RSA when commitment is only in instruction file")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawRSAWithInstructionFile")
        void decryptRsaWithCommitmentOnlyInInstructionFileFails(TestUtils.LanguageServerTarget language) {

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(RSA_KEY)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsRsa
                    .stream()
                    .map(key -> key + SUFFIX_BAD_ONLY_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt RSA duplicate commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawRSAWithInstructionFile")
        void decryptRsaWithDuplicateCommitmentFailsWithForbidPolicy(TestUtils.LanguageServerTarget language) {

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(RSA_KEY)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsRsa
                    .stream()
                    .map(key -> key + SUFFIX_BAD_BOTH_META_AND_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt RSA instruction file commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawRSAWithInstructionFile")
        void decryptRsaWithInstructionFileCommitmentFailsWithForbidPolicy(TestUtils.LanguageServerTarget language) {

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(RSA_KEY)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsRsa
                    .stream()
                    .map(key -> key + SUFFIX_BAD_ONLY_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        // AES instruction file decrypt

        @ParameterizedTest(name = "{0}: Successfully decrypt AES encrypted original and good-copy objects")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawAESWithInstructionFile")
        void decryptAesOriginalAndGoodCopyObjectsSucceeds(TestUtils.LanguageServerTarget language) {

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(AES_KEY)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt(
                client,
                S3ECId,
                crossLanguageObjectsAes,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );

            TestUtils.Decrypt(
                client,
                S3ECId,
                crossLanguageObjectsAes
                    .stream()
                    .map(key -> key + SUFFIX_GOOD_COPY)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
                crossLanguageObjectsAes
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt AES when commitment is duplicated in metadata and instruction file")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawAESWithInstructionFile")
        void decryptAesWithDuplicateCommitmentInMetadataAndInstructionFails(TestUtils.LanguageServerTarget language) {

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(AES_KEY)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsAes
                    .stream()
                    .map(key -> key + SUFFIX_BAD_BOTH_META_AND_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt AES when commitment is only in instruction file")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawAESWithInstructionFile")
        void decryptAesWithCommitmentOnlyInInstructionFileFails(TestUtils.LanguageServerTarget language) {

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(AES_KEY)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsAes
                    .stream()
                    .map(key -> key + SUFFIX_BAD_ONLY_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt AES duplicate commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawAESWithInstructionFile")
        void decryptAesWithDuplicateCommitmentFailsWithForbidPolicy(TestUtils.LanguageServerTarget language) {

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(AES_KEY)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsAes
                    .stream()
                    .map(key -> key + SUFFIX_BAD_BOTH_META_AND_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt AES instruction file commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawAESWithInstructionFile")
        void decryptAesWithInstructionFileCommitmentFailsWithForbidPolicy(TestUtils.LanguageServerTarget language) {

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(AES_KEY)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsAes
                    .stream()
                    .map(key -> key + SUFFIX_BAD_ONLY_INSTRUCTION)
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        // Envelope merge tests

        @ParameterizedTest(name = "{0}: Successfully decrypt metadata-only object with instruction file config")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawRSAWithInstructionFile")
        void decryptMetadataOnlyObjectWithInstructionFileConfigSucceeds(TestUtils.LanguageServerTarget language) {
            if (crossLanguageObjectsMetadataOnly.isEmpty()) return;

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            // Configure client to look for instruction file but metadata has complete envelope
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(RSA_KEY)
            .instructionFileConfig(
                InstructionFileConfig.builder()
                .enableInstructionFilePutObject(true)
                .build()
            )
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            // Should succeed - instruction file doesn't exist but metadata has complete envelope
            TestUtils.Decrypt(
                client,
                S3ECId,
                crossLanguageObjectsMetadataOnly,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt when metadata incomplete and instruction file deleted")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawRSAWithInstructionFile")
        void decryptWithIncompleteMetadataAndNoInstructionFileFails(TestUtils.LanguageServerTarget language) {
            if (crossLanguageObjectsInstructionFileDeleted.isEmpty()) return;

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            // Configure client for metadata-only but metadata is incomplete
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(RSA_KEY)
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            // Should fail - metadata incomplete (missing x-amz-3, x-amz-w), instruction file deleted
            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsInstructionFileDeleted,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt with instruction file config when file deleted and metadata incomplete")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetRawRSAWithInstructionFile")
        void decryptWithInstructionFileConfigWhenFileDeletedFails(TestUtils.LanguageServerTarget language) {
            if (crossLanguageObjectsInstructionFileDeleted.isEmpty()) return;

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            // Configure client to look for instruction file but it's been deleted
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
            .keyMaterial(RSA_KEY)
            .instructionFileConfig(
                InstructionFileConfig.builder()
                .enableInstructionFilePutObject(true)
                .build()
            )
            .build())
            .build());
            String S3ECId = clientOutput.getClientId();

            // Should fail - instruction file deleted, metadata incomplete (missing x-amz-3, x-amz-w)
            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsInstructionFileDeleted,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt with manipulated V3 Instruction File")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetKMSWithInstructionFile")
        void decryptWithManipulatedInstructionFileV3ImprovedClients(TestUtils.LanguageServerTarget language) {
            if (crossLanguageObjectsInstructionFileManipulatedV3.isEmpty()) return;

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsInstructionFileManipulatedV3
                    .stream()
                    .map(key -> key + SUFFIX_BAD_JSON_INSTRUCTION + "-v3")
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsInstructionFileManipulatedV3
                    .stream()
                    .map(key -> key + SUFFIX_MANIPULATED_INSTRUCTION + "-v3")
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to decrypt with manipulated V2 Instruction File")
        @MethodSource("software.amazon.encryption.s3.InstructionFileFailures$DecryptTests#clientsCanGetKMSWithInstructionFile")
        void decryptWithManipulatedInstructionFileV2ImprovedClients(TestUtils.LanguageServerTarget language) {
            if (crossLanguageObjectsInstructionFileManipulatedV2.isEmpty()) return;

            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsInstructionFileManipulatedV2
                    .stream()
                    .map(key -> key + SUFFIX_BAD_JSON_INSTRUCTION + "-v2")
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );

            TestUtils.Decrypt_fails(
                client,
                S3ECId,
                crossLanguageObjectsInstructionFileManipulatedV3
                    .stream()
                    .map(key -> key + SUFFIX_MANIPULATED_INSTRUCTION + "-v2")
                    .collect(Collectors.toList()),
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }
    }
}
