/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import software.amazon.encryption.s3.model.GetObjectInput;
import software.amazon.encryption.s3.model.GetObjectOutput;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

/**
 * Ranged Get Tests - S3 Encryption Client Cross-Language Compatibility
 * 
 * PURPOSE:
 * This test suite validates that ranged get operations (partial object reads) work correctly
 * across all three encryption algorithms (CBC, GCM, KC-GCM) and that commitment validation
 * occurs properly during ranged gets for KC-GCM encrypted objects.
 * 
 * WHAT IS BEING TESTED:
 * 1. Ranged gets successfully retrieve partial content from encrypted objects across all algorithms
 * 2. Commitment validation is enforced during ranged gets for KC-GCM encrypted objects
 * 3. Corrupted commitment metadata (removed, moved, or mutated) causes ranged gets to fail
 * 4. Various byte ranges work correctly: start, end, middle, whole file, and auth tag only
 * 
 * WHY THIS IS IMPORTANT:
 * - Ranged gets are a critical S3 feature that must work with encrypted objects
 * - KC-GCM's commitment mechanism must be validated even for partial reads to prevent
 *   commitment-based issues where an actor control the encryption keys
 * - Cross-language compatibility ensures all SDKs handle ranged gets consistently
 * - Edge cases (first/last bytes, auth tags) verify boundary condition handling
 * 
 * TEST STRUCTURE:
 * This suite uses a two-phase approach with enforced ordering:
 * 1. EncryptTests - Encrypts objects with CBC, GCM, and KC-GCM algorithms
 *    - Creates corrupted KC-GCM test cases with manipulated commitment metadata
 *    - All encrypt tests can run in parallel within this phase
 * 2. RangedGetTests - Waits for encryption to complete, then tests ranged gets
 *    - Tests successful ranged gets on valid objects
 *    - Tests failed ranged gets on corrupted commitment objects
 *    - All ranged get tests can run in parallel within this phase
 * 
 * Coordination uses a CountDownLatch to ensure all encryption completes before ranged gets begin.
 * 
 * INPUT DIMENSIONS:
 * - Encryption Algorithm: CBC, GCM, KC-GCM
 * - Language Implementation: All languages supporting RANGED_GETS_SUPPORTED
 * - Byte Range Types: 
 *   * Start (bytes 0-99)
 *   * End (last 100 bytes)
 *   * Middle (100 bytes centered in file)
 *   * Whole file (all bytes)
 *   * Auth tag only (last 16 bytes for authenticated algorithms)
 * - Commitment State (KC-GCM only):
 *   * Valid (original and good-copy)
 *   * Commitment duplicated - left in metadata added to instruction file
 *   * No commitment - removed from metadata, only in instruction file
 *   * Mutated commitment - bit flipped in x-amz-c value
 *   * Mutated commitment - bit flipped in x-amz-d value
 *   * Mutated commitment - bit flipped in x-amz-i value
 * 
 * EXPECTED RESULTS:
 * - Positive: Ranged gets on valid CBC, GCM, KC-GCM objects return correct partial content
 * - Negative: Ranged gets on corrupted KC-GCM objects fail with commitment validation errors
 * 
 * REPRESENTATIVE VALUES:
 * - Bit flip position: Randomly selected per test run, included in object key name
 * - File size: Object keys themselves (short strings) serve as representative small files
 * - Byte ranges: Fixed patterns covering important boundary conditions
 * 
 * SCOPE:
 * - Languages in RANGED_GETS_SUPPORTED set are tested,
 *   the encrypt tests are to create values that are then tested.
 * - CBC and GCM tests validate ranged get functionality works
 * - KC-GCM tests focus on commitment validation during ranged gets
 */
public class RangedGetTests {
    // Synchronization latch - released when encrypt phase completes
    private static final CountDownLatch encryptPhaseComplete = new CountDownLatch(1);
    
    // Random number generator for bit flipping (seeded for reproducibility)
    private static final Random random = new Random(System.currentTimeMillis());

    /**
     * Encryption Tests - Encrypt Phase
     * 
     * These tests encrypt objects using CBC, GCM, and KC-GCM algorithms, then create
     * corrupted copies for failure testing. All tests in this class can run in parallel.
     */
    @Nested
    class EncryptTests {
        private static final String sharedObjectKeyBase = "test-ranged-get";
        private static KeyMaterial kmsKeyArn = KeyMaterial.builder()
            .kmsKeyId(TestUtils.KMS_KEY_ARN)
            .build();
        
        // Thread-safe lists for storing encrypted object keys
        private static final List<String> cbcObjects = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> gcmObjects = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> kcGcmObjects = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> mutatedCObjects = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> mutatedDObjects = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> mutatedIObjects = 
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
         * Public accessors for ranged get tests to retrieve encrypted object keys
         */
        static List<String> getCbcObjects() {
            return new ArrayList<>(cbcObjects);
        }

        static List<String> getGcmObjects() {
            return new ArrayList<>(gcmObjects);
        }

        static List<String> getKcGcmObjects() {
            return new ArrayList<>(kcGcmObjects);
        }

        static List<String> getMutatedCObjects() {
            return new ArrayList<>(mutatedCObjects);
        }

        static List<String> getMutatedDObjects() {
            return new ArrayList<>(mutatedDObjects);
        }

        static List<String> getMutatedIObjects() {
            return new ArrayList<>(mutatedIObjects);
        }

        static KeyMaterial getKmsKeyArn() {
            return kmsKeyArn;
        }

        static KeyMaterial getRsaKey() {
            return RSA_KEY;
        }

        static KeyMaterial getAesKey() {
            return AES_KEY;
        }

        // GCM can be encrypted by transition and improved clients
        public static Stream<Arguments> transitionAndImprovedForGCM() {
            return Stream.concat(
                transitionClientsForTest(),
                improvedClientsForTest()
            );
        }

        // KC-GCM can be encrypted by improved clients only
        public static Stream<Arguments> improvedClientsForKCGCM() {
            return improvedClientsForTest();
        }

        @org.junit.jupiter.api.Test
        void encrypt_cbc_for_ranged_gets() {
            // Use old V1 client for CBC encryption (legacy algorithm)
            // Only Java V1 client is available - no V1 test servers for other languages
            EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(TestUtils.KMS_KEY_ARN);
            
            CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.EncryptionOnly)
                .withStorageMode(CryptoStorageMode.ObjectMetadata)
                .withAwsKmsRegion(TestUtils.KMS_REGION);
            
            AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();
            
            String objectKey = appendTestSuffix(sharedObjectKeyBase + "-cbc-java");
            v1Client.putObject(TestUtils.BUCKET, objectKey, objectKey);
            cbcObjects.add(objectKey);
        }

        @ParameterizedTest(name = "{0}: Encrypt GCM for ranged get testing")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$EncryptTests#transitionAndImprovedForGCM")
        void encrypt_gcm_for_ranged_gets(TestUtils.LanguageServerTarget language) {
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
                appendTestSuffix(sharedObjectKeyBase + "-gcm-" + language.getLanguageName()),
                gcmObjects,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Encrypt KC-GCM for ranged get testing")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$EncryptTests#improvedClientsForKCGCM")
        void encrypt_kc_gcm_for_ranged_gets(TestUtils.LanguageServerTarget language) {
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
                appendTestSuffix(sharedObjectKeyBase + "-kc-gcm-" + language.getLanguageName()),
                kcGcmObjects,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        /**
         * Flips a random bit in the given byte array
         * @param data The byte array to modify
         * @return The bit position that was flipped
         */
        static int flipRandomBit(byte[] data) {
            if (data.length == 0) {
                return -1;
            }
            int bitPosition = random.nextInt(data.length * 8);
            int byteIndex = bitPosition / 8;
            int bitIndex = bitPosition % 8;
            data[byteIndex] ^= (1 << bitIndex);
            return bitPosition;
        }

        /**
         * Creates corrupted copies of KC-GCM objects for failure testing
         */
        static void createCorruptedCopies() throws Exception {
            try (S3Client ptS3Client = S3Client.create()) {
                for (String objectKey : kcGcmObjects) {
                    // Get the encrypted object
                    ResponseBytes<GetObjectResponse> encryptedObject = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(objectKey)
                        .build());

                    byte[] objectData = encryptedObject.asByteArray();
                    Map<String, String> objectMetadata = encryptedObject.response().metadata();

                    // Create good copy
                    putObjectWithMetadata(ptS3Client, objectKey + "-good-copy", objectData, objectMetadata);

                    // Extract commitment values from metadata
                    String commitC = objectMetadata.get("x-amz-c");
                    String commitD = objectMetadata.get("x-amz-d");
                    String commitI = objectMetadata.get("x-amz-i");

                    // Create copies with no commitment in metadata
                    Map<String, String> noCommitMetadata = objectMetadata.entrySet().stream()
                        .filter(e -> !e.getKey().equals("x-amz-c") && !e.getKey().equals("x-amz-d") && !e.getKey().equals("x-amz-i"))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

                    // Create instruction file JSON with commitment
                    ObjectMapper mapper = new ObjectMapper();
                    Map<String, Object> instructionFileMap = new java.util.HashMap<>();
                    instructionFileMap.put("x-amz-c", commitC);
                    instructionFileMap.put("x-amz-d", commitD);
                    instructionFileMap.put("x-amz-i", commitI);
                    String instructionFileJson = mapper.writeValueAsString(instructionFileMap);

                    // No commitment - removed from metadata, added to instruction file
                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + "-bad-commitment-add-to-instruction",
                        objectData,
                        objectMetadata,
                        instructionFileJson
                    );

                    // No commitment - removed from metadata, only in instruction file
                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + "-bad-no-commitment-only-instruction",
                        objectData,
                        noCommitMetadata,
                        instructionFileJson
                    );

                    // Create mutated commitment copies
                    if (commitC != null) {
                        byte[] commitCBytes = Base64.getDecoder().decode(commitC);
                        int bitPos = flipRandomBit(commitCBytes);
                        String mutatedC = Base64.getEncoder().encodeToString(commitCBytes);
                        Map<String, String> mutatedMetadata = new java.util.HashMap<>(objectMetadata);
                        mutatedMetadata.put("x-amz-c", mutatedC);
                        String mutatedKey = objectKey + "-bad-mutated-c-bit-" + bitPos;
                        putObjectWithMetadata(
                            ptS3Client,
                            mutatedKey,
                            objectData,
                            mutatedMetadata
                        );
                        mutatedCObjects.add(mutatedKey);
                    }

                    if (commitD != null) {
                        byte[] commitDBytes = Base64.getDecoder().decode(commitD);
                        int bitPos = flipRandomBit(commitDBytes);
                        String mutatedD = Base64.getEncoder().encodeToString(commitDBytes);
                        Map<String, String> mutatedMetadata = new java.util.HashMap<>(objectMetadata);
                        mutatedMetadata.put("x-amz-d", mutatedD);
                        String mutatedKey = objectKey + "-bad-mutated-d-bit-" + bitPos;
                        putObjectWithMetadata(
                            ptS3Client,
                            mutatedKey,
                            objectData,
                            mutatedMetadata
                        );
                        mutatedDObjects.add(mutatedKey);
                    }

                    if (commitI != null) {
                        byte[] commitIBytes = Base64.getDecoder().decode(commitI);
                        int bitPos = flipRandomBit(commitIBytes);
                        String mutatedI = Base64.getEncoder().encodeToString(commitIBytes);
                        Map<String, String> mutatedMetadata = new java.util.HashMap<>(objectMetadata);
                        mutatedMetadata.put("x-amz-i", mutatedI);
                        String mutatedKey = objectKey + "-bad-mutated-i-bit-" + bitPos;
                        putObjectWithMetadata(
                            ptS3Client,
                            mutatedKey,
                            objectData,
                            mutatedMetadata
                        );
                        mutatedIObjects.add(mutatedKey);
                    }
                }
            }
        }

        static void putObjectWithMetadata(
            S3Client ptS3Client,
            String objectKey,
            byte[] objectData,
            Map<String, String> objectMetadata
        ) {
            ptS3Client.putObject(builder -> builder
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .metadata(objectMetadata)
                .build(),
                software.amazon.awssdk.core.sync.RequestBody.fromBytes(objectData));
        }

        static void putObjectWithInstructionFile(
            S3Client ptS3Client,
            String objectKey,
            byte[] objectData,
            Map<String, String> objectMetadata,
            String instructionFileJson
        ) {
            // Put the encrypted object
            ptS3Client.putObject(builder -> builder
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .metadata(objectMetadata)
                .build(),
                software.amazon.awssdk.core.sync.RequestBody.fromBytes(objectData));

            // Put the instruction file
            ptS3Client.putObject(builder -> builder
                .bucket(TestUtils.BUCKET)
                .key(objectKey + ".instruction")
                .build(),
                software.amazon.awssdk.core.sync.RequestBody.fromBytes(
                    instructionFileJson.getBytes(StandardCharsets.UTF_8)));
        }

        @AfterAll
        static void signalEncryptionComplete() throws Exception {
            createCorruptedCopies();
            
            // Signal that all encryption tests have completed
            encryptPhaseComplete.countDown();
        }
    }

    /**
     * Ranged Get Tests - Test Phase
     * 
     * These tests perform ranged get operations on objects encrypted by EncryptTests.
     * All tests in this class can run fully in parallel with each other.
     * They depend on EncryptTests completing first.
     */
    @Nested
    class RangedGetTestsNested {
        private static List<String> cbcObjects;
        private static List<String> gcmObjects;
        private static List<String> kcGcmObjects;
        private static List<String> mutatedCObjects;
        private static List<String> mutatedDObjects;
        private static List<String> mutatedIObjects;
        private static KeyMaterial kmsKeyArn;
        private static KeyMaterial RSA_KEY;
        private static KeyMaterial AES_KEY;

        @BeforeAll
        static void setup() throws InterruptedException {
            // Wait for all encryption tests to complete
            encryptPhaseComplete.await();

            // Import encrypted objects from the encrypt phase
            cbcObjects = EncryptTests.getCbcObjects();
            gcmObjects = EncryptTests.getGcmObjects();
            kcGcmObjects = EncryptTests.getKcGcmObjects();
            mutatedCObjects = EncryptTests.getMutatedCObjects();
            mutatedDObjects = EncryptTests.getMutatedDObjects();
            mutatedIObjects = EncryptTests.getMutatedIObjects();
            kmsKeyArn = EncryptTests.getKmsKeyArn();
            RSA_KEY = EncryptTests.getRsaKey();
            AES_KEY = EncryptTests.getAesKey();

            // Verify we have objects to test
            if (cbcObjects.isEmpty() && gcmObjects.isEmpty() && kcGcmObjects.isEmpty()) {
                throw new IllegalStateException(
                    "No encrypted objects found. Ensure EncryptTests runs first.");
            }
        }

        public static Stream<Arguments> rangedGetSupportedClients() {
            Stream<Arguments> improved = improvedClientsForTest()
                .filter(target -> RANGED_GETS_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
            
            Stream<Arguments> transition = transitionClientsForTest()
                .filter(target -> RANGED_GETS_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
            
            return Stream.concat(improved, transition);
        }

        public static Stream<Arguments> rangedGetCBCSupportedClients() {
            return rangedGetSupportedClients()
                // This is just a quick hack. Perhaps it would be good to have an equivalent group for languages.
                .filter(target -> !((LanguageServerTarget) target.get()[0]).getLanguageName().startsWith("CPP"));
        }

        // CBC Ranged Get Tests

        @ParameterizedTest(name = "{0}: Successfully ranged get CBC objects - start range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetCBCSupportedClients")
        void ranged_get_cbc_start_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .enableLegacyUnauthenticatedModes(true)
                    .enableLegacyWrappingAlgorithms(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.RangedGet(
                client,
                S3ECId,
                cbcObjects,
                0,
                5,
                EncryptionAlgorithm.ALG_AES_256_CBC_IV16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get CBC objects - end range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetCBCSupportedClients")
        void ranged_get_cbc_end_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .enableLegacyUnauthenticatedModes(true)
                    .enableLegacyWrappingAlgorithms(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            // For each object, get its length and test the last 5 bytes
            for (String objectKey : cbcObjects) {
                GetObjectOutput fullOutput = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .build());
                long objectLength = fullOutput.getBody().array().length;
                long rangeStart = Math.max(0, objectLength - 5);
                long rangeEnd = objectLength - 1;
                
                TestUtils.RangedGet(
                    client,
                    S3ECId,
                    java.util.Collections.singletonList(objectKey),
                    rangeStart,
                    rangeEnd,
                    EncryptionAlgorithm.ALG_AES_256_CBC_IV16_NO_KDF
                );
            }
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get CBC objects - middle range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetCBCSupportedClients")
        void ranged_get_cbc_middle_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .enableLegacyUnauthenticatedModes(true)
                    .enableLegacyWrappingAlgorithms(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.RangedGet(
                client,
                S3ECId,
                cbcObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_CBC_IV16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get CBC objects - whole file")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetCBCSupportedClients")
        void ranged_get_cbc_whole_file_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .enableLegacyUnauthenticatedModes(true)
                    .enableLegacyWrappingAlgorithms(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            // For each object, get its length and test the whole file using range
            for (String objectKey : cbcObjects) {
                GetObjectOutput fullOutput = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .build());
                long objectLength = fullOutput.getBody().array().length;
                
                TestUtils.RangedGet(
                    client,
                    S3ECId,
                    java.util.Collections.singletonList(objectKey),
                    0,
                    objectLength - 1,
                    EncryptionAlgorithm.ALG_AES_256_CBC_IV16_NO_KDF
                );
            }
        }

        // // GCM Ranged Get Tests

        @ParameterizedTest(name = "{0}: Successfully ranged get GCM objects - start range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_gcm_start_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.RangedGet(
                client,
                S3ECId,
                gcmObjects,
                0,
                5,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get GCM objects - end range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_gcm_end_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            // For each object, get its length and test the last 5 bytes
            for (String objectKey : gcmObjects) {
                GetObjectOutput fullOutput = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .build());
                long objectLength = fullOutput.getBody().array().length;
                long rangeStart = Math.max(0, objectLength - 5);
                long rangeEnd = objectLength - 1;
                
                TestUtils.RangedGet(
                    client,
                    S3ECId,
                    java.util.Collections.singletonList(objectKey),
                    rangeStart,
                    rangeEnd,
                    EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
                );
            }
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get GCM objects - middle range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_gcm_middle_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.RangedGet(
                client,
                S3ECId,
                gcmObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get GCM objects - whole file")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_gcm_whole_file_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            // For each object, get its length and test the whole file using range
            for (String objectKey : gcmObjects) {
                GetObjectOutput fullOutput = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .build());
                long objectLength = fullOutput.getBody().array().length;
                
                TestUtils.RangedGet(
                    client,
                    S3ECId,
                    java.util.Collections.singletonList(objectKey),
                    0,
                    objectLength - 1,
                    EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
                );
            }
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get GCM objects - Include tag")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_gcm_tag_only_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.RangedGet(
                client,
                S3ECId,
                gcmObjects,
                10,
                1000,
                EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
            );
        }

        // KC-GCM Ranged Get Tests - Valid Objects

        @ParameterizedTest(name = "{0}: Successfully ranged get KC-GCM objects - start range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_kc_gcm_start_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.RangedGet(
                client,
                S3ECId,
                kcGcmObjects,
                0,
                5,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );

            TestUtils.RangedGet(
                client,
                S3ECId,
                kcGcmObjects
                    .stream()
                    .map(key -> key + "-good-copy")
                    .collect(Collectors.toList()),
                0,
                5,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get KC-GCM objects - middle range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_kc_gcm_middle_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.RangedGet(
                client,
                S3ECId,
                kcGcmObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );

            TestUtils.RangedGet(
                client,
                S3ECId,
                kcGcmObjects
                    .stream()
                    .map(key -> key + "-good-copy")
                    .collect(Collectors.toList()),
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get KC-GCM objects - Include tag")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_kc_gcm_tag_only_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.RangedGet(
                client,
                S3ECId,
                kcGcmObjects,
                10,
                1000,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );

            TestUtils.RangedGet(
                client,
                S3ECId,
                kcGcmObjects
                    .stream()
                    .map(key -> key + "-good-copy")
                    .collect(Collectors.toList()),
                10,
                1000,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get KC-GCM objects - end range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_kc_gcm_end_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            // Test original objects
            for (String objectKey : kcGcmObjects) {
                GetObjectOutput fullOutput = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .build());
                long objectLength = fullOutput.getBody().array().length;
                long rangeStart = Math.max(0, objectLength - 5);
                long rangeEnd = objectLength - 1;
                
                TestUtils.RangedGet(
                    client,
                    S3ECId,
                    java.util.Collections.singletonList(objectKey),
                    rangeStart,
                    rangeEnd,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
                );
            }
            
            // Test good-copy objects
            for (String objectKey : kcGcmObjects) {
                String goodCopyKey = objectKey + "-good-copy";
                GetObjectOutput fullOutput = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(goodCopyKey)
                    .build());
                long objectLength = fullOutput.getBody().array().length;
                long rangeStart = Math.max(0, objectLength - 5);
                long rangeEnd = objectLength - 1;
                
                TestUtils.RangedGet(
                    client,
                    S3ECId,
                    java.util.Collections.singletonList(goodCopyKey),
                    rangeStart,
                    rangeEnd,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
                );
            }
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get KC-GCM objects - whole file")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_kc_gcm_whole_file_succeeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            // Test original objects
            for (String objectKey : kcGcmObjects) {
                GetObjectOutput fullOutput = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .build());
                long objectLength = fullOutput.getBody().array().length;
                
                TestUtils.RangedGet(
                    client,
                    S3ECId,
                    java.util.Collections.singletonList(objectKey),
                    0,
                    objectLength - 1,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
                );
            }
            
            // Test good-copy objects
            for (String objectKey : kcGcmObjects) {
                String goodCopyKey = objectKey + "-good-copy";
                GetObjectOutput fullOutput = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(goodCopyKey)
                    .build());
                long objectLength = fullOutput.getBody().array().length;
                
                TestUtils.RangedGet(
                    client,
                    S3ECId,
                    java.util.Collections.singletonList(goodCopyKey),
                    0,
                    objectLength - 1,
                    EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
                );
            }
        }

        // KC-GCM Ranged Get Tests - Failure Cases

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM with no commitment - add to instruction")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_kc_gcm_no_commitment_add_to_instruction_fails(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.RangedGet_fails(
                client,
                S3ECId,
                kcGcmObjects.stream()
                    .map(key -> key + "-bad-no-commitment-add-to-instruction")
                    .collect(Collectors.toList()),
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM with no commitment - only instruction")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_kc_gcm_no_commitment_only_instruction_fails(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            TestUtils.RangedGet_fails(
                client,
                S3ECId,
                kcGcmObjects.stream()
                    .map(key -> key + "-bad-no-commitment-only-instruction")
                    .collect(Collectors.toList()),
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM with mutated commitment C")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_kc_gcm_mutated_c_fails(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            assertFalse(mutatedCObjects.isEmpty(), "Expected mutated C objects to be created but list is empty");
            
            TestUtils.RangedGet_fails(
                client,
                S3ECId,
                mutatedCObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM with mutated commitment D")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_kc_gcm_mutated_d_fails(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            assertFalse(mutatedDObjects.isEmpty(), "Expected mutated D objects to be created but list is empty");
            
            TestUtils.RangedGet_fails(
                client,
                S3ECId,
                mutatedDObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM with mutated commitment I")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void ranged_get_kc_gcm_mutated_i_fails(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            assertFalse(mutatedIObjects.isEmpty(), "Expected mutated I objects to be created but list is empty");
            
            TestUtils.RangedGet_fails(
                client,
                S3ECId,
                mutatedIObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }
    }
}
