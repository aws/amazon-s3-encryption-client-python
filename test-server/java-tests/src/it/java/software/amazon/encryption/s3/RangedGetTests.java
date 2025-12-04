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
import software.amazon.encryption.s3.model.InstructionFileConfig;
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
 * - Storage Mode (KC-GCM only):
 *   * Object Metadata Storage (all metadata in object, no instruction file)
 *   * Instruction File Storage (c/d/i in metadata, x-amz-3/w/m/t in instruction file)
 * - Commitment State (KC-GCM only):
 *   * Valid - Object Metadata Storage (original and good-copy)
 *   * Valid - Instruction File Storage (original and good-copy)
 *   * Corrupted - Object Metadata Storage:
 *     - Mutated c/d/i: bit flipped in metadata values
 *     - Invalid c length: c < 28 bytes in metadata
 *     - Invalid c length: c > 28 bytes in metadata
 *   * Corrupted - Instruction File Storage:
 *     - Commitment duplicated: c/d/i in instruction file (already in metadata)
 *     - Commitment removed: c/d/i removed from metadata
 *     - Mutated c/d/i in metadata: bit flipped
 *     - Mutated c/d/i in instruction file: bit flipped
 *     - Invalid c length: c < 28 bytes in metadata
 *     - Invalid c length: c > 28 bytes in metadata
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
    
    // Object key suffixes for test copies
    private static final String SUFFIX_GOOD_COPY = "-good-copy";
    private static final String SUFFIX_BAD_MUTATED_C = "-bad-mutated-c-bit-";
    private static final String SUFFIX_BAD_MUTATED_D = "-bad-mutated-d-bit-";
    private static final String SUFFIX_BAD_MUTATED_I = "-bad-mutated-i-bit-";
    private static final String SUFFIX_BAD_INVALID_D_LENGTH_SHORT = "-bad-invalid-d-length-short";
    private static final String SUFFIX_BAD_INVALID_D_LENGTH_LONG = "-bad-invalid-d-length-long";
    private static final String SUFFIX_BAD_COMMITMENT_IN_INSTRUCTION = "-bad-commitment-in-instruction";

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
        // KC-GCM with Object Metadata Storage (all metadata in object)
        private static final List<String> kcGcmObjectsMetadata = 
            Collections.synchronizedList(new ArrayList<>());
        // KC-GCM with Instruction File Storage (c/d/i in metadata, rest in instruction file)
        private static final List<String> kcGcmObjectsInstruction = 
            Collections.synchronizedList(new ArrayList<>());
        // Corruption test lists for metadata storage mode
        private static final List<String> mutatedCObjectsMetadata = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> mutatedDObjectsMetadata = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> mutatedIObjectsMetadata = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> invalidDLengthShortMetadata = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> invalidDLengthLongMetadata = 
            Collections.synchronizedList(new ArrayList<>());
        // Corruption test lists for instruction file storage mode
        private static final List<String> mutatedCObjectsInstruction = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> mutatedDObjectsInstruction = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> mutatedIObjectsInstruction = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> invalidDLengthShortInstruction = 
            Collections.synchronizedList(new ArrayList<>());
        private static final List<String> invalidDLengthLongInstruction = 
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

        static List<String> getKcGcmObjectsMetadata() {
            return new ArrayList<>(kcGcmObjectsMetadata);
        }

        static List<String> getKcGcmObjectsInstruction() {
            return new ArrayList<>(kcGcmObjectsInstruction);
        }

        static List<String> getMutatedCObjectsMetadata() {
            return new ArrayList<>(mutatedCObjectsMetadata);
        }

        static List<String> getMutatedDObjectsMetadata() {
            return new ArrayList<>(mutatedDObjectsMetadata);
        }

        static List<String> getMutatedIObjectsMetadata() {
            return new ArrayList<>(mutatedIObjectsMetadata);
        }

        static List<String> getInvalidDLengthShortMetadata() {
            return new ArrayList<>(invalidDLengthShortMetadata);
        }

        static List<String> getInvalidDLengthLongMetadata() {
            return new ArrayList<>(invalidDLengthLongMetadata);
        }

        static List<String> getMutatedCObjectsInstruction() {
            return new ArrayList<>(mutatedCObjectsInstruction);
        }

        static List<String> getMutatedDObjectsInstruction() {
            return new ArrayList<>(mutatedDObjectsInstruction);
        }

        static List<String> getMutatedIObjectsInstruction() {
            return new ArrayList<>(mutatedIObjectsInstruction);
        }

        static List<String> getInvalidDLengthShortInstruction() {
            return new ArrayList<>(invalidDLengthShortInstruction);
        }

        static List<String> getInvalidDLengthLongInstruction() {
            return new ArrayList<>(invalidDLengthLongInstruction);
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

        public static Stream<Arguments> improvedClientsCanPutKMSWithInstructionFile() {
            return improvedClientsForTest()
                .filter(target -> !INSTRUCTION_FILE_PUT_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
                .filter(target -> !KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        }

        @org.junit.jupiter.api.Test
        void encryptCbcForRangedGets() {
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
        void encryptGcmForRangedGets(TestUtils.LanguageServerTarget language) {
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

        @ParameterizedTest(name = "{0}: Encrypt KC-GCM with Object Metadata Storage for ranged get testing")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$EncryptTests#improvedClientsForKCGCM")
        void encryptKcGcmMetadataForRangedGets(TestUtils.LanguageServerTarget language) {
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
                appendTestSuffix(sharedObjectKeyBase + "-kc-gcm-metadata-" + language.getLanguageName()),
                kcGcmObjectsMetadata,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }


        @ParameterizedTest(name = "{0}: Encrypt KC-GCM with Instruction file Storage for ranged get testing")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$EncryptTests#improvedClientsCanPutKMSWithInstructionFile")
        void encryptKcGcmInstructionFileForRangedGets(TestUtils.LanguageServerTarget language) {
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
                appendTestSuffix(sharedObjectKeyBase + "-kc-gcm-instruction-java" + language.getLanguageName()),
                kcGcmObjectsInstruction,
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
         * Handles both object metadata storage and instruction file storage modes
         */
        static void createCorruptedCopies() throws Exception {
            try (S3Client ptS3Client = S3Client.create()) {
                ObjectMapper mapper = new ObjectMapper();
                
                // Process metadata storage mode objects (all V3 keys in metadata, no instruction file)
                for (String objectKey : kcGcmObjectsMetadata) {
                    ResponseBytes<GetObjectResponse> encryptedObject = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(objectKey)
                        .build());

                    byte[] objectData = encryptedObject.asByteArray();
                    Map<String, String> objectMetadata = encryptedObject.response().metadata();

                    // Create good copy
                    putObjectWithMetadata(ptS3Client, objectKey + SUFFIX_GOOD_COPY, objectData, objectMetadata);

                    // Extract commitment values from metadata
                    String commitC = objectMetadata.get("x-amz-c");
                    String commitD = objectMetadata.get("x-amz-d");
                    String commitI = objectMetadata.get("x-amz-i");

                    // Create mutated commitment copies in metadata
                    if (commitC != null) {
                        byte[] commitCBytes = Base64.getDecoder().decode(commitC);
                        int bitPos = flipRandomBit(commitCBytes);
                        String mutatedC = Base64.getEncoder().encodeToString(commitCBytes);
                        Map<String, String> mutatedMetadata = new java.util.HashMap<>(objectMetadata);
                        mutatedMetadata.put("x-amz-c", mutatedC);
                        String mutatedKey = objectKey + SUFFIX_BAD_MUTATED_C + bitPos;
                        putObjectWithMetadata(ptS3Client, mutatedKey, objectData, mutatedMetadata);
                        mutatedCObjectsMetadata.add(mutatedKey);
                    }

                    if (commitD != null) {
                        byte[] commitDBytes = Base64.getDecoder().decode(commitD);
                        int bitPos = flipRandomBit(commitDBytes);
                        String mutatedD = Base64.getEncoder().encodeToString(commitDBytes);
                        Map<String, String> mutatedMetadata = new java.util.HashMap<>(objectMetadata);
                        mutatedMetadata.put("x-amz-d", mutatedD);
                        String mutatedKey = objectKey + SUFFIX_BAD_MUTATED_D + bitPos;
                        putObjectWithMetadata(ptS3Client, mutatedKey, objectData, mutatedMetadata);
                        mutatedDObjectsMetadata.add(mutatedKey);
                    }

                    if (commitI != null) {
                        byte[] commitIBytes = Base64.getDecoder().decode(commitI);
                        int bitPos = flipRandomBit(commitIBytes);
                        String mutatedI = Base64.getEncoder().encodeToString(commitIBytes);
                        Map<String, String> mutatedMetadata = new java.util.HashMap<>(objectMetadata);
                        mutatedMetadata.put("x-amz-i", mutatedI);
                        String mutatedKey = objectKey + SUFFIX_BAD_MUTATED_I + bitPos;
                        putObjectWithMetadata(ptS3Client, mutatedKey, objectData, mutatedMetadata);
                        mutatedIObjectsMetadata.add(mutatedKey);
                    }

                    // Create invalid D length copies (metadata storage)
                    if (commitD != null) {
                        byte[] commitDBytes = Base64.getDecoder().decode(commitD);
                        
                        // Short D (< 28 bytes) - truncate to 20 bytes
                        int shortLength = Math.min(20, commitDBytes.length);
                        byte[] shortDBytes = new byte[shortLength];
                        System.arraycopy(commitDBytes, 0, shortDBytes, 0, shortLength);
                        String shortD = Base64.getEncoder().encodeToString(shortDBytes);
                        Map<String, String> shortDMetadata = new java.util.HashMap<>(objectMetadata);
                        shortDMetadata.put("x-amz-d", shortD);
                        String shortDKey = objectKey + SUFFIX_BAD_INVALID_D_LENGTH_SHORT;
                        putObjectWithMetadata(ptS3Client, shortDKey, objectData, shortDMetadata);
                        invalidDLengthShortMetadata.add(shortDKey);
                        
                        // Long D (> 28 bytes) - extend to 40 bytes
                        byte[] longDBytes = new byte[40];
                        System.arraycopy(commitDBytes, 0, longDBytes, 0, commitDBytes.length);
                        // Fill remaining bytes with zeros
                        for (int i = commitDBytes.length; i < 40; i++) {
                            longDBytes[i] = 0;
                        }
                        String longD = Base64.getEncoder().encodeToString(longDBytes);
                        Map<String, String> longDMetadata = new java.util.HashMap<>(objectMetadata);
                        longDMetadata.put("x-amz-d", longD);
                        String longDKey = objectKey + SUFFIX_BAD_INVALID_D_LENGTH_LONG;
                        putObjectWithMetadata(ptS3Client, longDKey, objectData, longDMetadata);
                        invalidDLengthLongMetadata.add(longDKey);
                    }
                }
                
                // Process instruction file storage mode objects (c/d/i in metadata, x-amz-3/w/m/t in instruction file)
                for (String objectKey : kcGcmObjectsInstruction) {
                    // Get the encrypted object
                    ResponseBytes<GetObjectResponse> encryptedObject = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(objectKey)
                        .build());

                    byte[] objectData = encryptedObject.asByteArray();
                    Map<String, String> objectMetadata = encryptedObject.response().metadata();
                    
                    // Get the instruction file
                    ResponseBytes<GetObjectResponse> instructionObject = ptS3Client.getObjectAsBytes(builder -> builder
                        .bucket(TestUtils.BUCKET)
                        .key(objectKey + ".instruction")
                        .build());
                    
                    String originalInstructionFileJson = new String(instructionObject.asByteArray(), StandardCharsets.UTF_8);

                    // Create good copy (both object and instruction file)
                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + SUFFIX_GOOD_COPY,
                        objectData,
                        objectMetadata,
                        originalInstructionFileJson
                    );

                    // Extract commitment values from metadata
                    String commitC = objectMetadata.get("x-amz-c");
                    String commitD = objectMetadata.get("x-amz-d");
                    String commitI = objectMetadata.get("x-amz-i");

                    // Corruption: Add c/d/i to instruction file (duplication - should fail)
                    Map<String, Object> corruptedInstructionMap = mapper.readValue(originalInstructionFileJson, Map.class);
                    corruptedInstructionMap.put("x-amz-c", commitC);
                    corruptedInstructionMap.put("x-amz-d", commitD);
                    corruptedInstructionMap.put("x-amz-i", commitI);
                    String corruptedInstructionJson = mapper.writeValueAsString(corruptedInstructionMap);
                    
                    putObjectWithInstructionFile(
                        ptS3Client,
                        objectKey + SUFFIX_BAD_COMMITMENT_IN_INSTRUCTION,
                        objectData,
                        objectMetadata,
                        corruptedInstructionJson
                    );

                    // Create mutated commitment copies in metadata
                    if (commitC != null) {
                        byte[] commitCBytes = Base64.getDecoder().decode(commitC);
                        int bitPos = flipRandomBit(commitCBytes);
                        String mutatedC = Base64.getEncoder().encodeToString(commitCBytes);
                        Map<String, String> mutatedMetadata = new java.util.HashMap<>(objectMetadata);
                        mutatedMetadata.put("x-amz-c", mutatedC);
                        String mutatedKey = objectKey + SUFFIX_BAD_MUTATED_C + bitPos;
                        putObjectWithInstructionFile(ptS3Client, mutatedKey, objectData, mutatedMetadata, originalInstructionFileJson);
                        mutatedCObjectsInstruction.add(mutatedKey);
                    }

                    if (commitD != null) {
                        byte[] commitDBytes = Base64.getDecoder().decode(commitD);
                        int bitPos = flipRandomBit(commitDBytes);
                        String mutatedD = Base64.getEncoder().encodeToString(commitDBytes);
                        Map<String, String> mutatedMetadata = new java.util.HashMap<>(objectMetadata);
                        mutatedMetadata.put("x-amz-d", mutatedD);
                        String mutatedKey = objectKey + SUFFIX_BAD_MUTATED_D + bitPos;
                        putObjectWithInstructionFile(ptS3Client, mutatedKey, objectData, mutatedMetadata, originalInstructionFileJson);
                        mutatedDObjectsInstruction.add(mutatedKey);
                    }

                    if (commitI != null) {
                        byte[] commitIBytes = Base64.getDecoder().decode(commitI);
                        int bitPos = flipRandomBit(commitIBytes);
                        String mutatedI = Base64.getEncoder().encodeToString(commitIBytes);
                        Map<String, String> mutatedMetadata = new java.util.HashMap<>(objectMetadata);
                        mutatedMetadata.put("x-amz-i", mutatedI);
                        String mutatedKey = objectKey + SUFFIX_BAD_MUTATED_I + bitPos;
                        putObjectWithInstructionFile(ptS3Client, mutatedKey, objectData, mutatedMetadata, originalInstructionFileJson);
                        mutatedIObjectsInstruction.add(mutatedKey);
                    }

                    // Create invalid D length copies (instruction file storage)
                    if (commitD != null) {
                        byte[] commitDBytes = Base64.getDecoder().decode(commitD);
                        
                        // Short D (< 28 bytes) - truncate to 20 bytes
                        int shortLength = Math.min(20, commitDBytes.length);
                        byte[] shortDBytes = new byte[shortLength];
                        System.arraycopy(commitDBytes, 0, shortDBytes, 0, shortLength);
                        String shortD = Base64.getEncoder().encodeToString(shortDBytes);
                        Map<String, String> shortDMetadata = new java.util.HashMap<>(objectMetadata);
                        shortDMetadata.put("x-amz-d", shortD);
                        String shortDKey = objectKey + SUFFIX_BAD_INVALID_D_LENGTH_SHORT;
                        putObjectWithInstructionFile(ptS3Client, shortDKey, objectData, shortDMetadata, originalInstructionFileJson);
                        invalidDLengthShortInstruction.add(shortDKey);
                        
                        // Long D (> 28 bytes) - extend to 40 bytes
                        byte[] longDBytes = new byte[40];
                        System.arraycopy(commitDBytes, 0, longDBytes, 0, commitDBytes.length);
                        // Fill remaining bytes with zeros
                        for (int i = commitDBytes.length; i < 40; i++) {
                            longDBytes[i] = 0;
                        }
                        String longD = Base64.getEncoder().encodeToString(longDBytes);
                        Map<String, String> longDMetadata = new java.util.HashMap<>(objectMetadata);
                        longDMetadata.put("x-amz-d", longD);
                        String longDKey = objectKey + SUFFIX_BAD_INVALID_D_LENGTH_LONG;
                        putObjectWithInstructionFile(ptS3Client, longDKey, objectData, longDMetadata, originalInstructionFileJson);
                        invalidDLengthLongInstruction.add(longDKey);
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
        private static List<String> kcGcmObjectsInstruction;
        private static List<String> mutatedCObjects;
        private static List<String> mutatedDObjects;
        private static List<String> mutatedIObjects;
        private static List<String> mutatedCObjectsInstruction;
        private static List<String> mutatedDObjectsInstruction;
        private static List<String> mutatedIObjectsInstruction;
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
            // Import KC-GCM objects for both storage modes
            kcGcmObjects = EncryptTests.getKcGcmObjectsMetadata();
            kcGcmObjectsInstruction = EncryptTests.getKcGcmObjectsInstruction();
            // Import corrupted objects for metadata storage mode
            mutatedCObjects = EncryptTests.getMutatedCObjectsMetadata();
            mutatedDObjects = EncryptTests.getMutatedDObjectsMetadata();
            mutatedIObjects = EncryptTests.getMutatedIObjectsMetadata();
            // Import corrupted objects for instruction file storage mode
            mutatedCObjectsInstruction = EncryptTests.getMutatedCObjectsInstruction();
            mutatedDObjectsInstruction = EncryptTests.getMutatedDObjectsInstruction();
            mutatedIObjectsInstruction = EncryptTests.getMutatedIObjectsInstruction();
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
        void rangedGetCbcStartSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetCbcEndSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetCbcMiddleSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetCbcWholeFileSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetGcmStartSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetGcmEndSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetGcmMiddleSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetGcmWholeFileSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetGcmTagOnlySucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetKcGcmStartSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetKcGcmMiddleSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetKcGcmTagOnlySucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetKcGcmEndSucceeds(TestUtils.LanguageServerTarget language) {
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
        void rangedGetKcGcmWholeFileSucceeds(TestUtils.LanguageServerTarget language) {
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

        // KC-GCM Instruction File Storage - Valid Object Tests

        @ParameterizedTest(name = "{0}: Successfully ranged get KC-GCM Instruction File objects - start range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionStartSucceeds(TestUtils.LanguageServerTarget language) {
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
                kcGcmObjectsInstruction,
                0,
                5,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );

            TestUtils.RangedGet(
                client,
                S3ECId,
                kcGcmObjectsInstruction
                    .stream()
                    .map(key -> key + "-good-copy")
                    .collect(Collectors.toList()),
                0,
                5,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get KC-GCM Instruction File objects - middle range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionMiddleSucceeds(TestUtils.LanguageServerTarget language) {
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
                kcGcmObjectsInstruction,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );

            TestUtils.RangedGet(
                client,
                S3ECId,
                kcGcmObjectsInstruction
                    .stream()
                    .map(key -> key + "-good-copy")
                    .collect(Collectors.toList()),
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get KC-GCM Instruction File objects - Include tag")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionTagOnlySucceeds(TestUtils.LanguageServerTarget language) {
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
                kcGcmObjectsInstruction,
                10,
                1000,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );

            TestUtils.RangedGet(
                client,
                S3ECId,
                kcGcmObjectsInstruction
                    .stream()
                    .map(key -> key + "-good-copy")
                    .collect(Collectors.toList()),
                10,
                1000,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Successfully ranged get KC-GCM Instruction File objects - end range")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionEndSucceeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            // Test original objects
            for (String objectKey : kcGcmObjectsInstruction) {
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
            for (String objectKey : kcGcmObjectsInstruction) {
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

        @ParameterizedTest(name = "{0}: Successfully ranged get KC-GCM Instruction File objects - whole file")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionWholeFileSucceeds(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            // Test original objects
            for (String objectKey : kcGcmObjectsInstruction) {
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
            for (String objectKey : kcGcmObjectsInstruction) {
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

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM Instruction File with commitment duplicated in instruction file")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionCommitmentInInstructionFails(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            // Test instruction file storage mode objects with c/d/i duplicated into instruction file
            TestUtils.RangedGet_fails(
                client,
                S3ECId,
                kcGcmObjectsInstruction.stream()
                    .map(key -> key + "-bad-commitment-in-instruction")
                    .collect(Collectors.toList()),
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM with mutated commitment C")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmMutatedCFails(TestUtils.LanguageServerTarget language) {
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
                mutatedCObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM with mutated commitment D")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmMutatedDFails(TestUtils.LanguageServerTarget language) {
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
                mutatedDObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM with mutated commitment I")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmMutatedIFails(TestUtils.LanguageServerTarget language) {
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
                mutatedIObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM Instruction File with mutated commitment C in metadata")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionMutatedCFails(TestUtils.LanguageServerTarget language) {
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
                mutatedCObjectsInstruction,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM Instruction File with mutated commitment D in metadata")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionMutatedDFails(TestUtils.LanguageServerTarget language) {
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
                mutatedDObjectsInstruction,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM Instruction File with mutated commitment I in metadata")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionMutatedIFails(TestUtils.LanguageServerTarget language) {
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
                mutatedIObjectsInstruction,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM with invalid C length (too short) in metadata")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmMetadataInvalidCLengthShortFails(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            List<String> invalidDLengthShortObjects = EncryptTests.getInvalidDLengthShortMetadata();
            
            TestUtils.RangedGet_fails(
                client,
                S3ECId,
                invalidDLengthShortObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM with invalid D length (too long) in metadata")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmMetadataInvalidDLengthLongFails(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            List<String> invalidDLengthLongObjects = EncryptTests.getInvalidDLengthLongMetadata();
            
            TestUtils.RangedGet_fails(
                client,
                S3ECId,
                invalidDLengthLongObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM Instruction File with invalid D length (too short) in metadata")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionInvalidDLengthShortFails(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            List<String> invalidDLengthShortObjects = EncryptTests.getInvalidDLengthShortInstruction();
            
            TestUtils.RangedGet_fails(
                client,
                S3ECId,
                invalidDLengthShortObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }

        @ParameterizedTest(name = "{0}: Fail to ranged get KC-GCM Instruction File with invalid D length (too long) in metadata")
        @MethodSource("software.amazon.encryption.s3.RangedGetTests$RangedGetTestsNested#rangedGetSupportedClients")
        void rangedGetKcGcmInstructionInvalidDLengthLongFails(TestUtils.LanguageServerTarget language) {
            S3ECTestServerClient client = TestUtils.testServerClientFor(language);
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                    .keyMaterial(kmsKeyArn)
                    .enableLegacyUnauthenticatedModes(true)
                    .build())
                .build());
            String S3ECId = clientOutput.getClientId();
            
            List<String> invalidDLengthLongObjects = EncryptTests.getInvalidDLengthLongInstruction();
            
            TestUtils.RangedGet_fails(
                client,
                S3ECId,
                invalidDLengthLongObjects,
                5,
                10,
                EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            );
        }
    }
}
