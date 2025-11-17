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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import software.amazon.encryption.s3.TestUtils.LanguageServerTarget;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.InstructionFileConfig;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

/**
* Exhaustive tests for S3 Encryption Client round-trip operations.
* These tests cover various combinations of client versions, commitment policies, and encryption modes.
*
* Tests are based on the exhaustive test matrix defined at:
* https://tiny.amazon.com/3xnzwczl/loopcloumicrpeyJ3
*
*/

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class InstructionFileFailures {
    private static final String sharedObjectKeyBaseMetaDataMode = "test-instruction-files-cases";
    private static KeyMaterial kmsKeyArn = KeyMaterial.builder()
    .kmsKeyId(TestUtils.KMS_KEY_ARN)
    .build();
    private static final List<String> crossLanguageObjectsKms = new ArrayList<>();
    private static final List<String> crossLanguageObjectsRsa = new ArrayList<>();
    private static final List<String> crossLanguageObjectsAes = new ArrayList<>();

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

    public static Stream<Arguments> improvedClientsCanPutKMSWithInstructionFile() {
        return improvedClientsForTest()
            .filter(target -> !INSTRUCTION_FILE_PUT_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
            .filter(target -> !KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
    }

    public static Stream<Arguments> improvedClientsCanPutRawWithInstructionFile() {
        return improvedClientsForTest()
            .filter(target -> !INSTRUCTION_FILE_PUT_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
            .filter(target -> RAW_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
    }

    public static Stream<Arguments> clientsCanGetKMSWithInstructionFile() {
        Stream<Arguments> improved = improvedClientsForTest()
            .filter(target -> !KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        
        Stream<Arguments> transition = transitionClientsForTest()
            .filter(target -> !KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        
        return Stream.concat(improved, transition);
    }

    public static Stream<Arguments> clientsCanGetRawWithInstructionFile() {
        Stream<Arguments> improved = improvedClientsForTest()
            .filter(target -> RAW_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        
        Stream<Arguments> transition = transitionClientsForTest()
            .filter(target -> RAW_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        
        return Stream.concat(improved, transition);
    }

    @Order(1)
    @ParameterizedTest(name = "{0}: Encrypt KMS KC-GCM with instruction files")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#improvedClientsCanPutKMSWithInstructionFile")
    void encrypt_with_instruction_files_kms_kc_gcm(TestUtils.LanguageServerTarget language) {
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

    @Order(2)
    @ParameterizedTest(name = "{0}: Encrypt RSA KC-GCM with instruction files")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#improvedClientsCanPutRawWithInstructionFile")
    void encrypt_with_instruction_files_rsa_kc_gcm(TestUtils.LanguageServerTarget language) {
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

    @Order(3)
    @ParameterizedTest(name = "{0}: Encrypt AES KC-GCM with instruction files")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#improvedClientsCanPutRawWithInstructionFile")
    void encrypt_with_instruction_files_aes_kc_gcm(TestUtils.LanguageServerTarget language) {
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

    @Order(9)
    @Test
    void make_copies_to_verify_things() throws Exception {
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
                    objectKey + "-good-copy",
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
                    objectKey + "-bad-both-meta-and-instruction",
                    encryptedObject.asByteArray(),
                    objectMetadata,
                    instructionFileWithCommitmentValues
                );

                putObjectWithInstructionFile(
                    ptS3Client,
                    objectKey + "-bad-only-instruction",
                    encryptedObject.asByteArray(),
                    Map.of(),
                    instructionFileWithCommitmentValues
                );

            }
        }
    }

    void putObjectWithInstructionFile(
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

    // KMS instruction files decrypt

    @Order(10)
    @ParameterizedTest(name = "{0}: Successfully decrypt KMS encrypted original and good-copy objects")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetKMSWithInstructionFile")
    void decrypt_kms_original_and_good_copy_objects_succeeds(TestUtils.LanguageServerTarget language) {

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
                .map(key -> key + "-good-copy")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            crossLanguageObjectsKms
        );
    }

    @Order(11)
    @ParameterizedTest(name = "{0}: Fail to decrypt KMS when commitment is duplicated in metadata and instruction file")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetKMSWithInstructionFile")
    void decrypt_kms_with_duplicate_commitment_in_metadata_and_instruction_fails(TestUtils.LanguageServerTarget language) {

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
                .map(key -> key + "-bad-both-meta-and-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(12)
    @ParameterizedTest(name = "{0}: Fail to decrypt KMS when commitment is only in instruction file")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetKMSWithInstructionFile")
    void decrypt_kms_with_commitment_only_in_instruction_file_fails(TestUtils.LanguageServerTarget language) {

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
                .map(key -> key + "-bad-only-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(13)
    @ParameterizedTest(name = "{0}: Fail to decrypt KMS duplicate commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetKMSWithInstructionFile")
    void decrypt_kms_with_duplicate_commitment_fails_with_forbid_policy(TestUtils.LanguageServerTarget language) {

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
            crossLanguageObjectsKms
                .stream()
                .map(key -> key + "-bad-both-meta-and-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(14)
    @ParameterizedTest(name = "{0}: Fail to decrypt KMS instruction file commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetKMSWithInstructionFile")
    void decrypt_kms_with_instruction_file_commitment_fails_with_forbid_policy(TestUtils.LanguageServerTarget language) {

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
            crossLanguageObjectsKms
                .stream()
                .map(key -> key + "-bad-only-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    // RSA instruction file decrypt

    @Order(20)
    @ParameterizedTest(name = "{0}: Successfully decrypt RSA encrypted original and good-copy objects")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetRawWithInstructionFile")
    void decrypt_rsa_original_and_good_copy_objects_succeeds(TestUtils.LanguageServerTarget language) {

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
                .map(key -> key + "-good-copy")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            crossLanguageObjectsRsa
        );
    }

    @Order(21)
    @ParameterizedTest(name = "{0}: Fail to decrypt RSA when commitment is duplicated in metadata and instruction file")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetRawWithInstructionFile")
    void decrypt_rsa_with_duplicate_commitment_in_metadata_and_instruction_fails(TestUtils.LanguageServerTarget language) {

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
                .map(key -> key + "-bad-both-meta-and-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(22)
    @ParameterizedTest(name = "{0}: Fail to decrypt RSA when commitment is only in instruction file")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetRawWithInstructionFile")
    void decrypt_rsa_with_commitment_only_in_instruction_file_fails(TestUtils.LanguageServerTarget language) {

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
                .map(key -> key + "-bad-only-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(23)
    @ParameterizedTest(name = "{0}: Fail to decrypt RSA duplicate commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetRawWithInstructionFile")
    void decrypt_rsa_with_duplicate_commitment_fails_with_forbid_policy(TestUtils.LanguageServerTarget language) {

        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(RSA_KEY)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();

        TestUtils.Decrypt_fails(
            client,
            S3ECId,
            crossLanguageObjectsRsa
                .stream()
                .map(key -> key + "-bad-both-meta-and-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(24)
    @ParameterizedTest(name = "{0}: Fail to decrypt RSA instruction file commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetRawWithInstructionFile")
    void decrypt_rsa_with_instruction_file_commitment_fails_with_forbid_policy(TestUtils.LanguageServerTarget language) {

        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(RSA_KEY)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();

        TestUtils.Decrypt_fails(
            client,
            S3ECId,
            crossLanguageObjectsRsa
                .stream()
                .map(key -> key + "-bad-only-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    // AES instruction file decrypt

    @Order(30)
    @ParameterizedTest(name = "{0}: Successfully decrypt AES encrypted original and good-copy objects")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetRawWithInstructionFile")
    void decrypt_aes_original_and_good_copy_objects_succeeds(TestUtils.LanguageServerTarget language) {

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
                .map(key -> key + "-good-copy")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            crossLanguageObjectsAes
        );
    }

    @Order(31)
    @ParameterizedTest(name = "{0}: Fail to decrypt AES when commitment is duplicated in metadata and instruction file")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetRawWithInstructionFile")
    void decrypt_aes_with_duplicate_commitment_in_metadata_and_instruction_fails(TestUtils.LanguageServerTarget language) {

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
                .map(key -> key + "-bad-both-meta-and-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(32)
    @ParameterizedTest(name = "{0}: Fail to decrypt AES when commitment is only in instruction file")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetRawWithInstructionFile")
    void decrypt_aes_with_commitment_only_in_instruction_file_fails(TestUtils.LanguageServerTarget language) {

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
                .map(key -> key + "-bad-only-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(33)
    @ParameterizedTest(name = "{0}: Fail to decrypt AES duplicate commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetRawWithInstructionFile")
    void decrypt_aes_with_duplicate_commitment_fails_with_forbid_policy(TestUtils.LanguageServerTarget language) {

        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(AES_KEY)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();

        TestUtils.Decrypt_fails(
            client,
            S3ECId,
            crossLanguageObjectsAes
                .stream()
                .map(key -> key + "-bad-both-meta-and-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(34)
    @ParameterizedTest(name = "{0}: Fail to decrypt AES instruction file commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetRawWithInstructionFile")
    void decrypt_aes_with_instruction_file_commitment_fails_with_forbid_policy(TestUtils.LanguageServerTarget language) {

        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(AES_KEY)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();

        TestUtils.Decrypt_fails(
            client,
            S3ECId,
            crossLanguageObjectsAes
                .stream()
                .map(key -> key + "-bad-only-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }
    

}
