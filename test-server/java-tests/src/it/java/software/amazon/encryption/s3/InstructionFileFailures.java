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
    private static final String sharedObjectKeyBaseMetaDataMode = "test-kc-gcm-kms";
    private static final String sharedObjectKeyBaseInsFileMode = "test-kc-gcm-kms-instruction-file";
    private static KeyMaterial kmsKeyArn = KeyMaterial.builder()
    .kmsKeyId(TestUtils.KMS_KEY_ARN)
    .build();
    private static final List<String> crossLanguageObjects = new ArrayList<>();
    private static KeyPair RSA_KEY_PAIR_1;

    @BeforeAll
    static void setupKeys() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        RSA_KEY_PAIR_1 = keyPairGen.generateKeyPair();
    }

    public static Stream<Arguments> improvedClientsCanPutKMSWithInstructionFile() {
        return improvedClientsForTest()
            .filter(target -> !INSTRUCTION_FILE_PUT_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()))
            .filter(target -> !KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
    }

    public static Stream<Arguments> clientsCanGetKMSWithInstructionFile() {
        Stream<Arguments> improved = improvedClientsForTest()
            .filter(target -> !KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        
        Stream<Arguments> transition = transitionClientsForTest()
            .filter(target -> !KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        
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
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
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
            appendTestSuffix(sharedObjectKeyBaseMetaDataMode + language.getLanguageName()),
            crossLanguageObjects,
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(2)
    @Test
    void make_good_copies_to_verify_we_can() throws Exception {
        // Create a plaintext S3 client to copy objects with instruction files
        try (S3Client ptS3Client = S3Client.create()) {
            for (String objectKey : crossLanguageObjects) {
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
                instructionFileMap.put("x-amz-matdesc", objectMetadata.get("x-amz-matdesc"));

                String instructionFileWithCommitmentValues = mapper.writeValueAsString(instructionFileMap);

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


    @Order(10)
    @ParameterizedTest(name = "{0}: Successfully decrypt original and good-copy objects")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetKMSWithInstructionFile")
    void decrypt_original_and_good_copy_objects_succeeds(TestUtils.LanguageServerTarget language) {

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
            crossLanguageObjects,
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );

        TestUtils.Decrypt(
            client,
            S3ECId,
            crossLanguageObjects
                .stream()
                .map(key -> key + "-good-copy")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            crossLanguageObjects
        );
    }

    @Order(11)
    @ParameterizedTest(name = "{0}: Fail to decrypt when commitment is duplicated in metadata and instruction file")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetKMSWithInstructionFile")
    void decrypt_with_duplicate_commitment_in_metadata_and_instruction_fails(TestUtils.LanguageServerTarget language) {

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
            crossLanguageObjects
                .stream()
                .map(key -> key + "-bad-both-meta-and-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(12)
    @ParameterizedTest(name = "{0}: Fail to decrypt when commitment is only in instruction file")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetKMSWithInstructionFile")
    void decrypt_with_commitment_only_in_instruction_file_fails(TestUtils.LanguageServerTarget language) {

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
            crossLanguageObjects
                .stream()
                .map(key -> key + "-bad-only-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(13)
    @ParameterizedTest(name = "{0}: Fail to decrypt duplicate commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetKMSWithInstructionFile")
    void decrypt_with_duplicate_commitment_fails_with_forbid_policy(TestUtils.LanguageServerTarget language) {

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
            crossLanguageObjects
                .stream()
                .map(key -> key + "-bad-both-meta-and-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

    @Order(14)
    @ParameterizedTest(name = "{0}: Fail to decrypt instruction file commitment with FORBID_ENCRYPT_ALLOW_DECRYPT policy")
    @MethodSource("software.amazon.encryption.s3.InstructionFileFailures#clientsCanGetKMSWithInstructionFile")
    void decrypt_with_instruction_file_commitment_fails_with_forbid_policy(TestUtils.LanguageServerTarget language) {

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
            crossLanguageObjects
                .stream()
                .map(key -> key + "-bad-only-instruction")
                .collect(Collectors.toList()),
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        );
    }

}
