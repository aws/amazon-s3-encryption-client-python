/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.GetObjectInput;
import software.amazon.encryption.s3.model.GetObjectOutput;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.PutObjectInput;
import software.amazon.encryption.s3.model.S3ECConfig;
import software.amazon.encryption.s3.model.S3EncryptionClientError;

import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import software.amazon.encryption.s3.TestUtils.*;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;

/**
 * Exhaustive tests for S3 Encryption Client round-trip operations.
 * These tests cover various combinations of client versions, commitment policies, and encryption modes.
 * 
 * Tests are based on the exhaustive test matrix defined at:
 * https://tiny.amazon.com/3xnzwczl/loopcloumicrpeyJ3
 * 
 * Tests 1-25 are included in this file.
 */
public class ExhaustiveRoundTripTests1_25 {

    @BeforeAll
    public static void setup() {
        TestUtils.validateServersRunning();
    }

    // Begin Exhaustive tests defined here:
    // https://tiny.amazon.com/3xnzwczl/loopcloumicrpeyJ3
    

    // Exhaustive test 2
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	ForbidEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1, Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
      TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        final String objectKey = "test-key-kms-v1-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create the object using the old client
        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(TestUtils.KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(TestUtils.KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(TestUtils.BUCKET, objectKey, input);

        S3ECTestServerClient decClient = TestUtils.testServerClientFor(language);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .enableLegacyWrappingAlgorithms(true)
            .build()
          )
          .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC object with a current version client
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
          .clientID(decS3ECId)
          .bucket(TestUtils.BUCKET)
          .key(objectKey)
          .build());

        // Then: Pass
    }

    // Exhaustive test 3
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	ForbidEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
        TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        final String objectKey = "test-key-kms-v1-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with GCM encryption
        // V1 Client with GCM
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(TestUtils.KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption) // StrictAuthenticatedEncryption uses GCM
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(TestUtils.KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(TestUtils.BUCKET, objectKey, input);

        // When: decrypt GCM object with an improved version client
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 4
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	ForbidEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#encryptImprovedDecryptImproved")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            LanguageServerTarget encLang, LanguageServerTarget decLang
    ) {

        S3ECTestServerClient encClient = TestUtils.testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-improved-test-key-" + encLang;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String encS3ECId = encClientOutput.getClientId();
        
        // Given: object encrypted with key commitment
        encClient.putObject(PutObjectInput.builder()
                .clientID(encS3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());
                
        S3ECTestServerClient decClient = TestUtils.testServerClientFor(decLang);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC-GCM object with an improved version client with ForbidEncryptAllowDecrypt policy
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

}
