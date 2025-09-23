/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.encryption.s3.model.*;
import software.amazon.encryption.s3.client.S3ECTestServerClient;

import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;

import static software.amazon.encryption.s3.TestUtils.*;

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
        TestUtils.setupTestServers();
    }

    // Begin Exhaustive tests defined here:
    // https://tiny.amazon.com/3xnzwczl/loopcloumicrpeyJ3
    

    // Exhaustive test 1
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Current	Decrypt	null	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("TestUtils#crossLanguageClients")
    public void GIVEN_DataEncryptedWithKC_AND_CurrentClientDecrypting_WHEN_Decrypt_THEN_Fail(TestUtils.LanguageServerTarget encLang, TestUtils.LanguageServerTarget decLang) {
        // Given: encrypt language is either an improved version or a transition version
        if (!TestUtils.IMPROVED_VERSIONS.contains(encLang.getLanguageName()) || !TestUtils.TRANSITION_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is a current version
        if (!TestUtils.CURRENT_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = TestUtils.testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-decrypt-current-test-key-" + encLang;
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
            .keyMaterial(kmsKeyArn).build())
          .build());
        String decS3ECId = decClientOutput.getClientId();

        // Then: Fails
        try {
            decClient.getObject(GetObjectInput.builder()
              .clientID(decS3ECId)
              .bucket(TestUtils.BUCKET)
              .key(objectKey)
              .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting unrecognized alg suite"));
        }
    }

    // Exhaustive test 2
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	ForbidEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1, Decrypt: {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
      TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

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
            .keyMaterial(kmsKeyArn).build())
          .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC object with a current version client
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
          .clientID(decS3ECId)
          .bucket(TestUtils.BUCKET)
          .key(objectKey)
          .build());

        // Then: Pass
        client.getObject(GetObjectInput.builder()
          .clientID(s3ECId)
          .bucket(TestUtils.BUCKET)
          .key(objectKey)
          .build());
    }

    // Exhaustive test 3
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	ForbidEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            String language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
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
    @MethodSource("TestUtils#crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            TestUtils.LanguageServerTarget encLang, TestUtils.LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version or a transition version
        if (!TestUtils.IMPROVED_VERSIONS.contains(encLang.getLanguageName()) || !TestUtils.TRANSITION_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

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


    // Exhaustive test 5
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Decrypt	null	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-CBC, Decrypt: {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientDecryptingWithNullPolicy_WHEN_Decrypt_THEN_Fail(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-cbc-null-policy-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with CBC encryption
        // V1 Client with CBC
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(TestUtils.KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption) // AuthenticatedEncryption uses CBC
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(TestUtils.KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(TestUtils.BUCKET, objectKey, input);

        // When: decrypt CBC object with an improved version client with null policy
        // Then: Fails
        try {
            client.getObject(GetObjectInput.builder()
                    .clientID(s3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting with null policy"));
        }
    }

    // Exhaustive test 6
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Decrypt	null	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientDecryptingWithNullPolicy_WHEN_Decrypt_THEN_Fail(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-gcm-null-policy-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
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

        // When: decrypt GCM object with an improved version client with null policy
        // Then: Fails
        try {
            client.getObject(GetObjectInput.builder()
                    .clientID(s3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting with null policy"));
        }
    }

    // Exhaustive test 7
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	null	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("TestUtils#crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientDecryptingWithNullPolicy_WHEN_Decrypt_THEN_Pass(
            TestUtils.LanguageServerTarget encLang, TestUtils.LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = TestUtils.testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-improved-null-policy-" + encLang;
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
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC-GCM object with an improved version client with null policy
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }


    // Exhaustive test 8
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	RequireEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-CBC, Decrypt: {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-cbc-require-encrypt-allow-decrypt-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with CBC encryption
        // V1 Client with CBC
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption) // AuthenticatedEncryption uses CBC
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt CBC object with an improved version client with RequireEncryptAllowDecrypt policy
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 9
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	RequireEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-gcm-require-encrypt-allow-decrypt-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with GCM encryption
        // V1 Client with GCM
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption) // StrictAuthenticatedEncryption uses GCM
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt GCM object with an improved version client with RequireEncryptAllowDecrypt policy
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 10
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	RequireEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("TestUtils#crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            TestUtils.LanguageServerTarget encLang, TestUtils.LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = TestUtils.testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-improved-require-encrypt-allow-decrypt-" + encLang;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
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
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());
                
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC-GCM object with an improved version client with RequireEncryptAllowDecrypt policy
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 11
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Decrypt	RequireEncryptRequireDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-CBC, Decrypt: {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptRequireDecrypt_WHEN_Decrypt_THEN_Fail(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-cbc-require-encrypt-require-decrypt-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with CBC encryption
        // V1 Client with CBC
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption) // AuthenticatedEncryption uses CBC
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt CBC object with an improved version client with RequireEncryptRequireDecrypt policy
        // Then: Fails
        try {
            client.getObject(GetObjectInput.builder()
                    .clientID(s3ECId)
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting with RequireEncryptRequireDecrypt policy"));
        }
    }

    // Exhaustive test 12
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Decrypt	RequireEncryptRequireDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptRequireDecrypt_WHEN_Decrypt_THEN_Fail(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-gcm-require-encrypt-require-decrypt-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with GCM encryption
        // V1 Client with GCM
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption) // StrictAuthenticatedEncryption uses GCM
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt GCM object with an improved version client with RequireEncryptRequireDecrypt policy
        // Then: Fails
        try {
            client.getObject(GetObjectInput.builder()
                    .clientID(s3ECId)
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting with RequireEncryptRequireDecrypt policy"));
        }
    }

    // Exhaustive test 13
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	RequireEncryptRequireDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("TestUtils#crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptRequireDecrypt_WHEN_Decrypt_THEN_Pass(
            TestUtils.LanguageServerTarget encLang, TestUtils.LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = TestUtils.testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-improved-require-encrypt-require-decrypt-" + encLang;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
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
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());
                
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC-GCM object with an improved version client with RequireEncryptRequireDecrypt policy
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 14
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Encrypt	ForbidEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithForbidEncryptAllowDecrypt_WHEN_EncryptWithCBC_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-forbid-encrypt-allow-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with ForbidEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with CBC using an improved version client with ForbidEncryptAllowDecrypt policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 15
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Encrypt	ForbidEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithForbidEncryptAllowDecrypt_WHEN_EncryptWithGCM_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-forbid-encrypt-allow-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with ForbidEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with GCM using an improved version client with ForbidEncryptAllowDecrypt policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 16
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	ForbidEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithForbidEncryptAllowDecrypt_WHEN_EncryptWithKCGCM_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-forbid-encrypt-allow-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with ForbidEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with KC-GCM using an improved version client with ForbidEncryptAllowDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with ForbidEncryptAllowDecrypt policy"));
        }
    }

    // Exhaustive test 17
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	null	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithNullPolicy_WHEN_EncryptWithCBC_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-null-policy-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with CBC using an improved version client with null policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with null policy"));
        }
    }

    // Exhaustive test 18
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	null	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithNullPolicy_WHEN_EncryptWithGCM_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-null-policy-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with GCM using an improved version client with null policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with null policy"));
        }
    }

    // Exhaustive test 19
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Encrypt	null	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithNullPolicy_WHEN_EncryptWithKCGCM_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-null-policy-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with KC-GCM using an improved version client with null policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 20
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	RequireEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptAllowDecrypt_WHEN_EncryptWithCBC_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-require-encrypt-allow-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with CBC using an improved version client with RequireEncryptAllowDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with RequireEncryptAllowDecrypt policy"));
        }
    }

    // Exhaustive test 21
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	RequireEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptAllowDecrypt_WHEN_EncryptWithGCM_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-require-encrypt-allow-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with GCM using an improved version client with RequireEncryptAllowDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with RequireEncryptAllowDecrypt policy"));
        }
    }

    // Exhaustive test 22
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Encrypt	RequireEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptAllowDecrypt_WHEN_EncryptWithKCGCM_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-require-encrypt-allow-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with KC-GCM using an improved version client with RequireEncryptAllowDecrypt policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 23
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	RequireEncryptRequireDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptRequireDecrypt_WHEN_EncryptWithCBC_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-require-encrypt-require-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with CBC using an improved version client with RequireEncryptRequireDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with RequireEncryptRequireDecrypt policy"));
        }
    }

    // Exhaustive test 24
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	RequireEncryptRequireDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptRequireDecrypt_WHEN_EncryptWithGCM_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-improved-require-encrypt-require-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with GCM using an improved version client with RequireEncryptRequireDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with RequireEncryptRequireDecrypt policy"));
        }
    }

    // Exhaustive test 25
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Encrypt	RequireEncryptRequireDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptRequire
        final String objectKey = "encrypt-improved-require-encrypt-require-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with KC-GCM using an improved version client with RequireEncryptRequireDecrypt policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }
}
