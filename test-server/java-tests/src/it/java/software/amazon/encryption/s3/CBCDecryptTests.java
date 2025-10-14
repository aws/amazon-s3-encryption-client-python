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
import org.junit.jupiter.api.Nested;
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
 * These tests deal with decrypting CBC messages
 */

class CBCDecryptTests {
    private static String sharedObjectKey = appendTestSuffix("test-cbc-kms-v1-");
    private static String sharedInput = "simple-test-input";
    private static KeyMaterial kmsKeyArn = KeyMaterial.builder()
        .kmsKeyId(TestUtils.KMS_KEY_ARN)
        .build();
    
    @BeforeAll
    static void encryptCBCObject() {
    // Create the object using the old client
    // V1 Client
    EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(TestUtils.KMS_KEY_ARN);

    CryptoConfiguration v1Config =
        new CryptoConfiguration(CryptoMode.EncryptionOnly)
            .withStorageMode(CryptoStorageMode.ObjectMetadata)
            .withAwsKmsRegion(TestUtils.KMS_REGION);

    AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
        .withCryptoConfiguration(v1Config)
        .withEncryptionMaterials(materialsProvider)
        .build();

    v1Client.putObject(TestUtils.BUCKET, sharedObjectKey, sharedInput);
    }
    
    @ParameterizedTest(name = "{displayName} Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void FORBID_ENCRYPT_ALLOW_DECRYPT(TestUtils.LanguageServerTarget language) {
    S3ECTestServerClient decClient = TestUtils.testServerClientFor(language);
    CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .enableLegacyUnauthenticatedModes(true)
            .build())
        .build());
    String decS3ECId = decClientOutput.getClientId();

    // When: decrypt KC-GCM object with an improved version client with ForbidEncryptAllowDecrypt policy
    GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
        .clientID(decS3ECId)
        .bucket(TestUtils.BUCKET)
        .key(sharedObjectKey)
        .build());

    // Then: Pass
    assertEquals(sharedInput, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    @ParameterizedTest(name = "{displayName} Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void REQUIRE_ENCRYPT_ALLOW_DECRYPT(TestUtils.LanguageServerTarget language) {
    S3ECTestServerClient decClient = TestUtils.testServerClientFor(language);
    CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
            .enableLegacyUnauthenticatedModes(true)
            .build())
        .build());
    String decS3ECId = decClientOutput.getClientId();

    // When: decrypt KC-GCM object with an improved version client with ForbidEncryptAllowDecrypt policy
    GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
        .clientID(decS3ECId)
        .bucket(TestUtils.BUCKET)
        .key(sharedObjectKey)
        .build());

    // Then: Pass
    assertEquals(sharedInput, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    @ParameterizedTest(name = "{displayName} Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void REQUIRE_ENCRYPT_REQUIRE_DECRYPT(TestUtils.LanguageServerTarget language) {
    S3ECTestServerClient decClient = TestUtils.testServerClientFor(language);
    CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .enableLegacyUnauthenticatedModes(true)
            .build())
        .build());
    String decS3ECId = decClientOutput.getClientId();

    try {
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
            .clientID(decS3ECId)
            .bucket(TestUtils.BUCKET)
            .key(sharedObjectKey)
            .build());
        fail("Should not be able to decrypt CBC");
    } catch (S3EncryptionClientError e) {
        // This is a success
    }
    }

    @ParameterizedTest(name = "{displayName} Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void Default_Commitment_Policy(TestUtils.LanguageServerTarget language) {
    S3ECTestServerClient decClient = TestUtils.testServerClientFor(language);
    CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .build())
        .build());
    String decS3ECId = decClientOutput.getClientId();

    try {
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
            .clientID(decS3ECId)
            .bucket(TestUtils.BUCKET)
            .key(sharedObjectKey)
            .build());
        fail("Should not be able to decrypt CBC");
    } catch (S3EncryptionClientError e) {
        // This is a success
    }
    }
}
