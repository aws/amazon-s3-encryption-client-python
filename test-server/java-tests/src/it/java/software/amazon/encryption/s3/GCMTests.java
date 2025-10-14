/*
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
* SPDX-License-Identifier: Apache-2.0
*/

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.TestUtils.*;

import java.lang.annotation.ElementType;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
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
*/

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class GCMTests {
    private static String sharedObjectKeyBase = "test-gcm-kms";
    private static KeyMaterial kmsKeyArn = KeyMaterial.builder()
    .kmsKeyId(TestUtils.KMS_KEY_ARN)
    .build();
    private static List<String> crossLanguageObjects = new ArrayList<>();
    
    @Order(1)
    @ParameterizedTest(name = "{displayName} Encrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void ENCRYPT_FORBID_ENCRYPT_ALLOW_DECRYPT_IMPROVED(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        Encrypt(client, S3ECId, appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()));
    }
    
    // @Order(2)
    // @ParameterizedTest(name = "{displayName} Encrypt: {0}")
    // @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    // void ENCRYPT_DEFAULT_TRANSITIONAL(TestUtils.LanguageServerTarget language) {
    //     S3ECTestServerClient client = TestUtils.testServerClientFor(language);
    //     CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
    //     .config(S3ECConfig.builder()
    //     .keyMaterial(kmsKeyArn)
    //     // .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
    //     .build())
    //     .build());
    //     String S3ECId = clientOutput.getClientId();
        
    //     Encrypt(client, S3ECId, appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()));
    // }
    
    @Order(10)
    @ParameterizedTest(name = "{displayName} Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void DECRYPT_FORBID_ENCRYPT_ALLOW_DECRYPT_IMPROVED(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        Decrypt(client, S3ECId);
    }
    
    @Order(11)
    @ParameterizedTest(name = "{displayName} Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void DECRYPT_TRANSITIONAL_DEFAULT(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        // .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        Decrypt(client, S3ECId);
    }
    
    @Order(12)
    @ParameterizedTest(name = "{displayName} Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void DECRYPT_REQUIRE_ENCRYPT_ALLOW_DECRYPT_IMPROVED(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        Decrypt(client, S3ECId);
    }
    
    @Order(13)
    @ParameterizedTest(name = "{displayName} Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void DECRYPT_REQUIRE_ENCRYPT_REQUIRE_DECRYPT_IMPROVED(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        Decrypt_fails(client, S3ECId);
    }
    
    void Encrypt(S3ECTestServerClient client, String S3ECId, String objectKey)
    {
        client.putObject(PutObjectInput.builder()
        .clientID(S3ECId)
        .key(objectKey)
        .bucket(TestUtils.BUCKET)
        .body(ByteBuffer.wrap(objectKey.getBytes(StandardCharsets.UTF_8)))
        .build());
        
        crossLanguageObjects.add(objectKey);
    }
    
    void Decrypt(S3ECTestServerClient client, String S3ECId)
    {
        for (String objectKey : crossLanguageObjects) {
            GetObjectOutput output = client.getObject(GetObjectInput.builder()
            .clientID(S3ECId)
            .bucket(TestUtils.BUCKET)
            .key(objectKey)
            .build());
            
            // Then: Pass
            assertEquals(objectKey, new String(output.getBody().array()));
        }
    }
    
    void Decrypt_fails(S3ECTestServerClient client, String S3ECId)
    {
        for (String objectKey : crossLanguageObjects) {
            try {
                GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(S3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());
            } catch (S3EncryptionClientError e) {
                // This is a success
            }
        }
    }
    
}
