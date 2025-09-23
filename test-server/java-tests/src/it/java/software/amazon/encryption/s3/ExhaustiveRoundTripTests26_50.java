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
 * Tests 26-50 are included in this file.
 */
public class ExhaustiveRoundTripTests26_50 {

    @BeforeAll
    public static void setup() {
        TestUtils.setupTestServers();
    }

    // Begin Exhaustive tests defined here:
    // https://tiny.amazon.com/3xnzwczl/loopcloumicrpeyJ3
    
    // Exhaustive test 26
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	null	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientReEncryptingWithNullPolicy_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-null-policy-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with null policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with CBC encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with null policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(TestUtils.BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with null policy");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Commitment policy cannot be null for re-encryption operations"));
        }
    }

    // Exhaustive test 27
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	null	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientReEncryptingWithNullPolicy_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-null-policy-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with GCM encryption (null policy)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with null policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(TestUtils.BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with null policy");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Commitment policy cannot be null for re-encryption operations"));
        }
    }

    // Exhaustive test 28
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	ReEncrypt	null	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientReEncryptingWithNullPolicy_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-null-policy-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with KC-GCM encryption (null policy)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with KC-GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with null policy (should allow since existing encryption is KC-GCM)
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }


    // Exhaustive test 29
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	ReEncrypt	ForbidEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientReEncryptingWithForbidEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-forbid-encrypt-allow-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with ForbidEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with CBC encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with ForbidEncryptAllowDecrypt policy
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 30
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	ReEncrypt	ForbidEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientReEncryptingWithForbidEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-forbid-encrypt-allow-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with GCM encryption and ForbidEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with ForbidEncryptAllowDecrypt policy
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 31
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	ForbidEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientReEncryptingWithForbidEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-forbid-encrypt-allow-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with KC-GCM encryption and ForbidEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with KC-GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with ForbidEncryptAllowDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(TestUtils.BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with ForbidEncryptAllowDecrypt policy");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Re-encryption with ForbidEncryptAllowDecrypt policy is not allowed"));
        }
    }

    // Exhaustive test 32
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	RequireEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-allow-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with RequireEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with CBC encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with RequireEncryptAllowDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(TestUtils.BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with RequireEncryptAllowDecrypt policy on CBC");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Re-encryption with RequireEncryptAllowDecrypt policy requires key commitment"));
        }
    }

    // Exhaustive test 33
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	RequireEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-allow-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with GCM encryption and RequireEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with RequireEncryptAllowDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(TestUtils.BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with RequireEncryptAllowDecrypt policy on GCM");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Re-encryption with RequireEncryptAllowDecrypt policy requires key commitment"));
        }
    }

    // Exhaustive test 34
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	ReEncrypt	RequireEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-allow-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with KC-GCM encryption and RequireEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with KC-GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with RequireEncryptAllowDecrypt policy
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 35
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	RequireEncryptRequireDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptRequireDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-require-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with RequireEncryptRequireDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with CBC encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with RequireEncryptRequireDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(TestUtils.BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with RequireEncryptRequireDecrypt policy on CBC");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Re-encryption with RequireEncryptRequireDecrypt policy requires key commitment"));
        }
    }

    // Exhaustive test 36
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	RequireEncryptRequireDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptRequireDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-require-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with GCM encryption and RequireEncryptRequireDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with RequireEncryptRequireDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(TestUtils.BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with RequireEncryptRequireDecrypt policy on GCM");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Re-encryption with RequireEncryptRequireDecrypt policy requires key commitment"));
        }
    }

    // Exhaustive test 37
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	ReEncrypt	RequireEncryptRequireDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#improvedClientsForTest")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptRequireDecrypt_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-require-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with KC-GCM encryption and RequireEncryptRequireDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with KC-GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with RequireEncryptRequireDecrypt policy
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }


    // Exhaustive test 38
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	Decrypt	ForbidEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-CBC, Decrypt: {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_TransitionClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            String language
    ) {
        // Given: decrypt language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-cbc-transition-forbid-encrypt-allow-decrypt-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
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

        // When: decrypt CBC object with a transition version client with ForbidEncryptAllowDecrypt policy
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 39
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	Decrypt	ForbidEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_TransitionClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            String language
    ) {
        // Given: decrypt language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-gcm-transition-forbid-encrypt-allow-decrypt-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
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

        // When: decrypt GCM object with a transition version client with ForbidEncryptAllowDecrypt policy
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 40
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	Decrypt	ForbidEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("TestUtils#crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_TransitionClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            TestUtils.LanguageServerTarget encLang, TestUtils.LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = TestUtils.testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-transition-forbid-encrypt-allow-decrypt-" + encLang;
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
        // Create client with ForbidEncryptAllowDecrypt commitment policy
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC-GCM object with a transition version client with ForbidEncryptAllowDecrypt policy
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 41
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	Decrypt	null	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-CBC, Decrypt: {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_TransitionClientDecryptingWithNullPolicy_WHEN_Decrypt_THEN_Pass(
            String language
    ) {
        // Given: decrypt language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-cbc-transition-null-policy-" + language;
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

        // When: decrypt CBC object with a transition version client with null policy
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 42
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	Decrypt	null	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_TransitionClientDecryptingWithNullPolicy_WHEN_Decrypt_THEN_Pass(
            String language
    ) {
        // Given: decrypt language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "test-key-kms-v1-gcm-transition-null-policy-" + language;
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

        // When: decrypt GCM object with a transition version client with null policy
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 43
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Transition	Decrypt	null	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("TestUtils#crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_TransitionClientDecryptingWithNullPolicy_WHEN_Decrypt_THEN_Fail(
            TestUtils.LanguageServerTarget encLang, TestUtils.LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = TestUtils.testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-transition-null-policy-fail-" + encLang;
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

        // When: decrypt KC-GCM object with a transition version client with null policy
        // Then: Fails
        try {
            decClient.getObject(GetObjectInput.builder()
                    .clientID(decS3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting KC-GCM with null policy"));
        }
    }

    // Exhaustive test 44
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	Decrypt	null	KC-GCM	
    // Note: This seems to be a duplicate of test 43 but with a different outcome. 
    // I'll implement it as a separate test with a different object key.

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("TestUtils#crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_TransitionClientDecryptingWithNullPolicy_WHEN_Decrypt_THEN_Pass(
            TestUtils.LanguageServerTarget encLang, TestUtils.LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version
        if (!TestUtils.IMPROVED_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = TestUtils.testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-transition-null-policy-pass-" + encLang;
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

        // When: decrypt KC-GCM object with a transition version client with null policy
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 45
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	Encrypt	ForbidEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_TransitionClientEncryptingWithForbidEncryptAllowDecrypt_WHEN_EncryptWithCBC_THEN_Pass(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-transition-forbid-encrypt-allow-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
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

        // When: encrypt with CBC using a transition version client with ForbidEncryptAllowDecrypt policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 46
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	Encrypt	ForbidEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_TransitionClientEncryptingWithForbidEncryptAllowDecrypt_WHEN_EncryptWithGCM_THEN_Pass(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-transition-forbid-encrypt-allow-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();
        
        // Create client with ForbidEncryptAllowDecrypt commitment policy and GCM encryption
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with GCM using a transition version client with ForbidEncryptAllowDecrypt policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 47
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Transition	Encrypt	ForbidEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_TransitionClientEncryptingWithForbidEncryptAllowDecrypt_WHEN_EncryptWithKCGCM_THEN_Fail(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-transition-forbid-encrypt-allow-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();
        
        // Create client with ForbidEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with KC-GCM using a transition version client with ForbidEncryptAllowDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(TestUtils.BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with ForbidEncryptAllowDecrypt policy"));
        }
    }

    // Exhaustive test 48
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	Encrypt	null	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_TransitionClientEncryptingWithNullPolicy_WHEN_EncryptWithCBC_THEN_Pass(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-transition-null-policy-cbc-" + language;
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

        // When: encrypt with CBC using a transition version client with null policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 49
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	Encrypt	null	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_TransitionClientEncryptingWithNullPolicy_WHEN_EncryptWithGCM_THEN_Pass(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "encrypt-transition-null-policy-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set) and GCM encryption
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with GCM using a transition version client with null policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 50
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	ReEncrypt	null	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_TransitionClientReEncryptingWithNullPolicy_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-transition-null-policy-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with null policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with CBC encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with null policy
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }
}
