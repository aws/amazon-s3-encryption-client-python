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
 * Tests 51-55 are included in this file.
 */
public class ExhaustiveRoundTripTests51_55 {

    @BeforeAll
    public static void setup() {
        TestUtils.setupTestServers();
    }

    // Begin Exhaustive tests defined here:
    // https://tiny.amazon.com/3xnzwczl/loopcloumicrpeyJ3

    // Exhaustive test 51
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	ReEncrypt	null	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_TransitionClientReEncryptingWithNullPolicy_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-transition-null-policy-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with null policy and GCM encryption
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        // No commitment policy set - defaults to null
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

    // Exhaustive test 52
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Transition	ReEncrypt	null	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_KCGCMEncryptedData_AND_TransitionClientReEncryptingWithNullPolicy_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-transition-null-policy-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with KC-GCM encryption
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

        // Create a new client with null policy for re-encryption
        CreateClientOutput output2 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String nullPolicyClientId = output2.getClientId();

        // Attempt to re-encrypt with null policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(nullPolicyClientId)
                    .key(objectKey)
                    .bucket(TestUtils.BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with null policy on KC-GCM");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for re-encrypting KC-GCM with null policy"));
        }
    }

    // Exhaustive test 53
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	ReEncrypt	ForbidEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_TransitionClientReEncryptingWithForbidEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-transition-forbid-encrypt-allow-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with ForbidEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
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

    // Exhaustive test 54
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Transition	ReEncrypt	ForbidEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_TransitionClientReEncryptingWithForbidEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-transition-forbid-encrypt-allow-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with GCM encryption and ForbidEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
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

    // Exhaustive test 55
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Transition	ReEncrypt	ForbidEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("TestUtils#transitionClientsForTest")
    public void GIVEN_KCGCMEncryptedData_AND_TransitionClientReEncryptingWithForbidEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is a transition version
        if (!TestUtils.TRANSITION_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = TestUtils.testServerClientFor(TestUtils.getServerMap().get(language));
        final String objectKey = "reencrypt-transition-forbid-encrypt-allow-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(TestUtils.KMS_KEY_ARN)
                .build();

        // Create client with KC-GCM encryption
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

        // Create a new client with ForbidEncryptAllowDecrypt policy for re-encryption
        CreateClientOutput output2 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String forbidEncryptClientId = output2.getClientId();

        // Attempt to re-encrypt with ForbidEncryptAllowDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(forbidEncryptClientId)
                    .key(objectKey)
                    .bucket(TestUtils.BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with ForbidEncryptAllowDecrypt policy on KC-GCM");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for re-encrypting KC-GCM with ForbidEncryptAllowDecrypt policy"));
        }
    }
}
