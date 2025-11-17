/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static software.amazon.encryption.s3.TestUtils.*;

import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

/**
 * GCM Decryption Tests - Decrypt Phase
 * 
 * These tests decrypt objects that were encrypted by GCMEncryptTests.
 * All tests in this class can run fully in parallel with each other.
 * They depend on GCMEncryptTests completing first (enforced by GCMTestSuite).
 */
@Order(2)
class GCMDecryptTests {
    private static List<String> crossLanguageObjects;
    private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
        .kmsKeyId(TestUtils.KMS_KEY_ARN)
        .build();
    
    @BeforeAll
    static void setup() {
        // Import encrypted objects from the encrypt phase
        crossLanguageObjects = GCMEncryptTests.getCrossLanguageObjects();
        
        // Verify we have objects to decrypt
        if (crossLanguageObjects.isEmpty()) {
            throw new IllegalStateException(
                "No encrypted objects found. Ensure GCMEncryptTests runs first.");
        }
    }
    
    @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt should decrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_gcm(
        TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(kmsKeyArn)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build())
            .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, 
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
    
    @ParameterizedTest(name = "{0}: Transition configured with the default should decrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_the_default_should_decrypt_gcm(
        TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(kmsKeyArn)
                // .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build())
            .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, 
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }

    @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt should decrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_gcm(
        TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(kmsKeyArn)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build())
            .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, 
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
    
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptAllowDecrypt should decrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_allow_decrypt_should_decrypt_gcm(
        TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(kmsKeyArn)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                .build())
            .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, 
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
    
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should fail to decrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_require_decrypt_should_fail_to_decrypt_gcm(
        TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(kmsKeyArn)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build())
            .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt_fails(client, S3ECId, crossLanguageObjects, 
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
}
