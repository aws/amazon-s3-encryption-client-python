/*
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
* SPDX-License-Identifier: Apache-2.0
*/

package software.amazon.encryption.s3;

import static software.amazon.encryption.s3.TestUtils.appendTestSuffix;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;
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
    @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt should encrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_forbid_encrypt_allow_decrypt_should_encrypt_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Encrypt(client, S3ECId, appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()), crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
    
    @Order(2)
    @ParameterizedTest(name = "{0}: Transition configured with the default should encrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_the_default_should_encrypt_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        // .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Encrypt(client, S3ECId, appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()), crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }

    @Order(3)
    @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt should encrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_forbid_encrypt_allow_decrypt_should_encrypt_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Encrypt(client, S3ECId, appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()), crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
    
    @Order(10)
    @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt should decrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
    
    @Order(11)
    @ParameterizedTest(name = "{0}: Transition configured with the default should decrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_the_default_should_decrypt_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        // .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }

    @Order(12)
    @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt should decrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
    
    @Order(13)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptAllowDecrypt should decrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_allow_decrypt_should_decrypt_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
    
    @Order(14)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should fail to decrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_require_decrypt_should_fail_to_decrypt_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt_fails(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }

    // Ranged Get Tests - using existing GCM encrypted objects with ranged-get-supported clients

    @Order(21)
    @ParameterizedTest(name = "{0}: Transition configured with the default can ranged get GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetTransitionClientsForTest")
    void transition_configured_with_the_default_can_ranged_get_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .enableLegacyUnauthenticatedModes(true)
        // .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.DecryptWithRangedGet(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }

    @Order(22)
    @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt can ranged get GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetTransitionClientsForTest")
    void transition_configured_with_forbid_encrypt_allow_decrypt_can_ranged_get_gcm(TestUtils.LanguageServerTarget language) {
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
        
        TestUtils.DecryptWithRangedGet(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }

    @Order(23)
    @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt can ranged get GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetImprovedClientsForTest")
    void improved_configured_with_forbid_encrypt_allow_decrypt_can_ranged_get_gcm(TestUtils.LanguageServerTarget language) {
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
        
        TestUtils.DecryptWithRangedGet(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }

    @Order(24)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptAllowDecrypt can ranged get GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetImprovedClientsForTest")
    void improved_configured_with_require_encrypt_allow_decrypt_can_ranged_get_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
        .enableLegacyUnauthenticatedModes(true)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.DecryptWithRangedGet(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }

    @Order(25)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should fail to ranged get GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetImprovedClientsForTest")
    void improved_configured_with_require_encrypt_require_decrypt_should_fail_to_ranged_get_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .enableLegacyUnauthenticatedModes(true)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.DecryptWithRangedGet_fails(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
    
}
