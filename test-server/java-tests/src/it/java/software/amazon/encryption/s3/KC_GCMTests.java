/*
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
* SPDX-License-Identifier: Apache-2.0
*/

package software.amazon.encryption.s3;

import static software.amazon.encryption.s3.TestUtils.*;
import static software.amazon.encryption.s3.TestUtils.appendTestSuffix;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;

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
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
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
class KC_GCMTests {
    private static final String sharedObjectKeyBaseMetaDataMode = "test-kc-gcm-kms";
    private static final String sharedObjectKeyBaseInsFileMode = "test-kc-gcm-kms-instruction-file";
    private static KeyMaterial kmsKeyArn = KeyMaterial.builder()
    .kmsKeyId(TestUtils.KMS_KEY_ARN)
    .build();
    private static final List<String> crossLanguageObjectsMetaDataMode = new ArrayList<>();
    private static final List<String> crossLanguageObjectsInstructionFiles = new ArrayList<>();
    private static KeyPair RSA_KEY_PAIR_1;

    @BeforeAll
    static void setupKeys() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        RSA_KEY_PAIR_1 = keyPairGen.generateKeyPair();
    }
    
    @Order(1)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptAllowDecrypt should encrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_allow_decrypt_should_encrypt_kc_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Encrypt(client, S3ECId, appendTestSuffix(sharedObjectKeyBaseMetaDataMode + language.getLanguageName()), crossLanguageObjectsMetaDataMode, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(2)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should encrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_require_decrypt_should_encrypt_kc_gcm_ins_file(TestUtils.LanguageServerTarget language) {
        if (!RAW_SUPPORTED.contains(language.getLanguageName())) {
            throw new TestAbortedException("Not encrypting raw keyring with: " + language.getLanguageName());
        }

        KeyMaterial rsaKey = KeyMaterial.builder()
          .rsaKey(ByteBuffer.wrap(RSA_KEY_PAIR_1.getPrivate().getEncoded()))
          .build();

        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .instructionFileConfig(InstructionFileConfig.builder()
                .enableInstructionFilePutObject(true)
                .build())
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
            .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .keyMaterial(rsaKey).build())
          .build());
        String S3ECId = clientOutput.getClientId();

        TestUtils.Encrypt(client, S3ECId, appendTestSuffix(sharedObjectKeyBaseInsFileMode + language.getLanguageName()), crossLanguageObjectsInstructionFiles, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(2)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should encrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_require_decrypt_should_encrypt_kc_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Encrypt(client, S3ECId, appendTestSuffix(sharedObjectKeyBaseMetaDataMode + language.getLanguageName()), crossLanguageObjectsMetaDataMode, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(2)
    @ParameterizedTest(name = "{0}: Improved configured with the default should encrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_the_default_should_encrypt_kc_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        // .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Encrypt(client, S3ECId, appendTestSuffix(sharedObjectKeyBaseMetaDataMode + language.getLanguageName()), crossLanguageObjectsMetaDataMode, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }
        
    @Order(10)
    @ParameterizedTest(name = "{0}: Transition configured with the default should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_the_default_should_decrypt_kc_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        // .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(11)
    @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_kc_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(12)
    @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_kc_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }
    
    @Order(13)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptAllowDecrypt should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_allow_decrypt_should_decrypt_kc_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }
    
    @Order(14)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_require_decrypt_should_decrypt_kc_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(15)
    @ParameterizedTest(name = "{0}: Improved configured with the default should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_the_default_should_decrypt_kc_gcm(TestUtils.LanguageServerTarget language) {
        
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        // .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(16)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should encrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_require_decrypt_should_decrypt_kc_gcm_ins_file(final TestUtils.LanguageServerTarget language) {
        if (!RAW_SUPPORTED.contains(language.getLanguageName())) {
            throw new TestAbortedException("Not encrypting raw keyring with: " + language.getLanguageName());
        }

        KeyMaterial rsaKey = KeyMaterial.builder()
          .rsaKey(ByteBuffer.wrap(RSA_KEY_PAIR_1.getPrivate().getEncoded()))
          .build();

        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .instructionFileConfig(InstructionFileConfig.builder()
                .enableInstructionFilePutObject(true)
                .build())
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
            .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .keyMaterial(rsaKey).build())
          .build());
        String S3ECId = clientOutput.getClientId();

        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsInstructionFiles, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    // Ranged Get Tests - using existing KC-GCM encrypted objects with ranged-get-supported clients

    @Order(20)
    @ParameterizedTest(name = "{0}: Transition configured with the default can ranged get KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetTransitionClientsForTest")
    void transition_configured_with_the_default_can_ranged_get_kc_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .enableLegacyUnauthenticatedModes(true)
        // .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();

        TestUtils.DecryptWithRangedGet(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(21)
    @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt can ranged get KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetTransitionClientsForTest")
    void transition_configured_with_forbid_encrypt_allow_decrypt_can_ranged_get_kc_gcm(TestUtils.LanguageServerTarget language) {
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

        TestUtils.DecryptWithRangedGet(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(22)
    @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt can ranged get KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetImprovedClientsForTest")
    void improved_configured_with_forbid_encrypt_allow_decrypt_can_ranged_get_kc_gcm(TestUtils.LanguageServerTarget language) {
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

        TestUtils.DecryptWithRangedGet(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(23)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptAllowDecrypt can ranged get KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetImprovedClientsForTest")
    void improved_configured_with_require_encrypt_allow_decrypt_can_ranged_get_kc_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
        .enableLegacyUnauthenticatedModes(true)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();

        TestUtils.DecryptWithRangedGet(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(24)
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt can ranged get KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetImprovedClientsForTest")
    void improved_configured_with_require_encrypt_require_decrypt_can_ranged_get_kc_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .enableLegacyUnauthenticatedModes(true)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();

        TestUtils.DecryptWithRangedGet(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @Order(25)
    @ParameterizedTest(name = "{0}: Improved configured with the default can ranged get KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#rangedGetImprovedClientsForTest")
    void improved_configured_with_the_default_can_ranged_get_kc_gcm(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
        .config(S3ECConfig.builder()
        .keyMaterial(kmsKeyArn)
        .enableLegacyUnauthenticatedModes(true)
        // .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .build())
        .build());
        String S3ECId = clientOutput.getClientId();

        TestUtils.DecryptWithRangedGet(client, S3ECId, crossLanguageObjects, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

}
