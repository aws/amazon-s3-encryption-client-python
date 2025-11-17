/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentest4j.TestAbortedException;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.InstructionFileConfig;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

/**
 * KC-GCM Decryption Tests - Decrypt Phase
 * 
 * These tests decrypt objects that were encrypted by KC_GCMEncryptTests.
 * All tests in this class can run fully in parallel with each other.
 * They depend on KC_GCMEncryptTests completing first (enforced by KC_GCMTestSuite).
 */
@Order(2)
class KC_GCMDecryptTests {
    private static List<String> crossLanguageObjectsMetaDataMode;
    private static List<String> crossLanguageObjectsInstructionFiles;
    private static KeyPair RSA_KEY_PAIR_1;
    private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
        .kmsKeyId(TestUtils.KMS_KEY_ARN)
        .build();
    
    @BeforeAll
    static void setup() {
        // Import encrypted objects and RSA key from the encrypt phase
        crossLanguageObjectsMetaDataMode = KC_GCMEncryptTests.getCrossLanguageObjectsMetaDataMode();
        crossLanguageObjectsInstructionFiles = KC_GCMEncryptTests.getCrossLanguageObjectsInstructionFiles();
        RSA_KEY_PAIR_1 = KC_GCMEncryptTests.getRsaKeyPair();
        
        // Verify we have objects to decrypt
        if (crossLanguageObjectsMetaDataMode.isEmpty()) {
            throw new IllegalStateException(
                "No encrypted objects found. Ensure KC_GCMEncryptTests runs first.");
        }
    }
    
    @ParameterizedTest(name = "{0}: Transition configured with the default should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_the_default_should_decrypt_kc_gcm(
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
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_kc_gcm(
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
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_forbid_encrypt_allow_decrypt_should_decrypt_kc_gcm(
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
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }
    
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptAllowDecrypt should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_allow_decrypt_should_decrypt_kc_gcm(
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
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }
    
    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_require_decrypt_should_decrypt_kc_gcm(
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
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @ParameterizedTest(name = "{0}: Improved configured with the default should decrypt KC-GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_the_default_should_decrypt_kc_gcm(
        TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
            .config(S3ECConfig.builder()
                .keyMaterial(kmsKeyArn)
                // .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build())
            .build());
        String S3ECId = clientOutput.getClientId();
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsMetaDataMode, 
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    @ParameterizedTest(name = "{0}: Improved configured with RequireEncryptRequireDecrypt should decrypt KC-GCM (instruction file)")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_require_encrypt_require_decrypt_should_decrypt_kc_gcm_ins_file(
        final TestUtils.LanguageServerTarget language
    ) {
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
        
        TestUtils.Decrypt(client, S3ECId, crossLanguageObjectsInstructionFiles, 
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }
}
