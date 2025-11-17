/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static software.amazon.encryption.s3.TestUtils.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
 * GCM Encryption Tests - Encrypt Phase
 * 
 * These tests encrypt objects using GCM encryption algorithm.
 * All tests in this class can run in parallel with each other.
 * The encrypted objects are stored in a thread-safe list for use by GCMDecryptTests.
 */
@Order(1)
class GCMEncryptTests {
    private static final String sharedObjectKeyBase = "test-gcm-kms";
    private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
        .kmsKeyId(TestUtils.KMS_KEY_ARN)
        .build();
    
    // Thread-safe list for storing encrypted object keys
    private static final List<String> crossLanguageObjects = 
        Collections.synchronizedList(new ArrayList<>());
    
    /**
     * Public accessor for decrypt tests to retrieve encrypted object keys
     */
    public static List<String> getCrossLanguageObjects() {
        return new ArrayList<>(crossLanguageObjects); // Return defensive copy
    }
    
    @ParameterizedTest(name = "{0}: Improved configured with ForbidEncryptAllowDecrypt should encrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_configured_with_forbid_encrypt_allow_decrypt_should_encrypt_gcm(
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
        
        TestUtils.Encrypt(client, S3ECId, 
            appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()), 
            crossLanguageObjects, 
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
    
    @ParameterizedTest(name = "{0}: Transition configured with the default should encrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_the_default_should_encrypt_gcm(
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
        
        TestUtils.Encrypt(client, S3ECId, 
            appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()), 
            crossLanguageObjects, 
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }

    @ParameterizedTest(name = "{0}: Transition configured with ForbidEncryptAllowDecrypt should encrypt GCM")
    @MethodSource("software.amazon.encryption.s3.TestUtils#transitionClientsForTest")
    void transition_configured_with_forbid_encrypt_allow_decrypt_should_encrypt_gcm(
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
        
        TestUtils.Encrypt(client, S3ECId, 
            appendTestSuffix(sharedObjectKeyBase + language.getLanguageName()), 
            crossLanguageObjects, 
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
    }
}
