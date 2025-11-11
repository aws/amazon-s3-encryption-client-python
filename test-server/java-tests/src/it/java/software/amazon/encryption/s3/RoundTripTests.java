/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.FunWithGcm.add;
import static software.amazon.encryption.s3.FunWithGcm.authKey;
import static software.amazon.encryption.s3.FunWithGcm.gctr;
import static software.amazon.encryption.s3.FunWithGcm.ghash;
import static software.amazon.encryption.s3.FunWithGcm.inverse;
import static software.amazon.encryption.s3.FunWithGcm.lengthBlock;
import static software.amazon.encryption.s3.FunWithGcm.mul;
import static software.amazon.encryption.s3.FunWithGcm.tagBlock;
import static software.amazon.encryption.s3.S3EncryptionClient.withCustomInstructionFileSuffix;
import static software.amazon.encryption.s3.TestUtils.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentest4j.TestAbortedException;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.GetObjectInput;
import software.amazon.encryption.s3.model.GetObjectOutput;
import software.amazon.encryption.s3.model.InstructionFileConfig;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.PutObjectInput;
import software.amazon.encryption.s3.model.S3ECConfig;
import software.amazon.encryption.s3.model.S3EncryptionClientError;

import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public class RoundTripTests {

    @BeforeAll
    public static void setup() {
        validateServersRunning();
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#crossLanguageClients")
    public void crossLanguageTestKms(LanguageServerTarget encLang, LanguageServerTarget decLang) {
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = appendTestSuffix("cross-lang-test-key-" + encLang);
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig
            .builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build()
          )
          .build());
        String encS3ECId = encClientOutput.getClientId();
        encClient.putObject(PutObjectInput.builder()
          .clientID(encS3ECId)
          .key(objectKey)
          .bucket(BUCKET)
          .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
          .build());
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build()
          )
          .build());
        String decS3ECId = decClientOutput.getClientId();
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
          .clientID(decS3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .build());

        if (!input.equals(StandardCharsets.UTF_8.decode(output.getBody()).toString())) {
            fail(String.format("Encryption in %s failed to decrpyt in %s!", encLang, decLang));
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#crossLanguageClients")
    public void crossLanguageTestKmsWithEncCtx(LanguageServerTarget encLang, LanguageServerTarget decLang) {
        if (ENCRYPTION_CONTEXT_ON_ENCRYPT_UNSUPPORTED.contains(encLang.getLanguageName())) {
            return;
        }
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = appendTestSuffix("cross-lang-test-key-kms-ec-" + encLang);
        final String input = "simple-test-input";
        final Map<String, String> encCtx = new HashMap<>();
        encCtx.put("user-defined-enc-ctx-key", "user-defined-enc-ctx-value");
        encCtx.put("user-defined-enc-ctx-key-2", "user-defined-enc-ctx-value-2");
        final List<String> mdAsList = metadataMapToList(encCtx);
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build()
          )
          .build());
        String encS3ECId = encClientOutput.getClientId();

        encClient.putObject(PutObjectInput.builder()
          .clientID(encS3ECId)
          .key(objectKey)
          .bucket(BUCKET)
          .metadata(mdAsList)
          .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
          .build());
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build()
          )
          .build());
        String decS3ECId = decClientOutput.getClientId();
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
          .clientID(decS3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .metadata(mdAsList)
          .build());

        if (!input.equals(StandardCharsets.UTF_8.decode(output.getBody()).toString())) {
            fail(String.format("Encryption in %s failed to decrpyt in %s!", encLang, decLang));
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#crossLanguageClients")
    public void crossLanguageTestKmsWithSubsetEncCtxFails(LanguageServerTarget encLang, LanguageServerTarget decLang) {
        if (ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED.contains(decLang.getLanguageName())) {
            return;
        }
        if (ENCRYPTION_CONTEXT_ON_ENCRYPT_UNSUPPORTED.contains(encLang.getLanguageName())) {
            return;
        }
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = appendTestSuffix("cross-lang-test-key-kms-ec-subset-fails" + encLang);
        final String input = "simple-test-input";
        final Map<String, String> encCtx = new HashMap<>();
        encCtx.put("user-defined-enc-ctx-key", "user-defined-enc-ctx-value");
        encCtx.put("user-defined-enc-ctx-key-2", "user-defined-enc-ctx-value-2");
        final List<String> mdAsList = metadataMapToList(encCtx);
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                        .build())
                .build());
        String encS3ECId = encClientOutput.getClientId();

        encClient.putObject(PutObjectInput.builder()
                .clientID(encS3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .metadata(mdAsList)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                  .keyMaterial(kmsKeyArn)
                  .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                  .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                  .build()
                )
                .build());
        String decS3ECId = decClientOutput.getClientId();
        try {
            decClient.getObject(GetObjectInput.builder()
                    .clientID(decS3ECId)
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected exception!");
        } catch (S3EncryptionClientError e) {
            if (decLang.getLanguageName().equals(RUBY_V3) || decLang.getLanguageName().equals(RUBY_V2_CURRENT) || decLang.getLanguageName().equals(RUBY_V2_TRANSITION)) {
                assertTrue(e.getMessage().contains("Value of encryption context from envelope does not match the provided encryption context"));
            } else {
                assertTrue(e.getMessage().contains("Provided encryption context does not match information retrieved from S3"));
            }
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#crossLanguageClients")
    public void crossLanguageTestKmsWithIncorrectEncCtxFails(LanguageServerTarget encLang, LanguageServerTarget decLang) {
        if (ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED.contains(decLang.getLanguageName())) {
            return;
        }
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = appendTestSuffix("cross-lang-test-key-kms-ec-incorrect-fails" + encLang);
        final String input = "simple-test-input";
        final Map<String, String> encCtx = new HashMap<>();
        encCtx.put("user-defined-enc-ctx-key", "user-defined-enc-ctx-value");
        encCtx.put("user-defined-enc-ctx-key-2", "user-defined-enc-ctx-value-2");
        final List<String> mdAsList = metadataMapToList(encCtx);
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build()
          )
          .build());
        String encS3ECId = encClientOutput.getClientId();

        encClient.putObject(PutObjectInput.builder()
          .clientID(encS3ECId)
          .key(objectKey)
          .bucket(BUCKET)
          .metadata(mdAsList)
          .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
          .build());
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build()
          )
          .build());
        String decS3ECId = decClientOutput.getClientId();

        final Map<String, String> incorrectEncCtx = new HashMap<>();
        incorrectEncCtx.put("this-is-wrong-ec-key", "bad-value");
        var incorrectMdAsList = metadataMapToList(incorrectEncCtx);
        try {
            decClient.getObject(GetObjectInput.builder()
              .clientID(decS3ECId)
              .bucket(BUCKET)
              .key(objectKey)
              .metadata(incorrectMdAsList)
              .build());
            fail("Expected exception!");
        } catch (S3EncryptionClientError e) {
            if (decLang.getLanguageName().equals(RUBY_V3) || decLang.getLanguageName().equals(RUBY_V2_CURRENT) || decLang.getLanguageName().equals(RUBY_V2_TRANSITION)) {
              assertTrue(e.getMessage().contains("Value of encryption context from envelope does not match the provided encryption context"));
            } else {
              assertTrue(e.getMessage().contains("Provided encryption context does not match information retrieved from S3"));
            }
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: Java, Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
    public void kmsV1Legacy(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = testServerClientFor(language);
        final String objectKey = appendTestSuffix("test-key-kms-v1-" + language);
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .enableLegacyWrappingAlgorithms(true)
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build())
          .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client
        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
          new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
            .withStorageMode(CryptoStorageMode.ObjectMetadata)
            .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
          .withCryptoConfiguration(v1Config)
          .withEncryptionMaterials(materialsProvider)
          .build();

        v1Client.putObject(BUCKET, objectKey, input);

        GetObjectOutput output = client.getObject(GetObjectInput.builder()
          .clientID(s3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: Java, Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
    public void kmsV1LegacyWithEncCtx(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = testServerClientFor(language);
        final String objectKey = appendTestSuffix("test-key-kms-v1-with-enc-ctx-" + language);
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .enableLegacyWrappingAlgorithms(true)
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build())
          .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client
        // V1 Client
        final String ecKey = "user-metadata-key";
        final String ecValue = "user-metadata-value-v1";
        KMSEncryptionMaterials kmsMaterials = new KMSEncryptionMaterials(KMS_KEY_ARN);
        kmsMaterials.addDescription(ecKey, ecValue);
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(kmsMaterials);

        CryptoConfiguration v1Config =
          new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
            .withStorageMode(CryptoStorageMode.ObjectMetadata)
            .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
          .withCryptoConfiguration(v1Config)
          .withEncryptionMaterials(materialsProvider)
          .build();

        v1Client.putObject(BUCKET, objectKey, input);

        final Map<String, String> encCtx = new HashMap<>();
        encCtx.put(ecKey, ecValue);
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
          .clientID(s3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .metadata(metadataMapToList(encCtx))
          .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: Java, Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
    public void kmsV1LegacyFailsWhenLegacyDisabled(TestUtils.LanguageServerTarget language) {
        S3ECTestServerClient client = testServerClientFor(language);
        final String objectKey = appendTestSuffix("test-key-kms-v1-fails-disabled" + language);
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .enableLegacyWrappingAlgorithms(false)
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build())
          .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client
        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
          new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
            .withStorageMode(CryptoStorageMode.ObjectMetadata)
            .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
          .withCryptoConfiguration(v1Config)
          .withEncryptionMaterials(materialsProvider)
          .build();

        v1Client.putObject(BUCKET, objectKey, input);

        try {
            client.getObject(GetObjectInput.builder()
              .clientID(s3ECId)
              .bucket(BUCKET)
              .key(objectKey)
              .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            if (language.getLanguageName().equals(NET_V3_CURRENT) || language.getLanguageName().equals(NET_V2_CURRENT) || language.getLanguageName().equals(NET_V3_TRANSITION) 
            || language.getLanguageName().equals(CPP_V2_CURRENT) || language.getLanguageName().equals(CPP_V2_TRANSITION) || language.getLanguageName().equals(CPP_V3)) {
              assertTrue(e.getMessage().contains(
                "The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration"
              ));
            } else if (language.getLanguageName().equals(RUBY_V3) || language.getLanguageName().equals(RUBY_V2_CURRENT) || language.getLanguageName().equals(RUBY_V2_TRANSITION)) {
              assertTrue(e.getMessage().contains(
                "The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration security_profile = :v2. Retry with :v2_and_legacy or re-encrypt the object."
                ), "Actual error:" + e.getMessage());
            } else {
              assertTrue(e.getMessage().contains("Enable legacy wrapping algorithms to use legacy key wrapping algorithm: kms"));
            }
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: Java, Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
    public void instructionFileReadV2Format(TestUtils.LanguageServerTarget language) {
        if (KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(language.getLanguageName())) {
            throw new TestAbortedException(String.format("%s does not support KMS instruction files", language.getLanguageName()));
        }
        if (INSTRUCTION_FILE_GET_UNSUPPORTED.contains(language.getLanguageName())) {
            throw new TestAbortedException(String.format("%s does not support instruction file Gets", language.getLanguageName()));
        }
        S3ECTestServerClient client = testServerClientFor(language);
        final String objectKey = appendTestSuffix("read-instruction-file-v2-" + language);
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .enableLegacyWrappingAlgorithms(true)
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build())
          .build());
        String s3ECId = output1.getClientId();

        // Write with instruction file using V2 client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);
        CryptoConfigurationV2 cryptoConfigurationV2 = new CryptoConfigurationV2();
        cryptoConfigurationV2.setStorageMode(CryptoStorageMode.InstructionFile);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
          .withEncryptionMaterialsProvider(materialsProvider)
          .withCryptoConfiguration(cryptoConfigurationV2)
          .build();
        v2Client.putObject(BUCKET, objectKey, input);

        // Read should be enabled by default
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
          .clientID(s3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#crossLanguageClients")
    public void instructionFileWriteAndRead(LanguageServerTarget encLang, LanguageServerTarget decLang) {
        if (INSTRUCTION_FILE_PUT_UNSUPPORTED.contains(encLang.getLanguageName())) {
            throw new TestAbortedException("not testing " + encLang.getLanguageName());
        }
        if (INSTRUCTION_FILE_GET_UNSUPPORTED.contains(decLang.getLanguageName())) {
            throw new TestAbortedException("not testing " + encLang.getLanguageName());
        }
        if (KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(encLang.getLanguageName())) {
            throw new TestAbortedException("not testing " + encLang.getLanguageName());
        }
        if (KMS_INSTRUCTION_FILE_UNSUPPORTED.contains(decLang.getLanguageName())) {
            throw new TestAbortedException("not testing " + encLang.getLanguageName());
        }
        if (INSTRUCTION_FILE_ROUNDTRIP_TEMP_UNSUPPORTED.contains(encLang.getLanguageName())) {
            throw new TestAbortedException("not testing " + encLang.getLanguageName());
        }
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        final String objectKey = appendTestSuffix(String.format("write-%s-read-%s-instruction-file", encLang.getLanguageName(), decLang.getLanguageName()));
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput encOutput = encClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .instructionFileConfig(InstructionFileConfig.builder()
              .enableInstructionFilePutObject(true)
              .build())
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build())
          .build());
        String encS3ECId = encOutput.getClientId();
        CreateClientOutput decOutput = decClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build())
          .build());
        String decS3ECId = decOutput.getClientId();

        // Write with instruction file
        encClient.putObject(PutObjectInput.builder()
          .clientID(encS3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
          .build());

        // Assert using Java plaintext client that an instruction file exists
        ResponseBytes<GetObjectResponse> ptInstFile;
        try (S3Client ptS3Client = S3Client.create()) {
            ptInstFile = ptS3Client.getObjectAsBytes(builder -> builder
              .bucket(BUCKET)
              .key(objectKey + ".instruction")
              .build());
        }
        // Check for inst file key
        if (!encLang.getLanguageName().startsWith("Ruby") && !encLang.getLanguageName().startsWith("PHP")) {
            // Ruby and PHP do not include it :(
            assertTrue(ptInstFile.response().metadata().containsKey("x-amz-crypto-instr-file"));
        }
        assertFalse(ptInstFile.asUtf8String().isEmpty());

        // Read should be enabled by default
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
          .clientID(decS3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: Java, Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
    public void executeKeyCommitAttackCustomSuffixLocal(TestUtils.LanguageServerTarget language) throws Exception {
        // To execute this attack we need:
        // - A forged (content) ciphertext (+ IV(s))
        // - Two data keys
        // - Two wrapping keys (RSA)
        // Then:
        // - Upload the object for the content ciphertext, no parameters
        // - Upload one instruction file with Key1 (default suffix)
        // - Upload another instruction file with Key2 (custom suffix)
        // - Decrypt with S3EC

        // Generate RSA key pairs
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair RSA_KEY_PAIR_1 = keyPairGen.generateKeyPair();
        KeyPair RSA_KEY_PAIR_2 = keyPairGen.generateKeyPair();

        S3ECTestServerClient client = testServerClientFor(language);
        final String objectKey = "key-commitment-attack-custom-suffix";
        byte[] message = "Hello, World!".getBytes(Charset.forName("UTF-8"));
        SecureRandom rand = new SecureRandom();
        byte[] key = new byte[32];
        rand.nextBytes(key);
        byte[] key2 = new byte[32];
        rand.nextBytes(key2);
        message[0] = 0x13;
        message[1] = 0x37;
        byte[] ciphertext;
        byte message1[] = new byte[16];
        message1[0] = 0x13;
        message1[1] = 0x37;
        byte iv[] = new byte[12];
        rand.nextBytes(iv);
        byte authKey1[] = authKey(key);
        byte authKey2[] = authKey(key2);
        byte tagBlock1[] = tagBlock(iv, key);
        byte tagBlock2[] = tagBlock(iv, key2);
        byte ciphertext1[] = gctr(message1, iv, key);
        byte lengthBlock[] = lengthBlock(0, 32);
        // tag(H, tb) = c1 * H^3 + c2 * H^2 + lb * H + tb
        // c1 * H1^3 + c2 * H1^2 + lb * H1 + tb1 = c1 * H2^3 + c2 * H2^2 + lb * H2 + tb2
        // c2 * (H1^2 + H2^2) = c1 * (H1^3 + H2^3) + lb * (H1 + H2) + tb1 + tb2
        byte rhs[] = add(tagBlock1, tagBlock2);
        rhs = add(rhs, mul(lengthBlock, add(authKey1, authKey2)));
        byte authKey1sq[] = mul(authKey1, authKey1);
        byte authKey2sq[] = mul(authKey2, authKey2);
        byte lhs[] = add(authKey1sq, authKey2sq);
        byte authKey1cb[] = mul(authKey1sq, authKey1);
        byte authKey2cb[] = mul(authKey2sq, authKey2);
        rhs = add(rhs, mul(ciphertext1, add(authKey1cb, authKey2cb)));
        byte[] ciphertext2 = mul(inverse(lhs), rhs);
        ByteBuffer attackCiphertext = ByteBuffer.allocate(32);
        attackCiphertext.put(ciphertext1);
        attackCiphertext.put(ciphertext2);
        byte[] ghash = ghash(new byte[0], attackCiphertext.array(), authKey1);
        ByteBuffer attack = ByteBuffer.allocate( 32 + 16);
        //        attack.put(iv);
        attack.put(ciphertext1);
        attack.put(ciphertext2);
        attack.put(add(tagBlock1, ghash));
        ciphertext = attack.array();

        //        aliceOutput(ciphertext, key2, key);

        // Encrypt the data keys
        byte[] edk1 = encryptDataKeyRsa(rand, RSA_KEY_PAIR_1.getPublic(), key);
        //        byte[] edk2 = encryptDataKeyRsa(rand, RSA_KEY_PAIR_2.getPublic(), key2);
        byte[] edk2 = encryptDataKeyRsa(rand, RSA_KEY_PAIR_2.getPublic(), key2);

        // Make a fake instruction file
        String fakeInstFileKey1 = fakeInstFile(edk1, iv);
        String fakeInstFileKey2 = fakeInstFile(edk2, iv);

        // Put the three evil objects with default S3 client
        AmazonS3 s3 = AmazonS3ClientBuilder.defaultClient();
        InputStream ct = new ByteArrayInputStream(ciphertext);
        ObjectMetadata md = new ObjectMetadata();
        PutObjectRequest obj = new PutObjectRequest(BUCKET, objectKey, ct, md);
        s3.putObject(obj);

        s3.putObject(BUCKET, objectKey + ".instruction", fakeInstFileKey1);
        s3.putObject(BUCKET, objectKey + ".instruction.custom", fakeInstFileKey2);

        // Attempt to decrypt
        S3Client s3Ec = S3EncryptionClient.builder()
          .rsaKeyPair(RSA_KEY_PAIR_1)
          .build();

        ResponseBytes<GetObjectResponse> responseBytes = s3Ec.getObjectAsBytes(builder -> builder
          .bucket(BUCKET)
          .key(objectKey).build());
        System.out.println("Response for Key 1: " + Base64.getEncoder().encodeToString(responseBytes.asByteArray()));

        // Attempt to decrypt
        S3Client s3Ec2 = S3EncryptionClient.builder()
          .rsaKeyPair(RSA_KEY_PAIR_2)
          .build();

        ResponseBytes<GetObjectResponse> responseBytes2 = s3Ec2.getObjectAsBytes(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .overrideConfiguration(withCustomInstructionFileSuffix(".instruction.custom")).build());
        System.out.println("Response for Key 2: " + Base64.getEncoder().encodeToString(responseBytes2.asByteArray()));
    }

    public byte[] encryptDataKeyRsa(SecureRandom secureRandom, PublicKey pubKey, byte[] pdk) throws GeneralSecurityException {
        final String DIGEST_NAME = "SHA-1";
        final String MGF_NAME = "MGF1";

        // Java 8 doesn't support static class fields in inner classes
        MGF1ParameterSpec MGF_PARAMETER_SPEC = new MGF1ParameterSpec(DIGEST_NAME);
        OAEPParameterSpec OAEP_PARAMETER_SPEC =
          new OAEPParameterSpec(DIGEST_NAME, MGF_NAME, MGF_PARAMETER_SPEC, PSource.PSpecified.DEFAULT);
        final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.WRAP_MODE, pubKey, OAEP_PARAMETER_SPEC, secureRandom);

        // Create a pseudo-data key with the content encryption appended to the data key
        byte[] dataCipherName = "AES/GCM/NoPadding".getBytes(StandardCharsets.UTF_8);
        byte[] pseudoDataKey = new byte[1 + pdk.length + dataCipherName.length];

        pseudoDataKey[0] = (byte) pdk.length;
        System.arraycopy(pdk, 0, pseudoDataKey, 1, pdk.length);
        System.arraycopy(dataCipherName, 0, pseudoDataKey, 1 + pdk.length, dataCipherName.length);

        return cipher.wrap(new SecretKeySpec(pseudoDataKey, "AES"));
    }

    private String fakeInstFile(byte[] encDataKey, byte[] iv) {
        String ivStr = Base64.getEncoder().encodeToString(iv);
        String edkStr = Base64.getEncoder().encodeToString(encDataKey);

        String preIv = "{\"x-amz-tag-len\":\"128\",\"x-amz-iv\":\"";
        String postIv = "\",\"x-amz-wrap-alg\":\"RSA-OAEP-SHA1\",\"x-amz-key-v2\":\"";
        String postKey = "\",\"x-amz-cek-alg\":\"AES/GCM/NoPadding\",\"x-amz-matdesc\":\"{}\"}";
        return preIv + ivStr + postIv + edkStr + postKey;
    }

}
