/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentest4j.TestAbortedException;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.TestUtils.LanguageServerTarget;
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
                assertTrue(e.getMessage().contains("Value of encryption context from envelope does not match the provided encryption context"), "Actual error: " + e.getMessage());
            } else {
                assertTrue(e.getMessage().contains("Provided encryption context does not match information retrieved from S3"), "Actual error: " + e.getMessage());
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
                assertTrue(e.getMessage().contains("Value of encryption context from envelope does not match the provided encryption context"), "Actual error: " + e.getMessage());
            } else {
                assertTrue(e.getMessage().contains("Provided encryption context does not match information retrieved from S3"), "Actual error: " + e.getMessage());
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
            if (language.getLanguageName().equals(NET_V3_CURRENT) || language.getLanguageName().equals(NET_V2_CURRENT) || language.getLanguageName().equals(NET_V2_TRANSITION) || language.getLanguageName().equals(NET_V3_TRANSITION) || language.getLanguageName().equals(NET_V4)
            || language.getLanguageName().equals(CPP_V2_CURRENT) || language.getLanguageName().equals(CPP_V2_TRANSITION) || language.getLanguageName().equals(CPP_V3)) {
              assertTrue(e.getMessage().contains(
                "The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration"
              ), "Actual error:" + e.getMessage());
            } else if (language.getLanguageName().equals(RUBY_V3) || language.getLanguageName().equals(RUBY_V2_CURRENT) || language.getLanguageName().equals(RUBY_V2_TRANSITION)) {
                assertTrue(e.getMessage().contains(
                  "The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration security_profile = :v2. Retry with :v2_and_legacy or re-encrypt the object."
                ), "Actual error:" + e.getMessage());
            } else if (language.getLanguageName().equals(PHP_V3)) {
                assertTrue(e.getMessage().contains("The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration @SecurityProfile=V3. Retry with V3_AND_LEGACY enabled or reencrypt the object."), "Actual error: " + e.getMessage());
            } else {
                assertTrue(e.getMessage().contains("Enable legacy wrapping algorithms to use legacy key wrapping algorithm: kms"), "Actual error: " + e.getMessage());
            }
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#crossLanguageClients")
    public void rsaRoundTrip(LanguageServerTarget encLang, LanguageServerTarget decLang) throws Exception {
        if (!RAW_SUPPORTED.contains(encLang.getLanguageName())) {
            throw new TestAbortedException("not encrypting raw keyrings with: " + encLang.getLanguageName());
        }
        if (!RAW_SUPPORTED.contains(decLang.getLanguageName())) {
            throw new TestAbortedException("not decrypting raw keyrings with: " + decLang.getLanguageName());
        }
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        final String objectKey = appendTestSuffix(String.format("rsa-write-%s-read-%s", encLang.getLanguageName(), decLang.getLanguageName()));
        final String input = "simple-test-input-rsa";
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair RSA_KEY_PAIR_1 = keyPairGen.generateKeyPair();

        KeyMaterial rsaKeyOne = KeyMaterial.builder()
          .rsaKey(ByteBuffer.wrap(RSA_KEY_PAIR_1.getPrivate().getEncoded()))
          .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            // TODO: use this for now to satisfy current. think about long term soln for this
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .keyMaterial(rsaKeyOne).build())
          .build());
        String encS3ECId = encClientOutput.getClientId();
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .keyMaterial(rsaKeyOne).build())
          .build());
        String decS3ECId = decClientOutput.getClientId();
        encClient.putObject(PutObjectInput.builder()
          .clientID(encS3ECId)
          .key(objectKey)
          .bucket(BUCKET)
          .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
          .build());
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
          .clientID(decS3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .build());
        assertEquals(input, new String(output.getBody().array()));
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
    public void instructionFileWriteAndRead(LanguageServerTarget encLang, LanguageServerTarget decLang) throws Exception {
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
        // We skip PHP-V2-Current because it writes an instruction file that other languages may not read.
        if (encLang.getLanguageName().equals("PHP-V2-Current")) {
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

        // At high concurrency, this test tends to get:
        // BadDigest Message: The CRC64NVME you specified did not match the calculated checksum.
        // I think this is a read after write issue.
        // A better fix, would be to break this tests suite up into encrypt/decrypt
        // rather than having a test for many pairs and doing encrypt/decrypt on each pair
        Thread.sleep(100);

        assertFalse(ptInstFile.asUtf8String().isEmpty());
        // Read should be enabled by default
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
          .clientID(decS3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#crossLanguageClients")
    public void instructionFileWriteAndReadWithRSA(LanguageServerTarget encLang, LanguageServerTarget decLang) throws Exception {
        // Early validation
        if (!RAW_SUPPORTED.contains(encLang.getLanguageName())) {
            throw new TestAbortedException("not encrypting raw keyring with: " + encLang.getLanguageName());
        }
        if (!RAW_SUPPORTED.contains(decLang.getLanguageName())) {
            throw new TestAbortedException("not decrypting raw keyring with: " + decLang.getLanguageName());
        }

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyMaterial rsaKeyMaterial = KeyMaterial.builder()
                .rsaKey(ByteBuffer.wrap(keyPairGen.generateKeyPair().getPrivate().getEncoded()))
                .build();

        S3ECConfig config = S3ECConfig.builder()
                .instructionFileConfig(InstructionFileConfig.builder()
                        .enableInstructionFilePutObject(true)
                        .build())
                .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .keyMaterial(rsaKeyMaterial)
                .build();

        // Create clients
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        S3ECTestServerClient decClient = testServerClientFor(decLang);

        String encS3ECId = encClient.createClient(CreateClientInput.builder().config(config).build()).getClientId();
        String decS3ECId = decClient.createClient(CreateClientInput.builder().config(config).build()).getClientId();

        final String objectKey = appendTestSuffix(String.format("rsa-insfile-write-%s-read-%s",
                encLang.getLanguageName(), decLang.getLanguageName()));
        final String input = "simple-test-input-rsa";

        // Encrypt
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
        // assertTrue(ptInstFile.response().metadata().containsKey("x-amz-crypto-instr-file"));
        assertFalse(ptInstFile.asUtf8String().isEmpty());
        // Read should be enabled by default
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }
}
