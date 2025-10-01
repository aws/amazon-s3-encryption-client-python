/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
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
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn).build())
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
            .keyMaterial(kmsKeyArn).build())
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
            .keyMaterial(kmsKeyArn).build())
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
            .keyMaterial(kmsKeyArn).build())
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
                        .keyMaterial(kmsKeyArn).build())
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
                        .keyMaterial(kmsKeyArn).build())
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
            if (decLang.getLanguageName().equals(RUBY_V3) || decLang.getLanguageName().equals(RUBY_V2_CURRENT)) {
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
            .keyMaterial(kmsKeyArn).build())
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
            .keyMaterial(kmsKeyArn).build())
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
            if (decLang.getLanguageName().equals(RUBY_V3) || decLang.getLanguageName().equals(RUBY_V2_CURRENT)) {
              assertTrue(e.getMessage().contains("Value of encryption context from envelope does not match the provided encryption context"));
            } else {
              assertTrue(e.getMessage().contains("Provided encryption context does not match information retrieved from S3"));
            }
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: Java, Decrypt: {0}")
    @MethodSource("software.amazon.encryption.s3.TestUtils#clientsForTest")
    public void kmsV1Legacy(String language) {
        S3ECTestServerClient client = testServerClientFor(getServerMap().get(language));
        final String objectKey = appendTestSuffix("test-key-kms-v1-" + language);
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .enableLegacyWrappingAlgorithms(true)
            .keyMaterial(kmsKeyArn)
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
    public void kmsV1LegacyWithEncCtx(String language) {
        S3ECTestServerClient client = testServerClientFor(getServerMap().get(language));
        final String objectKey = appendTestSuffix("test-key-kms-v1-with-enc-ctx-" + language);
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .enableLegacyWrappingAlgorithms(true)
            .keyMaterial(kmsKeyArn)
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
    public void kmsV1LegacyFailsWhenLegacyDisabled(String language) {
        S3ECTestServerClient client = testServerClientFor(getServerMap().get(language));
        final String objectKey = appendTestSuffix("test-key-kms-v1-fails-disabled" + language);
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .enableLegacyWrappingAlgorithms(false)
            .keyMaterial(kmsKeyArn)
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
            if (language.equals(NET_V3) || language.equals(NET_V2_CURRENT) 
            || language.equals(CPP_V2_CURRENT) || language.equals(CPP_V2_TRANSITION) || language.equals(CPP_V3)) {
              assertTrue(e.getMessage().contains(
                "The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration"
              ));
            } else if (language.equals(RUBY_V3) || language.equals(RUBY_V2_CURRENT)) {
              assertTrue(e.getMessage().contains("The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration security_profile = :v2. Retry with :v2_and_legacy or re-encrypt the object."));
            } else {
              assertTrue(e.getMessage().contains("Enable legacy wrapping algorithms to use legacy key wrapping algorithm: kms"));
            }
        }
    }
}
