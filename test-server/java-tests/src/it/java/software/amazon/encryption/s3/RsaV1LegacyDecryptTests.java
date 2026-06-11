/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.stream.Stream;

import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.GetObjectInput;
import software.amazon.encryption.s3.model.GetObjectOutput;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

/**
 * Verifies that V1 RSA-encrypted objects can be
 * successfully decrypted by all RSA-capable runtimes with legacy wrapping enabled.
 *
 * Encrypt: Java V1 client (RSA PKCS#1v1.5 wrap + AES-CBC content encryption)
 * Decrypt: Each RSA-capable runtime × commitment policy matrix
 */
public class RsaV1LegacyDecryptTests {

    private static KeyPair rsaKeyPair;
    private static String v1ObjectKey;
    private static final String INPUT = "test-data-for-rsa-v1-legacy-decrypt";

    @BeforeAll
    static void setup() throws Exception {
        validateServersRunning();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        rsaKeyPair = keyPairGen.generateKeyPair();

        // Encrypt with Java V1 client: RSA PKCS#1v1.5 key wrap + AES-CBC content
        v1ObjectKey = appendTestSuffix("rsa-v1-legacy-decrypt");
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(new CryptoConfiguration(CryptoMode.EncryptionOnly)
                        .withStorageMode(CryptoStorageMode.ObjectMetadata))
                .withEncryptionMaterials(new StaticEncryptionMaterialsProvider(
                        new EncryptionMaterials(rsaKeyPair)))
                .build();

        v1Client.putObject(BUCKET, v1ObjectKey, INPUT);
    }

    static Stream<Arguments> rsaRuntimeAndPolicyMatrix() {
        List<Object[]> allConfigs = List.of(
                new Object[]{"forbid-encrypt-allow-decrypt-policy",
                        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
                        EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF},
                new Object[]{"require-encrypt-allow-decrypt-policy",
                        CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                        EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY}
        );

        List<Object[]> transitionConfigs = allConfigs.subList(0, 1);

        // For each RSA-capable runtime, pair it with the applicable config set.
        // Transition versions only support FORBID_ENCRYPT_ALLOW_DECRYPT (no key commitment),
        // so they get a single config. Improved versions get all three policies.
        return clientsRawRsaForTest().flatMap(langArg -> {
            LanguageServerTarget lang = (LanguageServerTarget) langArg.get()[0];
            var configs = TRANSITION_VERSIONS.contains(lang.getLanguageName())
                    ? transitionConfigs : allConfigs;
            return configs.stream().map(cfg -> Arguments.of(lang, cfg[0], cfg[1], cfg[2]));
        });
    }

    @ParameterizedTest(name = "Encrypt: Java-V1-RSA, Decrypt: {0} / {1}")
    @MethodSource("rsaRuntimeAndPolicyMatrix")
    void canDecryptV1RsaObjectWithLegacyEnabled(LanguageServerTarget language, String configName,
                                                 CommitmentPolicy policy, EncryptionAlgorithm algo) {
        S3ECTestServerClient client = testServerClientFor(language);

        KeyMaterial rsaKeyMaterial = KeyMaterial.builder()
                .rsaKey(ByteBuffer.wrap(rsaKeyPair.getPrivate().getEncoded()))
                .build();

        String clientId = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(rsaKeyMaterial)
                        .commitmentPolicy(policy)
                        .encryptionAlgorithm(algo)
                        .enableLegacyUnauthenticatedModes(true)
                        .enableLegacyWrappingAlgorithms(true)
                        .build())
                .build()).getClientId();

        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(clientId)
                .bucket(BUCKET)
                .key(v1ObjectKey)
                .build());

        assertEquals(INPUT, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    @ParameterizedTest(name = "Encrypt: Java-V1-RSA, Decrypt: {0} / {1}")
    @MethodSource("rsaRuntimeAndPolicyMatrix")
    void cannotDecryptV1RsaObjectWithLegacyDisabled(LanguageServerTarget language, String configName,
                                                 CommitmentPolicy policy, EncryptionAlgorithm algo) {
        S3ECTestServerClient client = testServerClientFor(language);

        KeyMaterial rsaKeyMaterial = KeyMaterial.builder()
                .rsaKey(ByteBuffer.wrap(rsaKeyPair.getPrivate().getEncoded()))
                .build();

        String clientId = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(rsaKeyMaterial)
                        .commitmentPolicy(policy)
                        .encryptionAlgorithm(algo)
                        .enableLegacyUnauthenticatedModes(true)
                        .enableLegacyWrappingAlgorithms(false)
                        .build())
                .build()).getClientId();

        assertThrows(Exception.class, () ->
            client.getObject(GetObjectInput.builder()
                .clientID(clientId)
                .bucket(BUCKET)
                .key(v1ObjectKey)
                .build())
        );
    }
}
