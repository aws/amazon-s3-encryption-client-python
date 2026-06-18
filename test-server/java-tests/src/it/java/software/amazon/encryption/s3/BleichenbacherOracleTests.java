/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.encryption.s3.TestUtils.LanguageServerTarget;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.GetObjectInput;
import software.amazon.encryption.s3.model.InstructionFileConfig;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.PutObjectInput;
import software.amazon.encryption.s3.model.S3ECConfig;
import software.amazon.encryption.s3.model.S3EncryptionClientError;

/**
 * Tests that verify the Bleichenbacher padding oracle does not exist across all
 * RSA-supporting runtimes and commitment policy configurations.
 */
public class BleichenbacherOracleTests {

    private static KeyPair rsaKeyPair;
    private static S3Client plaintextS3;
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final List<String> createdKeys = Collections.synchronizedList(new ArrayList<>());

    @BeforeAll
    public static void setup() throws Exception {
        validateServersRunning();
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        rsaKeyPair = keyPairGen.generateKeyPair();
        plaintextS3 = S3Client.create();
    }

    @AfterAll
    public static void cleanup() {
        for (String key : createdKeys) {
            try {
                plaintextS3.deleteObject(b -> b.bucket(BUCKET).key(key));
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Represents a client configuration to test against.
     */
    static class ConfigCase {
        final String name;
        final boolean legacyWrapping;
        final CommitmentPolicy policy;
        final EncryptionAlgorithm algo;

        ConfigCase(String name, boolean legacyWrapping, CommitmentPolicy policy, EncryptionAlgorithm algo) {
            this.name = name;
            this.legacyWrapping = legacyWrapping;
            this.policy = policy;
            this.algo = algo;
        }

        @Override
        public String toString() { return name; }
    }

    /**
     * Provides a matrix of (runtime x config) for parameterized tests.
     * Transition versions only support FORBID_ENCRYPT_ALLOW_DECRYPT with GCM (no key commitment),
     * so they get a reduced config set.
     */
    static Stream<Arguments> rsaRuntimeAndPolicyMatrix() {
        // All configs to test
        List<ConfigCase> allConfigs = List.of(
                new ConfigCase("GCM-forbid-encrypt-allow-decrypt", false, CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF),
                new ConfigCase("KC-GCM-require-encrypt-allow-decrypt", false, CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY),
                new ConfigCase("KC-GCM-require-encrypt-require-decrypt", false, CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
        );

        // Transition versions can only use FORBID_ENCRYPT_ALLOW_DECRYPT
        List<ConfigCase> transitionConfigs = allConfigs.stream()
                .filter(c -> c.policy == CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .toList();

        // For each RSA-capable runtime, pair it with the appropriate config set
        return clientsRawRsaForTest()
                .flatMap(langArg -> {
                    LanguageServerTarget lang = (LanguageServerTarget) langArg.get()[0];
                    // Transition versions get fewer configs; improved versions get all
                    List<ConfigCase> configs = TRANSITION_VERSIONS.contains(lang.getLanguageName())
                            ? transitionConfigs
                            : allConfigs;
                    return configs.stream().map(cfg -> Arguments.of(lang, cfg));
                });
    }

    /**
     * For each (runtime, commitmentPolicy) combination:
     * 1. Encrypt an object with RSA-OAEP
     * 2. Copy it with V1 metadata (downgrade x-amz-key-v2 → x-amz-key)
     * 3. Upload a second object with a known-valid PKCS#1v1.5 ciphertext in x-amz-key
     * 4. Attempt to decrypt both with legacy disabled
     * 5. Assert: the two produce the SAME error (proving the oracle is mitigated)
     */
    @ParameterizedTest(name = "{0} / {1}")
    @MethodSource("rsaRuntimeAndPolicyMatrix")
    public void oracleDistinguishableErrorsMetaData(LanguageServerTarget language, ConfigCase configCase) throws Exception {
        verifyNoOracle(language, configCase, "MetaData", null, this::uploadV1Object);
    }

    /**
     * Same as oracleDistinguishableErrorsMetaData but stores V1 metadata in an instruction file
     * instead of object metadata. Verifies the oracle mitigation applies equally to
     * the instruction file code path.
     */
    @ParameterizedTest(name = "InstructionFile: {0} / {1}")
    @MethodSource("rsaRuntimeAndPolicyMatrix")
    public void oracleDistinguishableErrorsInstructionFile(LanguageServerTarget language, ConfigCase configCase) throws Exception {
        if (INSTRUCTION_FILE_GET_UNSUPPORTED.contains(language.getLanguageName())) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, language.getLanguageName() + " does not support instruction file get");
        }
        verifyNoOracle(language, configCase, "InstructionFile",
                InstructionFileConfig.builder().enableInstructionFilePutObject(true).build(),
                this::uploadV1InstructionFileObject);
    }

    @FunctionalInterface
    private interface V1Uploader {
        void upload(String key, byte[] body, String wrappedKey, String iv, String matdesc) throws Exception;
    }

    private void verifyNoOracle(LanguageServerTarget language, ConfigCase configCase, String label, InstructionFileConfig instructionFileConfig, V1Uploader uploader) throws Exception {
        S3ECTestServerClient client = testServerClientFor(language);

        KeyMaterial rsaKeyMaterial = KeyMaterial.builder()
                .rsaKey(ByteBuffer.wrap(rsaKeyPair.getPrivate().getEncoded()))
                .build();

        S3ECConfig.Builder configBuilder = S3ECConfig.builder()
                .enableLegacyWrappingAlgorithms(configCase.legacyWrapping)
                .encryptionAlgorithm(configCase.algo)
                .commitmentPolicy(configCase.policy)
                .keyMaterial(rsaKeyMaterial);
        if (instructionFileConfig != null) {
            configBuilder.instructionFileConfig(instructionFileConfig);
        }
        S3ECConfig config = configBuilder.build();

        String clientId = client.createClient(CreateClientInput.builder().config(config).build()).getClientId();

        String suffix = language.getLanguageName() + "-" + configCase.name + "-" + label;

        // Encrypt with RSA-OAEP
        final String originalKey = appendTestSuffix("bleichenbacher-original-" + suffix);
        createdKeys.add(originalKey);
        client.putObject(PutObjectInput.builder()
                .clientID(clientId)
                .bucket(BUCKET)
                .key(originalKey)
                .body(ByteBuffer.wrap("secret".getBytes(StandardCharsets.UTF_8)))
                .build());

        // Use random bytes for the invalid PKCS#1 padding
        String wrappedKey = Base64.getEncoder().encodeToString(new byte[256]);
        String iv = Base64.getEncoder().encodeToString(new byte[16]);
        String matdesc = "{}";

        // Download raw encrypted body
        byte[] rawBody;
        try (ResponseInputStream<GetObjectResponse> s3Object = plaintextS3.getObject(b -> b.bucket(BUCKET).key(originalKey))) {
            rawBody = s3Object.readAllBytes();
        }

        // Upload with V1 wrapping with invalid PKCS#1 padding
        final String invalidPaddingKey = appendTestSuffix("bleichenbacher-invalid-" + suffix);
        createdKeys.add(invalidPaddingKey);
        uploader.upload(invalidPaddingKey, rawBody, wrappedKey, iv, matdesc);

        // Upload with V1 wrapping (known VALID PKCS#1v1.5 ciphertext)
        final String validPaddingKey = appendTestSuffix("bleichenbacher-valid-" + suffix);
        createdKeys.add(validPaddingKey);
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
        byte[] validPkcs1Ciphertext = cipher.doFinal(new byte[32]);
        String validPkcs1Base64 = Base64.getEncoder().encodeToString(validPkcs1Ciphertext);
        uploader.upload(validPaddingKey, rawBody, validPkcs1Base64, iv, matdesc);

        // Attempt decrypt of both — should get the same error
        String errorInvalid = getDecryptError(client, clientId, invalidPaddingKey);
        String errorValid = getDecryptError(client, clientId, validPaddingKey);

        System.out.printf("[BleichenbacherOracleTests][%s][%s][%s] Invalid padding error: %s%n", label, language.getLanguageName(), configCase.name, errorInvalid);
        System.out.printf("[BleichenbacherOracleTests][%s][%s][%s] Valid padding error:   %s%n", label, language.getLanguageName(), configCase.name, errorValid);

        assertNotEquals("NO_ERROR", errorInvalid,
                String.format("[%s][%s][%s] Expected decryption to fail for invalid padding object but it succeeded",
                        label, language.getLanguageName(), configCase.name));
        assertNotEquals("NO_ERROR", errorValid,
                String.format("[%s][%s][%s] Expected decryption to fail for valid padding object but it succeeded",
                        label, language.getLanguageName(), configCase.name));

        assertEquals(errorInvalid, errorValid,
                String.format("[%s][%s][%s] Errors differ for valid/invalid PKCS#1 padding — oracle still exists!",
                        label, language.getLanguageName(), configCase.name));
        System.out.printf("[BleichenbacherOracleTests][%s][%s][%s] PASSED — no oracle%n", label, language.getLanguageName(), configCase.name);
    }

    private void uploadV1Object(String key, byte[] body, String wrappedKey, String iv, String matdesc) {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-key", wrappedKey);
        metadata.put("x-amz-iv", iv);
        metadata.put("x-amz-matdesc", matdesc != null ? matdesc : "{}");

        plaintextS3.putObject(b -> b.bucket(BUCKET).key(key).metadata(metadata).contentLength((long) body.length),
                RequestBody.fromBytes(body));
    }

    private String getDecryptError(S3ECTestServerClient client, String clientId, String key) {
        try {
            client.getObject(GetObjectInput.builder()
                    .clientID(clientId)
                    .bucket(BUCKET)
                    .key(key)
                    .build());
            return "NO_ERROR";
        } catch (S3EncryptionClientError e) {
            return e.getMessage();
        } catch (Exception e) {
            return "UNEXPECTED: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    private void uploadV1InstructionFileObject(String key, byte[] body, String wrappedKey, String iv, String matdesc) throws Exception {
        // Upload body with NO encryption metadata in object metadata
        plaintextS3.putObject(b -> b.bucket(BUCKET).key(key).contentLength((long) body.length),
                RequestBody.fromBytes(body));

        // Upload .instruction file with V1 metadata as JSON
        Map<String, String> instructionMap = new HashMap<>();
        instructionMap.put("x-amz-key", wrappedKey);
        instructionMap.put("x-amz-iv", iv);
        instructionMap.put("x-amz-matdesc", matdesc != null ? matdesc : "{}");
        String instructionJson = MAPPER.writeValueAsString(instructionMap);
        plaintextS3.putObject(b -> b.bucket(BUCKET).key(key + ".instruction"),
                RequestBody.fromString(instructionJson));
        createdKeys.add(key + ".instruction");
    }
}
