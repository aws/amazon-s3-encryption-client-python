/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static software.amazon.encryption.s3.TestUtils.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
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

/**
 * Key Commitment Policy — Encryption Failure Tests
 *
 * Per the specification (key-commitment.md):
 *   "When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT,
 *    the S3EC MUST only encrypt using an algorithm suite which supports key commitment."
 *   "When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
 *    the S3EC MUST only encrypt using an algorithm suite which supports key commitment."
 *   "When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT,
 *    the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment."
 *
 * These tests verify that attempting to encrypt with an algorithm that conflicts
 * with the commitment policy is rejected by the S3EC.
 *
 * The "experimental" tests go further: when a server does NOT reject the
 * misconfiguration (i.e. the bug exists), they inspect the S3 object to
 * determine what algorithm was actually used and whether the ciphertext
 * can be decrypted. This helps characterize the severity of the bug
 * across different language implementations.
 */
@DisplayName("Key Commitment Policy — Encrypt Failures")
public class KeyCommitmentPolicyEncryptFailureTests {

    private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
        .kmsKeyId(TestUtils.KMS_KEY_ARN)
        .build();

    // =========================================================================
    // Strict tests — these MUST fail for a compliant implementation
    // =========================================================================

    @ParameterizedTest(name = "{0}: REQUIRE_ENCRYPT_ALLOW_DECRYPT with non-committing GCM MUST fail to encrypt")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_require_encrypt_allow_decrypt_with_non_committing_gcm_must_fail(
        TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        S3ECConfig config = S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build();

        TestUtils.Encrypt_fails(client, config,
            appendTestSuffix("test-kc-policy-fail-REAC-gcm-" + language.getLanguageName()));
    }

    @ParameterizedTest(name = "{0}: REQUIRE_ENCRYPT_REQUIRE_DECRYPT with non-committing GCM MUST fail to encrypt")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_require_encrypt_require_decrypt_with_non_committing_gcm_must_fail(
        TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        S3ECConfig config = S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .build();

        TestUtils.Encrypt_fails(client, config,
            appendTestSuffix("test-kc-policy-fail-RERD-gcm-" + language.getLanguageName()));
    }

    @ParameterizedTest(name = "{0}: FORBID_ENCRYPT_ALLOW_DECRYPT with committing GCM MUST fail to encrypt")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void improved_forbid_encrypt_allow_decrypt_with_committing_gcm_must_fail(
        TestUtils.LanguageServerTarget language
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        S3ECConfig config = S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .encryptionAlgorithm(EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
            .build();

        TestUtils.Encrypt_fails(client, config,
            appendTestSuffix("test-kc-policy-fail-FEAD-kc-gcm-" + language.getLanguageName()));
    }

    // =========================================================================
    // Experimental diagnostic tests
    //
    // These tests probe what actually happens when a server does NOT reject
    // the misconfigured commitment policy + algorithm combination.
    // They always pass (they are diagnostic), but print detailed findings:
    //   - Did client creation or PutObject fail? (correct behavior)
    //   - If not, what algorithm suite was actually written to S3?
    //   - Can the object be decrypted by a permissive client?
    //
    // This helps us understand whether a buggy server:
    //   (a) silently ignores the requested algorithm and uses the policy-implied one, or
    //   (b) actually encrypts with the wrong algorithm, violating the policy.
    // =========================================================================

    /**
     * Shared diagnostic logic for all three policy/algorithm mismatch scenarios.
     *
     * @param language          the server under test
     * @param policy            the commitment policy to configure
     * @param requestedAlgorithm the algorithm that conflicts with the policy
     * @param label             short label for log output
     */
    private void diagnoseEncryptWithMismatchedPolicy(
        TestUtils.LanguageServerTarget language,
        CommitmentPolicy policy,
        EncryptionAlgorithm requestedAlgorithm,
        String label
    ) {
        S3ECTestServerClient client = TestUtils.testServerClientFor(language);
        String objectKey = appendTestSuffix("test-kc-diag-" + label + "-" + language.getLanguageName());
        String plaintext = objectKey; // convention: plaintext == object key

        S3ECConfig config = S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(policy)
            .encryptionAlgorithm(requestedAlgorithm)
            .build();

        // Phase 1: attempt the misconfigured encrypt
        String s3ecId;
        try {
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(config)
                .build());
            s3ecId = clientOutput.getClientId();
        } catch (S3EncryptionClientError e) {
            System.out.println("[DIAG " + label + "] " + language.getLanguageName()
                + " — CORRECTLY rejected at CreateClient: " + e.getMessage());
            return; // correct behavior, nothing more to check
        }

        try {
            client.putObject(PutObjectInput.builder()
                .clientID(s3ecId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(plaintext.getBytes(StandardCharsets.UTF_8)))
                .build());
        } catch (S3EncryptionClientError e) {
            System.out.println("[DIAG " + label + "] " + language.getLanguageName()
                + " — CORRECTLY rejected at PutObject: " + e.getMessage());
            return; // correct behavior
        }

        // If we get here, the server did NOT reject the misconfiguration — this is the bug.
        System.out.println("[DIAG " + label + "] " + language.getLanguageName()
            + " — BUG: encryption succeeded when it should have been rejected."
            + " policy=" + policy + " requestedAlgorithm=" + requestedAlgorithm);

        // Phase 2: inspect what algorithm was actually written to S3
        EncryptionAlgorithm actualAlgorithm = null;
        try {
            actualAlgorithm = TestUtils.GetEncryptionAlgorithm(objectKey);
            System.out.println("[DIAG " + label + "] " + language.getLanguageName()
                + " — Actual algorithm on S3 object: " + actualAlgorithm);

            if (actualAlgorithm.equals(requestedAlgorithm)) {
                System.out.println("[DIAG " + label + "] " + language.getLanguageName()
                    + " — Server used the REQUESTED (wrong) algorithm. The policy was fully ignored.");
            } else {
                System.out.println("[DIAG " + label + "] " + language.getLanguageName()
                    + " — Server used a DIFFERENT algorithm than requested."
                    + " It may have derived the algorithm from the policy instead.");
            }
        } catch (Exception e) {
            System.out.println("[DIAG " + label + "] " + language.getLanguageName()
                + " — Could not determine actual algorithm: " + e.getMessage());
        }

        // Phase 3: attempt to decrypt with a permissive client
        // Use FORBID_ENCRYPT_ALLOW_DECRYPT which allows decrypting both committing and non-committing
        tryDecryptWithPermissiveClient(client, language, objectKey, plaintext, actualAlgorithm, label);
    }

    /**
     * Attempts to decrypt the object using a permissive client configuration
     * (FORBID_ENCRYPT_ALLOW_DECRYPT allows decrypting any algorithm).
     */
    private void tryDecryptWithPermissiveClient(
        S3ECTestServerClient client,
        TestUtils.LanguageServerTarget language,
        String objectKey,
        String expectedPlaintext,
        EncryptionAlgorithm actualAlgorithm,
        String label
    ) {
        // Build a permissive decrypt client — FORBID_ENCRYPT_ALLOW_DECRYPT allows
        // decrypting both committing and non-committing ciphertexts.
        // We also set the algorithm to match what was actually written, if known.
        S3ECConfig.Builder decryptConfigBuilder = S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT);

        if (actualAlgorithm != null) {
            decryptConfigBuilder.encryptionAlgorithm(actualAlgorithm);
        }

        try {
            CreateClientOutput decryptClientOutput = client.createClient(CreateClientInput.builder()
                .config(decryptConfigBuilder.build())
                .build());
            String decryptId = decryptClientOutput.getClientId();

            GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(decryptId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());

            String decryptedText = new String(output.getBody().array(), StandardCharsets.UTF_8);
            boolean plaintextMatches = expectedPlaintext.equals(decryptedText);

            System.out.println("[DIAG " + label + "] " + language.getLanguageName()
                + " — Decrypt with permissive client: SUCCESS"
                + " | plaintext matches: " + plaintextMatches);

            if (!plaintextMatches) {
                System.out.println("[DIAG " + label + "] " + language.getLanguageName()
                    + " — Expected plaintext length=" + expectedPlaintext.length()
                    + " got length=" + decryptedText.length());
            }
        } catch (S3EncryptionClientError e) {
            System.out.println("[DIAG " + label + "] " + language.getLanguageName()
                + " — Decrypt with permissive client: FAILED (S3EncryptionClientError): " + e.getMessage());
        } catch (Exception e) {
            System.out.println("[DIAG " + label + "] " + language.getLanguageName()
                + " — Decrypt with permissive client: FAILED (" + e.getClass().getSimpleName() + "): "
                + e.getMessage());
        }
    }

    // --- Experimental: REQUIRE_ENCRYPT_ALLOW_DECRYPT + non-committing GCM ---

    @ParameterizedTest(name = "{0}: [EXPERIMENTAL] REQUIRE_ENCRYPT_ALLOW_DECRYPT + non-committing GCM — diagnose behavior")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void experimental_require_encrypt_allow_decrypt_with_non_committing_gcm(
        TestUtils.LanguageServerTarget language
    ) {
        diagnoseEncryptWithMismatchedPolicy(
            language,
            CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            "REAC+GCM"
        );
    }

    // --- Experimental: REQUIRE_ENCRYPT_REQUIRE_DECRYPT + non-committing GCM ---

    @ParameterizedTest(name = "{0}: [EXPERIMENTAL] REQUIRE_ENCRYPT_REQUIRE_DECRYPT + non-committing GCM — diagnose behavior")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void experimental_require_encrypt_require_decrypt_with_non_committing_gcm(
        TestUtils.LanguageServerTarget language
    ) {
        diagnoseEncryptWithMismatchedPolicy(
            language,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            "RERD+GCM"
        );
    }

    // --- Experimental: FORBID_ENCRYPT_ALLOW_DECRYPT + committing GCM ---

    @ParameterizedTest(name = "{0}: [EXPERIMENTAL] FORBID_ENCRYPT_ALLOW_DECRYPT + committing GCM — diagnose behavior")
    @MethodSource("software.amazon.encryption.s3.TestUtils#improvedClientsForTest")
    void experimental_forbid_encrypt_allow_decrypt_with_committing_gcm(
        TestUtils.LanguageServerTarget language
    ) {
        diagnoseEncryptWithMismatchedPolicy(
            language,
            CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            "FEAD+KC_GCM"
        );
    }
}
