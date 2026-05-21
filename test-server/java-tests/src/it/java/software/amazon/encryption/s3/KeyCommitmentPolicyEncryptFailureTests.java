/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static software.amazon.encryption.s3.TestUtils.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CommitmentPolicy;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.S3ECConfig;

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
 * with the commitment policy is rejected by the S3EC — either at client creation
 * or at PutObject time.
 *
 * Currently scoped to Python V4 only. Other languages can be enabled by
 * switching the MethodSource to a broader provider (e.g. improvedClientsForTest).
 */
@DisplayName("Key Commitment Policy — Encrypt Failures")
public class KeyCommitmentPolicyEncryptFailureTests {

    private static final KeyMaterial kmsKeyArn = KeyMaterial.builder()
        .kmsKeyId(TestUtils.KMS_KEY_ARN)
        .build();

    @ParameterizedTest(name = "{0}: REQUIRE_ENCRYPT_ALLOW_DECRYPT with non-committing GCM MUST fail to encrypt")
    @MethodSource("software.amazon.encryption.s3.TestUtils#pythonV4ClientForTest")
    void require_encrypt_allow_decrypt_with_non_committing_gcm_must_fail(
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
    @MethodSource("software.amazon.encryption.s3.TestUtils#pythonV4ClientForTest")
    void require_encrypt_require_decrypt_with_non_committing_gcm_must_fail(
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
    @MethodSource("software.amazon.encryption.s3.TestUtils#pythonV4ClientForTest")
    void forbid_encrypt_allow_decrypt_with_committing_gcm_must_fail(
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
}
