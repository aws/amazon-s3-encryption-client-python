# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for key commitment policy enforcement on the encryption path.

Per specification/s3-encryption/key-commitment.md#commitment-policy:
  - REQUIRE_ENCRYPT_ALLOW_DECRYPT: the S3EC MUST only encrypt using an
    algorithm suite which supports key commitment.
  - REQUIRE_ENCRYPT_REQUIRE_DECRYPT: the S3EC MUST only encrypt using an
    algorithm suite which supports key commitment.
  - FORBID_ENCRYPT_ALLOW_DECRYPT: the S3EC MUST NOT encrypt using an
    algorithm suite which supports key commitment.

Per specification/s3-encryption/client.md#key-commitment:
  - The S3EC MUST validate the configured Encryption Algorithm against the
    provided key commitment policy.
  - If the configured Encryption Algorithm is incompatible with the key
    commitment policy, then it MUST throw an exception.

These tests verify that the S3EC rejects mismatched commitment policy and
algorithm suite configurations. The rejection may occur at client config
creation time or at encrypt time.
"""

import os
from unittest.mock import MagicMock

import pytest

from s3_encryption import S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy
from s3_encryption.pipelines import PutEncryptedObjectPipeline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_keyring():
    """Return a mock keyring that populates encryption materials."""
    key = os.urandom(32)
    mock = MagicMock()

    def on_encrypt(mats):
        mats.plaintext_data_key = key
        mats.encrypted_data_key = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-key",
        )
        return mats

    mock.on_encrypt.side_effect = on_encrypt
    return mock


# ---------------------------------------------------------------------------
# REQUIRE_ENCRYPT_* with non-committing algorithm → MUST fail
# ---------------------------------------------------------------------------

class TestRequireEncryptRejectsNonCommitting:
    """Configuring REQUIRE_ENCRYPT_* with a non-committing algorithm MUST fail."""

    ##= specification/s3-encryption/key-commitment.md#commitment-policy
    ##= type=test
    ##% When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
    def test_require_encrypt_allow_decrypt_rejects_non_committing_gcm(self):
        keyring = _mock_keyring()
        with pytest.raises(S3EncryptionClientError):
            S3EncryptionClientConfig(
                keyring=keyring,
                algorithm_suite=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
                commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
            )

    ##= specification/s3-encryption/key-commitment.md#commitment-policy
    ##= type=test
    ##% When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
    def test_require_encrypt_require_decrypt_rejects_non_committing_gcm(self):
        keyring = _mock_keyring()
        with pytest.raises(S3EncryptionClientError):
            S3EncryptionClientConfig(
                keyring=keyring,
                algorithm_suite=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
                commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            )


# ---------------------------------------------------------------------------
# FORBID_ENCRYPT_ALLOW_DECRYPT with committing algorithm → MUST fail
# ---------------------------------------------------------------------------

class TestForbidEncryptRejectsCommitting:
    """Configuring FORBID_ENCRYPT_ALLOW_DECRYPT with a committing algorithm MUST fail."""

    ##= specification/s3-encryption/key-commitment.md#commitment-policy
    ##= type=test
    ##% When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
    def test_forbid_encrypt_allow_decrypt_rejects_committing_gcm(self):
        keyring = _mock_keyring()
        with pytest.raises(S3EncryptionClientError):
            S3EncryptionClientConfig(
                keyring=keyring,
                algorithm_suite=AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
                commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            )
