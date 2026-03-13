# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration test: the default encryption algorithm MUST use key commitment.

When S3EncryptionClientConfig is created with no explicit encryption_algorithm,
the default (ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY) MUST produce ciphertext
that is decryptable under REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy.
"""

import os
from io import BytesIO
from unittest.mock import MagicMock

from s3_encryption import S3EncryptionClientConfig
from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from s3_encryption.materials.keyring import S3Keyring
from s3_encryption.materials.materials import (
    AlgorithmSuite,
    CommitmentPolicy,
)
from s3_encryption.pipelines import GetEncryptedObjectPipeline, PutEncryptedObjectPipeline


def _mock_keyring(key=None):
    """Return a mock keyring that populates encryption/decryption materials."""
    if key is None:
        key = os.urandom(32)
    mock = MagicMock(spec=S3Keyring)

    def on_encrypt(mats):
        mats.plaintext_data_key = key
        mats.encrypted_data_key = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-key",
        )
        return mats

    def on_decrypt(mats, encrypted_data_keys=None):
        mats.plaintext_data_key = key
        return mats

    mock.on_encrypt.side_effect = on_encrypt
    mock.on_decrypt.side_effect = on_decrypt
    return mock, key


class TestDefaultAlgorithmUsesKeyCommitment:
    """The default encryption algorithm MUST be key-committing."""

    def test_default_config_encrypts_with_committing_algorithm(self):
        """S3EncryptionClientConfig with no explicit algorithm MUST default to a
        key-committing suite.
        """
        keyring, _ = _mock_keyring()
        config = S3EncryptionClientConfig(keyring=keyring)
        assert config.encryption_algorithm == AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY

    def test_encryption_materials_defaults_to_committing_algorithm(self):
        """EncryptionMaterials with no explicit algorithm MUST default to a
        key-committing suite.
        """
        from s3_encryption.materials.materials import EncryptionMaterials

        mats = EncryptionMaterials()
        assert mats.encryption_algorithm == AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY

    def test_default_encryption_decryptable_with_require_decrypt(self):
        """Ciphertext produced with the default algorithm MUST be decryptable
        when the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT.
        """
        keyring, key = _mock_keyring()
        config = S3EncryptionClientConfig(keyring=keyring)
        cmm = DefaultCryptoMaterialsManager(keyring)

        # Encrypt using the default algorithm (no override)
        pipeline = PutEncryptedObjectPipeline(cmm)
        plaintext = b"integration test: default algorithm uses key commitment"
        ciphertext, metadata = pipeline.encrypt(
            plaintext,
            encryption_algorithm=config.encryption_algorithm,
        )

        # Build a response dict as if we fetched this object from S3
        response = {
            "Body": BytesIO(ciphertext),
            "Metadata": metadata,
        }

        # Decrypt with REQUIRE_ENCRYPT_REQUIRE_DECRYPT — this will reject
        # non-committing algorithm suites, so success proves the default commits.
        decrypt_pipeline = GetEncryptedObjectPipeline(
            cmm,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        result = decrypt_pipeline.decrypt(response)
        assert result == plaintext
