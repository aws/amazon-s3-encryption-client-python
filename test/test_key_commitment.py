# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for key commitment policy specification compliance annotations.

Each test in this module corresponds to a MUST/SHOULD requirement from
specification/s3-encryption/key-commitment.md and carries a type=test annotation
that mirrors the type=implementation annotation in the source code.
"""

import base64
import os
from io import BytesIO
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.key_derivation import derive_keys
from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from s3_encryption.materials.keyring import S3Keyring
from s3_encryption.materials.materials import (
    AlgorithmSuite,
    CommitmentPolicy,
    DecryptionMaterials,
)
from s3_encryption.pipelines import GetEncryptedObjectPipeline

_KC_SUITE = AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
KC_GCM_IV = _KC_SUITE.kc_gcm_iv
SUITE_ID_BYTES = _KC_SUITE.suite_id_bytes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pipeline(commitment_policy, keyring_return=None):
    """Create a GetEncryptedObjectPipeline with a mocked CMM/keyring."""
    mock_keyring = Mock(spec=S3Keyring)
    if keyring_return is not None:
        mock_keyring.on_decrypt.return_value = keyring_return
    cmm = DefaultCryptoMaterialsManager(mock_keyring)
    return GetEncryptedObjectPipeline(
        cmm,
        commitment_policy=commitment_policy,
        enable_legacy_unauthenticated_modes=True,
    )


def _v2_gcm_response(key, plaintext=b"test data"):
    """Create a V2 GCM-encrypted response with real ciphertext."""
    iv = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    metadata = {
        "x-amz-iv": base64.b64encode(iv).decode(),
        "x-amz-key-v2": base64.b64encode(b"encrypted-key").decode(),
        "x-amz-wrap-alg": "kms+context",
        "x-amz-matdesc": "{}",
        "x-amz-cek-alg": "AES/GCM/NoPadding",
        "x-amz-tag-len": "128",
    }
    dec_mats = DecryptionMaterials(
        iv=iv,
        plaintext_data_key=key,
        algorithm_suite=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
    )
    return {"Body": BytesIO(ciphertext), "Metadata": metadata}, dec_mats, plaintext


def _v3_kc_gcm_response(key, plaintext=b"test data"):
    """Create a V3 KC-GCM-encrypted response with real ciphertext."""
    message_id = os.urandom(28)
    derived_key, commitment = derive_keys(
        key, message_id, AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
    )
    ciphertext = AESGCM(derived_key).encrypt(KC_GCM_IV, plaintext, SUITE_ID_BYTES)
    metadata = {
        "x-amz-c": "115",
        "x-amz-3": base64.b64encode(b"encrypted-key").decode(),
        "x-amz-w": "12",
        "x-amz-t": "{}",
        "x-amz-d": base64.b64encode(commitment).decode(),
        "x-amz-i": base64.b64encode(message_id).decode(),
    }
    dec_mats = DecryptionMaterials(
        plaintext_data_key=key,
        algorithm_suite=AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
    )
    return {"Body": BytesIO(ciphertext), "Metadata": metadata}, dec_mats, plaintext


# ---------------------------------------------------------------------------
# Commitment Policy Tests
# ---------------------------------------------------------------------------


class TestCommitmentPolicy:
    """Tests for specification/s3-encryption/key-commitment.md#commitment-policy."""

    ##= specification/s3-encryption/key-commitment.md#commitment-policy
    ##= type=test
    ##% When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
    def test_forbid_encrypt_allows_non_committing_decrypt(self):
        """FORBID_ENCRYPT_ALLOW_DECRYPT MUST allow decryption with non-committing suites."""
        key = os.urandom(32)
        response, dec_mats, plaintext = _v2_gcm_response(key)

        pipeline = _make_pipeline(
            commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            keyring_return=dec_mats,
        )
        result = pipeline.decrypt(response, enable_delayed_authentication=False)
        assert result.read() == plaintext

    ##= specification/s3-encryption/key-commitment.md#commitment-policy
    ##= type=test
    ##% When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
    def test_require_encrypt_allow_decrypt_allows_non_committing_decrypt(self):
        """REQUIRE_ENCRYPT_ALLOW_DECRYPT MUST allow decryption with non-committing suites."""
        key = os.urandom(32)
        response, dec_mats, plaintext = _v2_gcm_response(key)

        pipeline = _make_pipeline(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
            keyring_return=dec_mats,
        )
        result = pipeline.decrypt(response, enable_delayed_authentication=False)
        assert result.read() == plaintext

    ##= specification/s3-encryption/key-commitment.md#commitment-policy
    ##= type=test
    ##% When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST NOT allow decryption using algorithm suites which do not support key commitment.
    def test_require_require_rejects_non_committing_decrypt(self):
        """REQUIRE_ENCRYPT_REQUIRE_DECRYPT MUST reject non-committing algorithm suites."""
        key = os.urandom(32)
        response, dec_mats, _ = _v2_gcm_response(key)

        pipeline = _make_pipeline(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            keyring_return=dec_mats,
        )
        with pytest.raises(S3EncryptionClientError, match="cannot decrypt non-key-committing"):
            pipeline.decrypt(response, enable_delayed_authentication=False)

    def test_require_require_allows_committing_decrypt(self):
        """REQUIRE_ENCRYPT_REQUIRE_DECRYPT MUST allow decryption with committing suites."""
        key = os.urandom(32)
        response, dec_mats, plaintext = _v3_kc_gcm_response(key)

        pipeline = _make_pipeline(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            keyring_return=dec_mats,
        )
        result = pipeline.decrypt(response, enable_delayed_authentication=False)
        assert result.read() == plaintext
