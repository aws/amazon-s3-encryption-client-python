# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for encryption specification compliance annotations.

Each test in this module corresponds to a MUST/SHOULD requirement from
specification/s3-encryption/encryption.md and carries a type=test annotation
that mirrors the type=implementation annotation in the source code.
"""

import base64
import os
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from s3_encryption.key_derivation import derive_keys
from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from s3_encryption.materials.materials import AlgorithmSuite

_KC_SUITE = AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
KC_GCM_IV = _KC_SUITE.kc_gcm_iv
MESSAGE_ID_LENGTH = _KC_SUITE.commitment_nonce_length_bytes
SUITE_ID_BYTES = _KC_SUITE.suite_id_bytes
from s3_encryption.pipelines import PutEncryptedObjectPipeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_cmm(plaintext_key=None, encrypted_key=b"encrypted-key"):
    """Return a CMM backed by a mock keyring that returns the given keys."""
    if plaintext_key is None:
        plaintext_key = os.urandom(32)

    mock_keyring = MagicMock()
    mock_keyring.on_encrypt.side_effect = lambda mats: _fill_materials(
        mats, plaintext_key, encrypted_key
    )
    return DefaultCryptoMaterialsManager(mock_keyring), plaintext_key


def _fill_materials(mats, plaintext_key, encrypted_key):
    mats.plaintext_data_key = plaintext_key
    mats.encrypted_data_key = EncryptedDataKey(
        key_provider_id=b"S3Keyring",
        key_provider_info="kms+context",
        encrypted_data_key=encrypted_key,
    )
    return mats


# ---------------------------------------------------------------------------
# Content Encryption — General
# ---------------------------------------------------------------------------


class TestContentEncryption:
    """Tests for specification/s3-encryption/encryption.md#content-encryption."""

    ##= specification/s3-encryption/encryption.md#content-encryption
    ##= type=test
    ##% The S3EC MUST use the encryption algorithm configured during
    ##% [client](./client.md) initialization.
    def test_uses_configured_algorithm_suite(self):
        """The pipeline MUST encrypt using the algorithm suite passed to encrypt()."""
        cmm, key = _mock_cmm()
        pipeline = PutEncryptedObjectPipeline(cmm)
        plaintext = b"test data"

        # V2 (GCM no KDF)
        _, meta_v2 = pipeline.encrypt(
            plaintext,
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        )
        assert "x-amz-cek-alg" in meta_v2
        assert meta_v2["x-amz-cek-alg"] == "AES/GCM/NoPadding"

        # V3 (KC GCM)
        _, meta_v3 = pipeline.encrypt(
            plaintext,
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )
        assert "x-amz-c" in meta_v3
        assert meta_v3["x-amz-c"] == "115"

    ##= specification/s3-encryption/encryption.md#content-encryption
    ##= type=test
    ##% The client MUST generate an IV or Message ID using the length of the IV
    ##% or Message ID defined in the algorithm suite.
    def test_iv_generated_with_correct_length_gcm(self):
        """GCM encryption MUST produce a 12-byte IV."""
        cmm, _ = _mock_cmm()
        pipeline = PutEncryptedObjectPipeline(cmm)

        _, meta = pipeline.encrypt(
            b"test",
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        )
        iv_bytes = base64.b64decode(meta["x-amz-iv"])
        assert len(iv_bytes) == 12

    def test_message_id_generated_with_correct_length_kc(self):
        """KC-GCM encryption MUST produce a 28-byte Message ID."""
        cmm, _ = _mock_cmm()
        pipeline = PutEncryptedObjectPipeline(cmm)

        _, meta = pipeline.encrypt(
            b"test",
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )
        message_id_bytes = base64.b64decode(meta["x-amz-i"])
        assert len(message_id_bytes) == MESSAGE_ID_LENGTH

    ##= specification/s3-encryption/encryption.md#content-encryption
    ##= type=test
    ##% The generated IV or Message ID MUST be set or returned from the encryption
    ##% process such that it can be included in the content metadata.
    def test_iv_included_in_metadata_gcm(self):
        """GCM encryption MUST include the IV in the returned metadata."""
        cmm, _ = _mock_cmm()
        pipeline = PutEncryptedObjectPipeline(cmm)

        _, meta = pipeline.encrypt(
            b"test",
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        )
        assert "x-amz-iv" in meta

    def test_message_id_included_in_metadata_kc(self):
        """KC-GCM encryption MUST include the Message ID in the returned metadata."""
        cmm, _ = _mock_cmm()
        pipeline = PutEncryptedObjectPipeline(cmm)

        _, meta = pipeline.encrypt(
            b"test",
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )
        assert "x-amz-i" in meta


# ---------------------------------------------------------------------------
# ALG_AES_256_GCM_IV12_TAG16_NO_KDF
# ---------------------------------------------------------------------------


class TestGcmNoKdf:
    """Tests for specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf."""

    ##= specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
    ##= type=test
    ##% The client MUST initialize the cipher, or call an AES-GCM encryption API,
    ##% with the plaintext data key, the generated IV, and the tag length defined
    ##% in the Algorithm Suite when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
    ##= specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
    ##= type=test
    ##% The client MUST NOT provide any AAD when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
    def test_gcm_encrypt_decrypt_roundtrip_no_aad(self):
        """GCM encryption MUST use the data key, generated IV, and no AAD."""
        cmm, key = _mock_cmm()
        pipeline = PutEncryptedObjectPipeline(cmm)
        plaintext = b"roundtrip test for GCM no KDF"

        ciphertext, meta = pipeline.encrypt(
            plaintext,
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        )

        # Decrypt with the same key, IV, and no AAD
        iv = base64.b64decode(meta["x-amz-iv"])
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce=iv, data=ciphertext, associated_data=None)
        assert decrypted == plaintext

    def test_gcm_decrypt_fails_with_aad(self):
        """Ciphertext produced with no AAD MUST NOT decrypt with AAD."""
        cmm, key = _mock_cmm()
        pipeline = PutEncryptedObjectPipeline(cmm)

        ciphertext, meta = pipeline.encrypt(
            b"test",
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        )

        iv = base64.b64decode(meta["x-amz-iv"])
        aesgcm = AESGCM(key)
        with pytest.raises(Exception):
            aesgcm.decrypt(nonce=iv, data=ciphertext, associated_data=b"unexpected-aad")


# ---------------------------------------------------------------------------
# ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
# ---------------------------------------------------------------------------


class TestKcGcm:
    """Tests for specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key."""

    ##= specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
    ##= type=test
    ##% The client MUST use HKDF to derive the key commitment value and the derived
    ##% encrypting key as described in [Key Derivation](key-derivation.md).
    def test_kc_gcm_uses_hkdf_derived_key(self):
        """KC-GCM encryption MUST use HKDF-derived keys, not the raw data key."""
        cmm, raw_key = _mock_cmm()
        pipeline = PutEncryptedObjectPipeline(cmm)
        plaintext = b"roundtrip test for KC GCM"

        ciphertext, meta = pipeline.encrypt(
            plaintext,
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )

        message_id = base64.b64decode(meta["x-amz-i"])
        derived_key, _ = derive_keys(
            raw_key, message_id, AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        )

        # Decrypt with the HKDF-derived key, fixed IV, and suite ID as AAD
        aesgcm = AESGCM(derived_key)
        decrypted = aesgcm.decrypt(nonce=KC_GCM_IV, data=ciphertext, associated_data=SUITE_ID_BYTES)
        assert decrypted == plaintext

        # Decrypting with the raw key must fail
        aesgcm_raw = AESGCM(raw_key)
        with pytest.raises(Exception):
            aesgcm_raw.decrypt(nonce=KC_GCM_IV, data=ciphertext, associated_data=SUITE_ID_BYTES)

    ##= specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
    ##= type=test
    ##% The derived key commitment value MUST be set or returned from the encryption
    ##% process such that it can be included in the content metadata.
    def test_kc_gcm_commitment_in_metadata(self):
        """KC-GCM encryption MUST include the key commitment in metadata."""
        cmm, raw_key = _mock_cmm()
        pipeline = PutEncryptedObjectPipeline(cmm)

        _, meta = pipeline.encrypt(
            b"test",
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )

        assert "x-amz-d" in meta
        commitment_bytes = base64.b64decode(meta["x-amz-d"])

        # Verify the commitment matches what HKDF would produce
        message_id = base64.b64decode(meta["x-amz-i"])
        _, expected_commitment = derive_keys(
            raw_key, message_id, AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        )
        assert commitment_bytes == expected_commitment
