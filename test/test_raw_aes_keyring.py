# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for RawAesKeyring implementation."""

import os

import pytest

from src.s3_encryption.exceptions import S3EncryptionClientError
from src.s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from src.s3_encryption.materials.materials import DecryptionMaterials, EncryptionMaterials
from src.s3_encryption.materials.raw_aes_keyring import (
    AES_WRAP_ALGORITHM,
    RAW_AES_KEY_NAME_CONTEXT_KEY,
    RawAesKeyring,
)


def _wrapping_key(length=32):
    return os.urandom(length)


class TestRawAesKeyringInitialization:
    """Tests for RawAesKeyring initialization."""

    def test_initialization_with_required_parameters(self):
        wrapping_key = _wrapping_key()
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=wrapping_key)

        assert keyring.key_name == "my-key"
        assert keyring.wrapping_key == wrapping_key

    @pytest.mark.parametrize("length", [16, 24, 32])
    def test_initialization_accepts_valid_aes_key_lengths(self, length):
        wrapping_key = _wrapping_key(length)
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=wrapping_key)

        assert keyring.wrapping_key == wrapping_key

    @pytest.mark.parametrize("length", [0, 8, 15, 31, 33, 64])
    def test_initialization_rejects_invalid_key_lengths(self, length):
        with pytest.raises(S3EncryptionClientError, match="16, 24, or 32 bytes"):
            RawAesKeyring(key_name="my-key", wrapping_key=os.urandom(length))

    def test_initialization_rejects_non_bytes_wrapping_key(self):
        with pytest.raises(S3EncryptionClientError, match="16, 24, or 32 bytes"):
            RawAesKeyring(key_name="my-key", wrapping_key="not-bytes")


class TestRawAesKeyringOnEncrypt:
    """Tests for RawAesKeyring encryption operations."""

    def test_on_encrypt_returns_encryption_materials(self):
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        enc_materials = EncryptionMaterials(encryption_context={"key": "value"})

        result = keyring.on_encrypt(enc_materials)

        assert isinstance(result, EncryptionMaterials)

    def test_on_encrypt_sets_plaintext_and_encrypted_data_key(self):
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        enc_materials = EncryptionMaterials(encryption_context={})

        result = keyring.on_encrypt(enc_materials)

        assert result.plaintext_data_key is not None
        assert len(result.plaintext_data_key) == result.encryption_algorithm.data_key_length_bytes
        assert result.encrypted_data_key is not None
        assert result.encrypted_data_key.key_provider_info == AES_WRAP_ALGORITHM
        assert result.encrypted_data_key.key_provider_id == b"S3Keyring"

    def test_on_encrypt_generates_unique_plaintext_keys(self):
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())

        first = keyring.on_encrypt(EncryptionMaterials(encryption_context={}))
        second = keyring.on_encrypt(EncryptionMaterials(encryption_context={}))

        assert first.plaintext_data_key != second.plaintext_data_key
        assert (
            first.encrypted_data_key.encrypted_data_key
            != second.encrypted_data_key.encrypted_data_key
        )

    def test_on_encrypt_adds_key_name_to_encryption_context(self):
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        enc_materials = EncryptionMaterials(encryption_context={"app": "demo"})

        result = keyring.on_encrypt(enc_materials)

        assert result.encryption_context[RAW_AES_KEY_NAME_CONTEXT_KEY] == "my-key"
        assert result.encryption_context["app"] == "demo"

    def test_on_encrypt_rejects_reserved_key_in_context(self):
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        enc_materials = EncryptionMaterials(
            encryption_context={RAW_AES_KEY_NAME_CONTEXT_KEY: "spoofed"}
        )

        with pytest.raises(S3EncryptionClientError, match="reserved key"):
            keyring.on_encrypt(enc_materials)


class TestRawAesKeyringOnDecrypt:
    """Tests for RawAesKeyring decryption operations."""

    def _encrypt(self, keyring, encryption_context=None):
        enc_materials = EncryptionMaterials(encryption_context=encryption_context or {})
        return keyring.on_encrypt(enc_materials)

    def test_on_decrypt_round_trips_plaintext_data_key(self):
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        enc_result = self._encrypt(keyring, {"app": "demo"})

        dec_materials = DecryptionMaterials(
            encrypted_data_keys=[enc_result.encrypted_data_key],
            encryption_context_stored=enc_result.encryption_context,
            encryption_context_from_request={"app": "demo"},
        )

        result = keyring.on_decrypt(dec_materials)

        assert result.plaintext_data_key == enc_result.plaintext_data_key

    def test_on_decrypt_fails_with_wrong_wrapping_key(self):
        encrypting_keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        enc_result = self._encrypt(encrypting_keyring, {"app": "demo"})

        decrypting_keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        dec_materials = DecryptionMaterials(
            encrypted_data_keys=[enc_result.encrypted_data_key],
            encryption_context_stored=enc_result.encryption_context,
            encryption_context_from_request={"app": "demo"},
        )

        with pytest.raises(S3EncryptionClientError, match="Failed to unwrap data key"):
            decrypting_keyring.on_decrypt(dec_materials)

    def test_on_decrypt_fails_with_mismatched_key_name(self):
        encrypting_keyring = RawAesKeyring(key_name="key-a", wrapping_key=_wrapping_key())
        wrapping_key = encrypting_keyring.wrapping_key
        enc_result = self._encrypt(encrypting_keyring, {"app": "demo"})

        decrypting_keyring = RawAesKeyring(key_name="key-b", wrapping_key=wrapping_key)
        dec_materials = DecryptionMaterials(
            encrypted_data_keys=[enc_result.encrypted_data_key],
            encryption_context_stored=enc_result.encryption_context,
            encryption_context_from_request={"app": "demo"},
        )

        with pytest.raises(S3EncryptionClientError, match="key_name"):
            decrypting_keyring.on_decrypt(dec_materials)

    def test_on_decrypt_fails_with_mismatched_encryption_context(self):
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        enc_result = self._encrypt(keyring, {"app": "demo"})

        dec_materials = DecryptionMaterials(
            encrypted_data_keys=[enc_result.encrypted_data_key],
            encryption_context_stored=enc_result.encryption_context,
            encryption_context_from_request={"app": "different"},
        )

        with pytest.raises(S3EncryptionClientError, match="does not match"):
            keyring.on_decrypt(dec_materials)

    def test_on_decrypt_rejects_reserved_key_in_request_context(self):
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        enc_result = self._encrypt(keyring, {})

        dec_materials = DecryptionMaterials(
            encrypted_data_keys=[enc_result.encrypted_data_key],
            encryption_context_stored=enc_result.encryption_context,
            encryption_context_from_request={RAW_AES_KEY_NAME_CONTEXT_KEY: "my-key"},
        )

        with pytest.raises(S3EncryptionClientError, match="reserved key"):
            keyring.on_decrypt(dec_materials)

    def test_on_decrypt_rejects_invalid_wrap_algorithm(self):
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"not-really-encrypted",
        )
        dec_materials = DecryptionMaterials(
            encrypted_data_keys=[edk],
            encryption_context_stored={},
            encryption_context_from_request={},
        )

        with pytest.raises(S3EncryptionClientError, match="not a valid key wrapping algorithm"):
            keyring.on_decrypt(dec_materials)

    def test_on_decrypt_fails_when_ciphertext_tampered(self):
        keyring = RawAesKeyring(key_name="my-key", wrapping_key=_wrapping_key())
        enc_result = self._encrypt(keyring, {})

        tampered_bytes = bytearray(enc_result.encrypted_data_key.encrypted_data_key)
        tampered_bytes[-1] ^= 0xFF
        tampered_edk = EncryptedDataKey(
            key_provider_id=enc_result.encrypted_data_key.key_provider_id,
            key_provider_info=enc_result.encrypted_data_key.key_provider_info,
            encrypted_data_key=bytes(tampered_bytes),
        )

        dec_materials = DecryptionMaterials(
            encrypted_data_keys=[tampered_edk],
            encryption_context_stored=enc_result.encryption_context,
            encryption_context_from_request={},
        )

        with pytest.raises(S3EncryptionClientError, match="Failed to unwrap data key"):
            keyring.on_decrypt(dec_materials)
