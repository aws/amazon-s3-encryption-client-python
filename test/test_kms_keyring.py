# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for KMS keyring implementation."""

from unittest.mock import MagicMock

import pytest

from src.s3_encryption.exceptions import S3EncryptionClientError
from src.s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from src.s3_encryption.materials.kms_keyring import KmsKeyring
from src.s3_encryption.materials.materials import DecryptionMaterials, EncryptionMaterials


class TestKmsKeyringInitialization:
    """Tests for KMS keyring initialization."""

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
    ##= type=test
    ##% On initialization, the caller MUST provide an AWS KMS key identifier.
    def test_initialization_with_required_parameters(self):
        """Test that KMS keyring can be initialized with required parameters."""
        mock_kms_client = MagicMock()
        kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id=kms_key_id)

        assert keyring.kms_client == mock_kms_client
        assert keyring.kms_key_id == kms_key_id
        assert keyring.enable_legacy_wrapping_algorithms is False

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
    ##= type=test
    ##% On initialization, the caller MAY provide an AWS KMS SDK client instance.
    def test_initialization_with_kms_client(self):
        """Test that KMS keyring accepts a KMS client instance."""
        mock_kms_client = MagicMock()
        kms_key_id = "test-key-id"

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id=kms_key_id)

        assert keyring.kms_client == mock_kms_client

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    ##= type=test
    ##% The KmsV1 mode MUST be only enabled when legacy wrapping algorithms are enabled.
    def test_initialization_with_legacy_wrapping_algorithms(self):
        """Test that legacy wrapping algorithms can be enabled."""
        mock_kms_client = MagicMock()
        kms_key_id = "test-key-id"

        keyring = KmsKeyring(
            kms_client=mock_kms_client,
            kms_key_id=kms_key_id,
            enable_legacy_wrapping_algorithms=True,
        )

        assert keyring.enable_legacy_wrapping_algorithms is True


class TestKmsKeyringOnEncrypt:
    """Tests for KMS keyring encryption operations."""

    def test_on_encrypt_returns_encryption_materials(self):
        """Test that on_encrypt returns EncryptionMaterials."""
        mock_kms_client = MagicMock()
        mock_kms_client.generate_data_key.return_value = {
            "CiphertextBlob": b"encrypted-key",
            "Plaintext": b"plaintext-key",
        }

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        enc_materials = EncryptionMaterials(encryption_context={"key": "value"})

        result = keyring.on_encrypt(enc_materials)

        assert isinstance(result, EncryptionMaterials)

    def test_on_encrypt_calls_kms_generate_data_key(self):
        """Test that on_encrypt calls KMS generate_data_key."""
        mock_kms_client = MagicMock()
        mock_kms_client.generate_data_key.return_value = {
            "CiphertextBlob": b"encrypted-key",
            "Plaintext": b"plaintext-key",
        }

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        enc_materials = EncryptionMaterials(encryption_context={"key": "value"})

        keyring.on_encrypt(enc_materials)

        mock_kms_client.generate_data_key.assert_called_once()

    def test_on_encrypt_uses_correct_kms_parameters(self):
        """Test that on_encrypt uses correct KMS parameters."""
        mock_kms_client = MagicMock()
        mock_kms_client.generate_data_key.return_value = {
            "CiphertextBlob": b"encrypted-key",
            "Plaintext": b"plaintext-key",
        }

        kms_key_id = "test-key-id"
        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id=kms_key_id)
        encryption_context = {"key": "value"}
        enc_materials = EncryptionMaterials(encryption_context=encryption_context)

        keyring.on_encrypt(enc_materials)

        call_args = mock_kms_client.generate_data_key.call_args
        assert call_args.kwargs["KeyId"] == kms_key_id
        assert "aws:x-amz-cek-alg" in call_args.kwargs["EncryptionContext"]
        assert call_args.kwargs["EncryptionContext"]["key"] == "value"

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    ##= type=test
    ##% The KmsKeyring MUST support encryption using Kms+Context mode.
    def test_on_encrypt_adds_kms_context_algorithm(self):
        """Test that on_encrypt adds the Kms+Context algorithm to encryption context."""
        mock_kms_client = MagicMock()
        mock_kms_client.generate_data_key.return_value = {
            "CiphertextBlob": b"encrypted-key",
            "Plaintext": b"plaintext-key",
        }

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        enc_materials = EncryptionMaterials(encryption_context={})

        result = keyring.on_encrypt(enc_materials)

        call_args = mock_kms_client.generate_data_key.call_args
        assert call_args.kwargs["EncryptionContext"]["aws:x-amz-cek-alg"] == "AES/GCM/NoPadding"

    def test_on_encrypt_sets_encrypted_data_key(self):
        """Test that on_encrypt sets the encrypted data key from KMS response."""
        mock_kms_client = MagicMock()
        ciphertext_blob = b"encrypted-key-from-kms"
        plaintext = b"plaintext-key-from-kms"
        mock_kms_client.generate_data_key.return_value = {
            "CiphertextBlob": ciphertext_blob,
            "Plaintext": plaintext,
        }

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        enc_materials = EncryptionMaterials(encryption_context={})

        result = keyring.on_encrypt(enc_materials)

        assert result.encrypted_data_key is not None
        assert result.encrypted_data_key.encrypted_data_key == ciphertext_blob
        assert result.encrypted_data_key.key_provider_info == "kms+context"
        assert result.plaintext_data_key == plaintext

    def test_on_encrypt_fails_when_kms_fails(self):
        """Test that on_encrypt fails when KMS call fails."""
        mock_kms_client = MagicMock()
        mock_kms_client.generate_data_key.side_effect = Exception("KMS error")

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        enc_materials = EncryptionMaterials(encryption_context={})

        with pytest.raises(Exception):
            keyring.on_encrypt(enc_materials)


class TestKmsKeyringOnDecrypt:
    """Tests for KMS keyring decryption operations."""

    def test_on_decrypt_returns_decryption_materials(self):
        """Test that on_decrypt returns DecryptionMaterials."""
        mock_kms_client = MagicMock()
        mock_kms_client.decrypt.return_value = {"Plaintext": b"plaintext-key"}

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-key",
        )
        dec_materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={"aws:x-amz-cek-alg": "AES/GCM/NoPadding"},
            encryption_context_from_request={},
        )

        result = keyring.on_decrypt(dec_materials)

        assert isinstance(result, DecryptionMaterials)

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
    ##= type=test
    ##% The KmsKeyring MUST determine whether to decrypt using KmsV1 mode or Kms+Context mode.
    ##= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    ##= type=test
    ##% The KmsKeyring MUST support decryption using Kms+Context mode.
    ##% The Kms+Context mode MUST be enabled as a fully-supported (non-legacy) wrapping algorithm.
    def test_on_decrypt_with_kms_context_mode(self):
        """Test that on_decrypt handles kms+context mode."""
        mock_kms_client = MagicMock()
        mock_kms_client.decrypt.return_value = {"Plaintext": b"plaintext-key"}

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-key",
        )
        dec_materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={"aws:x-amz-cek-alg": "AES/GCM/NoPadding"},
            encryption_context_from_request={},
        )

        result = keyring.on_decrypt(dec_materials)

        assert result.plaintext_data_key == b"plaintext-key"
        mock_kms_client.decrypt.assert_called_once()

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
    ##= type=test
    ##% If the Key Provider Info of the Encrypted Data Key is "kms+context", the KmsKeyring MUST attempt to decrypt using Kms+Context mode.
    def test_on_decrypt_validates_encryption_context(self):
        """Test that on_decrypt validates encryption context."""
        mock_kms_client = MagicMock()
        mock_kms_client.decrypt.return_value = {"Plaintext": b"plaintext-key"}

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-key",
        )
        dec_materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={
                "aws:x-amz-cek-alg": "AES/GCM/NoPadding",
                "custom-key": "custom-value",
            },
            encryption_context_from_request={"custom-key": "custom-value"},
        )

        result = keyring.on_decrypt(dec_materials)

        assert result.plaintext_data_key == b"plaintext-key"

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
    ##= type=test
    ##% When decrypting using Kms+Context mode, the KmsKeyring MUST validate the provided (request) encryption context with the stored (materials) encryption context.
    ##% If the stored encryption context with the two reserved keys removed does not match the provided encryption context, the KmsKeyring MUST throw an exception.
    def test_on_decrypt_fails_with_mismatched_encryption_context(self):
        """Test that on_decrypt fails when encryption contexts don't match."""
        mock_kms_client = MagicMock()

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-key",
        )
        dec_materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={
                "aws:x-amz-cek-alg": "AES/GCM/NoPadding",
                "custom-key": "stored-value",
            },
            encryption_context_from_request={"custom-key": "different-value"},
        )

        with pytest.raises(S3EncryptionClientError) as exc_info:
            keyring.on_decrypt(dec_materials)

        assert "does not match" in str(exc_info.value)

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
    ##= type=test
    ##% The stored encryption context with the two reserved keys removed MUST match the provided encryption context.
    def test_on_decrypt_rejects_reserved_key_in_request_context(self):
        """Test that on_decrypt rejects reserved keys in request encryption context."""
        mock_kms_client = MagicMock()

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-key",
        )
        dec_materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={"aws:x-amz-cek-alg": "AES/GCM/NoPadding"},
            encryption_context_from_request={"aws:x-amz-cek-alg": "AES/GCM/NoPadding"},
        )

        with pytest.raises(S3EncryptionClientError) as exc_info:
            keyring.on_decrypt(dec_materials)

        assert "reserved key" in str(exc_info.value)

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
    ##= type=test
    ##% If the Key Provider Info of the Encrypted Data Key is "kms", the KmsKeyring MUST attempt to decrypt using KmsV1 mode.
    def test_on_decrypt_with_kms_v1_mode(self):
        """Test that on_decrypt handles KmsV1 mode when legacy algorithms are enabled."""
        mock_kms_client = MagicMock()
        mock_kms_client.decrypt.return_value = {"Plaintext": b"plaintext-key"}

        kms_key_id = "test-key-id"
        encrypted_key = b"encrypted-key"
        encryption_context_stored = {"foo": "bar"}

        keyring = KmsKeyring(
            kms_client=mock_kms_client,
            kms_key_id=kms_key_id,
            enable_legacy_wrapping_algorithms=True,
        )
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms",
            encrypted_data_key=encrypted_key,
        )
        dec_materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored=encryption_context_stored,
            encryption_context_from_request={},
        )

        result = keyring.on_decrypt(dec_materials)

        ##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
        ##= type=test
        ##% To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), the KmsKeyring MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
        call_args = mock_kms_client.decrypt.call_args
        ##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
        ##= type=test
        ##% - `KeyId` MUST be the configured AWS KMS key identifier.
        assert call_args.kwargs["KeyId"] == kms_key_id
        ##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
        ##= type=test
        ##% - `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
        assert call_args.kwargs["CiphertextBlob"] == encrypted_key
        ##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
        ##= type=test
        ##% - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [decryption materials](../structures.md#decryption-materials).
        assert call_args.kwargs["EncryptionContext"] == encryption_context_stored
        assert result.plaintext_data_key == b"plaintext-key"

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    ##= type=test
    ##% The KmsKeyring MUST support decryption using KmsV1 mode.
    def test_on_decrypt_rejects_kms_v1_when_legacy_disabled(self):
        """Test that on_decrypt rejects KmsV1 mode when legacy algorithms are disabled."""
        mock_kms_client = MagicMock()

        keyring = KmsKeyring(
            kms_client=mock_kms_client,
            kms_key_id="test-key-id",
            enable_legacy_wrapping_algorithms=False,
        )
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms",
            encrypted_data_key=b"encrypted-key",
        )
        dec_materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={},
            encryption_context_from_request={},
        )

        with pytest.raises(S3EncryptionClientError) as exc_info:
            keyring.on_decrypt(dec_materials)

        assert "legacy wrapping algorithms" in str(exc_info.value)

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
    ##= type=test
    ##% To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), the KmsKeyring MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
    def test_on_decrypt_uses_correct_kms_parameters(self):
        """Test that on_decrypt uses correct KMS parameters."""
        mock_kms_client = MagicMock()
        mock_kms_client.decrypt.return_value = {"Plaintext": b"plaintext-key"}

        kms_key_id = "test-key-id"
        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id=kms_key_id)
        encrypted_key = b"encrypted-key-bytes"
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=encrypted_key,
        )
        encryption_context_stored = {"aws:x-amz-cek-alg": "AES/GCM/NoPadding"}
        dec_materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored=encryption_context_stored,
            encryption_context_from_request={},
        )

        keyring.on_decrypt(dec_materials)

        call_args = mock_kms_client.decrypt.call_args
        assert call_args.kwargs["KeyId"] == kms_key_id
        assert call_args.kwargs["CiphertextBlob"] == encrypted_key
        assert call_args.kwargs["EncryptionContext"] == encryption_context_stored

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
    ##= type=test
    ##% If the KmsKeyring fails to successfully decrypt the [encrypted data key](../structures.md#encrypted-data-key), then it MUST throw an exception.
    def test_on_decrypt_fails_when_kms_v1_fails(self):
        """Test that on_decrypt fails when KMS call fails."""
        mock_kms_client = MagicMock()
        kms_exception = Exception("KMS decrypt error")
        mock_kms_client.decrypt.side_effect = kms_exception

        keyring = KmsKeyring(
            kms_client=mock_kms_client,
            kms_key_id="test-key-id",
            enable_legacy_wrapping_algorithms=True,
        )
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms",
            encrypted_data_key=b"encrypted-key",
        )
        dec_materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={},
            encryption_context_from_request={},
        )

        with pytest.raises(Exception, match="KMS decrypt error") as exc_info:
            keyring.on_decrypt(dec_materials)

        assert exc_info.value is kms_exception

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
    ##= type=test
    ##% If the KmsKeyring fails to successfully decrypt the [encrypted data key](../structures.md#encrypted-data-key), then it MUST throw an exception.
    def test_on_decrypt_fails_when_kms_fails(self):
        """Test that on_decrypt fails when KMS call fails."""
        mock_kms_client = MagicMock()
        kms_exception = Exception("KMS decrypt error")
        mock_kms_client.decrypt.side_effect = kms_exception

        keyring = KmsKeyring(kms_client=mock_kms_client, kms_key_id="test-key-id")
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-key",
        )
        dec_materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={"aws:x-amz-cek-alg": "AES/GCM/NoPadding"},
            encryption_context_from_request={},
        )

        with pytest.raises(Exception, match="KMS decrypt error") as exc_info:
            keyring.on_decrypt(dec_materials)

        assert exc_info.value is kms_exception
