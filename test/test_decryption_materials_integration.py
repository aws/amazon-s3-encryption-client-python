# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import MagicMock

from src.s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from src.s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from src.s3_encryption.materials.kms_keyring import KmsKeyring
from src.s3_encryption.materials.materials import DecryptionMaterials


class TestDecryptionMaterialsIntegration:
    def test_keyring_on_decrypt(self):
        """Test that KmsKeyring.on_decrypt properly handles DecryptionMaterials."""
        # Create a mock KMS client
        mock_kms_client = MagicMock()
        mock_kms_client.decrypt.return_value = {
            "Plaintext": b"plaintext-data-key",
        }

        # Create a keyring
        keyring = KmsKeyring(
            kms_client=mock_kms_client,
            kms_key_id="arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
        )

        # Create an encrypted data key
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-data-key",
        )

        # Create decryption materials with matching encryption contexts
        # The stored context includes the reserved key, the request context should match (minus reserved keys)
        materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={"key1": "value1", "aws:x-amz-cek-alg": "AES/GCM/NoPadding"},
            encryption_context_from_request={"key1": "value1"},
        )

        # Call on_decrypt
        result = keyring.on_decrypt(materials, [edk])

        # Verify the result is a DecryptionMaterials instance
        assert isinstance(result, DecryptionMaterials)
        assert result.iv == b"initialization-vector"
        assert result.encrypted_data_keys == [edk]
        assert result.encryption_context_stored == {"key1": "value1", "aws:x-amz-cek-alg": "AES/GCM/NoPadding"}
        assert result.encryption_context_from_request == {"key1": "value1"}

    def test_keyring_on_decrypt_default_enc_ctx(self):
        """Test that KmsKeyring.on_decrypt properly handles DecryptionMaterials."""
        # Create a mock KMS client
        mock_kms_client = MagicMock()
        mock_kms_client.decrypt.return_value = {
            "Plaintext": b"plaintext-data-key",
        }

        # Create a keyring
        keyring = KmsKeyring(
            kms_client=mock_kms_client,
            kms_key_id="arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
        )

        # Create an encrypted data key
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-data-key",
        )

        # Create decryption materials
        materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={},
            encryption_context_from_request={},
        )

        # Mock the validation method to return the materials
        # Call on_decrypt
        result = keyring.on_decrypt(materials, [edk])

        # Verify the result is a DecryptionMaterials instance
        assert isinstance(result, DecryptionMaterials)
        assert result.iv == b"initialization-vector"
        assert result.encrypted_data_keys == [edk]
        assert result.encryption_context_stored == {}
        assert result.encryption_context_from_request == {}

    def test_cmm_decrypt_materials_with_dict(self):
        """Test that DefaultCryptoMaterialsManager.decrypt_materials properly handles dictionary input."""
        # Create a mock keyring
        keyring = MagicMock()
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-data-key",
        )
        keyring.on_decrypt.return_value = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={"key1": "value1"},
            encryption_context_from_request={"key2": "value2"},
            plaintext_data_key=b"plaintext-data-key",
        )

        # Create a CMM
        cmm = DefaultCryptoMaterialsManager(keyring=keyring)

        # Call decrypt_materials with a dictionary
        result = cmm.decrypt_materials(
            {
                "iv": b"initialization-vector",
                "encrypted_data_keys": [edk],
                "encryption_context_stored": {"key1": "value1"},
                "encryption_context_from_request": {"key2": "value2"},
            }
        )

        # Verify the result is a DecryptionMaterials instance
        assert isinstance(result, DecryptionMaterials)
        assert result.iv == b"initialization-vector"
        assert result.encrypted_data_keys == [edk]
        assert result.encryption_context_stored == {"key1": "value1"}
        assert result.encryption_context_from_request == {"key2": "value2"}
        assert result.plaintext_data_key == b"plaintext-data-key"

    def test_cmm_decrypt_materials_with_materials(self):
        """Test that DefaultCryptoMaterialsManager.decrypt_materials properly handles DecryptionMaterials input."""
        # Create a mock keyring
        keyring = MagicMock()
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-data-key",
        )
        keyring.on_decrypt.return_value = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={"key1": "value1"},
            encryption_context_from_request={"key2": "value2"},
            plaintext_data_key=b"plaintext-data-key",
        )

        # Create a CMM
        cmm = DefaultCryptoMaterialsManager(keyring=keyring)

        # Call decrypt_materials with a DecryptionMaterials instance
        materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={"key1": "value1"},
            encryption_context_from_request={"key2": "value2"},
        )
        result = cmm.decrypt_materials(materials)

        # Verify the result is a DecryptionMaterials instance
        assert isinstance(result, DecryptionMaterials)
        assert result.iv == b"initialization-vector"
        assert result.encrypted_data_keys == [edk]
        assert result.encryption_context_stored == {"key1": "value1"}
        assert result.encryption_context_from_request == {"key2": "value2"}
        assert result.plaintext_data_key == b"plaintext-data-key"
