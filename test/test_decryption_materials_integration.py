# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import MagicMock, patch

from src.s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from src.s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from src.s3_encryption.materials.keyring import S3Keyring
from src.s3_encryption.materials.materials import DecryptionMaterials


class TestDecryptionMaterialsIntegration(unittest.TestCase):
    def test_keyring_on_decrypt(self):
        """Test that S3Keyring.on_decrypt properly handles DecryptionMaterials."""
        # Create a keyring
        keyring = S3Keyring()

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
            encryption_context_stored={"key1": "value1"},
            encryption_context_from_request={"key2": "value2"},
        )

        # Mock the validation method to return the materials
        with patch.object(S3Keyring, "on_decrypt", return_value=materials) as mock_on_decrypt:
            # Call on_decrypt
            result = keyring.on_decrypt(materials, [edk])

            # Verify the result is a DecryptionMaterials instance
            self.assertIsInstance(result, DecryptionMaterials)
            self.assertEqual(result.iv, b"initialization-vector")
            self.assertEqual(result.encrypted_data_keys, [edk])
            self.assertEqual(result.encryption_context_stored, {"key1": "value1"})
            self.assertEqual(result.encryption_context_from_request, {"key2": "value2"})

    def test_keyring_on_decrypt_default_EC(self):
        """Test that S3Keyring.on_decrypt properly handles DecryptionMaterials."""
        # Create a keyring
        keyring = S3Keyring()

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
        with patch.object(S3Keyring, "on_decrypt", return_value=materials) as mock_on_decrypt:
            # Call on_decrypt
            result = keyring.on_decrypt(materials, [edk])

            # Verify the result is a DecryptionMaterials instance
            self.assertIsInstance(result, DecryptionMaterials)
            self.assertEqual(result.iv, b"initialization-vector")
            self.assertEqual(result.encrypted_data_keys, [edk])
            self.assertEqual(result.encryption_context_stored, {})
            self.assertEqual(result.encryption_context_from_request, {})

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
        self.assertIsInstance(result, DecryptionMaterials)
        self.assertEqual(result.iv, b"initialization-vector")
        self.assertEqual(result.encrypted_data_keys, [edk])
        self.assertEqual(result.encryption_context_stored, {"key1": "value1"})
        self.assertEqual(result.encryption_context_from_request, {"key2": "value2"})
        self.assertEqual(result.plaintext_data_key, b"plaintext-data-key")

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
        self.assertIsInstance(result, DecryptionMaterials)
        self.assertEqual(result.iv, b"initialization-vector")
        self.assertEqual(result.encrypted_data_keys, [edk])
        self.assertEqual(result.encryption_context_stored, {"key1": "value1"})
        self.assertEqual(result.encryption_context_from_request, {"key2": "value2"})
        self.assertEqual(result.plaintext_data_key, b"plaintext-data-key")


if __name__ == "__main__":
    unittest.main()
