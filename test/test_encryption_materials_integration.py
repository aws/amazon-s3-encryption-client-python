# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import MagicMock

from src.s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from src.s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from src.s3_encryption.materials.keyring import S3Keyring
from src.s3_encryption.materials.materials import EncryptionMaterials


class TestEncryptionMaterialsIntegration(unittest.TestCase):
    def test_keyring_on_encrypt(self):
        """Test that S3Keyring.on_encrypt properly handles EncryptionMaterials."""
        # Create a keyring
        keyring = S3Keyring()

        # Create encryption materials
        materials = EncryptionMaterials(encryption_context={"key1": "value1"})

        # Call on_encrypt
        result = keyring.on_encrypt(materials)

        # Verify the result is an EncryptionMaterials instance
        self.assertIsInstance(result, EncryptionMaterials)
        self.assertEqual(result.encryption_context, {"key1": "value1"})

    def test_cmm_get_encryption_materials_with_dict(self):
        """Test that DefaultCryptoMaterialsManager.get_encryption_materials properly handles dictionary input."""
        # Create a mock keyring
        keyring = MagicMock()
        keyring.on_encrypt.return_value = EncryptionMaterials(
            encryption_context={"key1": "value1"},
            encrypted_data_key=EncryptedDataKey(
                key_provider_id=b"S3Keyring",
                key_provider_info="kms+context",
                encrypted_data_key=b"encrypted-data-key",
            ),
            plaintext_data_key=b"plaintext-data-key",
        )

        # Create a CMM
        cmm = DefaultCryptoMaterialsManager(keyring=keyring)

        # Call get_encryption_materials with a dictionary
        result = cmm.get_encryption_materials({"encryption_context": {"key1": "value1"}})

        # Verify the result is an EncryptionMaterials instance
        self.assertIsInstance(result, EncryptionMaterials)
        self.assertEqual(result.encryption_context, {"key1": "value1"})
        self.assertIsNotNone(result.encrypted_data_key)
        self.assertIsNotNone(result.plaintext_data_key)

    def test_cmm_get_encryption_materials_with_materials(self):
        """Test that DefaultCryptoMaterialsManager.get_encryption_materials properly handles EncryptionMaterials input."""
        # Create a mock keyring
        keyring = MagicMock()
        keyring.on_encrypt.return_value = EncryptionMaterials(
            encryption_context={"key1": "value1"},
            encrypted_data_key=EncryptedDataKey(
                key_provider_id=b"S3Keyring",
                key_provider_info="kms+context",
                encrypted_data_key=b"encrypted-data-key",
            ),
            plaintext_data_key=b"plaintext-data-key",
        )

        # Create a CMM
        cmm = DefaultCryptoMaterialsManager(keyring=keyring)

        # Call get_encryption_materials with an EncryptionMaterials instance
        materials = EncryptionMaterials(encryption_context={"key1": "value1"})
        result = cmm.get_encryption_materials(materials)

        # Verify the result is an EncryptionMaterials instance
        self.assertIsInstance(result, EncryptionMaterials)
        self.assertEqual(result.encryption_context, {"key1": "value1"})
        self.assertIsNotNone(result.encrypted_data_key)
        self.assertIsNotNone(result.plaintext_data_key)


if __name__ == "__main__":
    unittest.main()
