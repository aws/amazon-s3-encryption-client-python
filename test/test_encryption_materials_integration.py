# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import MagicMock, patch

from src.s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from src.s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from src.s3_encryption.materials.keyring import S3Keyring
from src.s3_encryption.materials.materials import EncryptionMaterials


class TestEncryptionMaterialsIntegration(unittest.TestCase):
    def test_keyring_onEncrypt(self):
        """Test that S3Keyring.onEncrypt properly handles EncryptionMaterials."""
        # Create a keyring
        keyring = S3Keyring()

        # Create encryption materials
        materials = EncryptionMaterials(encryption_context={"key1": "value1"})

        # Call onEncrypt
        result = keyring.onEncrypt(materials)

        # Verify the result is an EncryptionMaterials instance
        self.assertIsInstance(result, EncryptionMaterials)
        self.assertEqual(result.encryption_context, {"key1": "value1"})

    def test_cmm_getEncryptionMaterials_with_dict(self):
        """Test that DefaultCryptoMaterialsManager.getEncryptionMaterials properly handles dictionary input."""
        # Create a mock keyring
        keyring = MagicMock()
        keyring.onEncrypt.return_value = EncryptionMaterials(
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

        # Call getEncryptionMaterials with a dictionary
        result = cmm.getEncryptionMaterials({"encryption_context": {"key1": "value1"}})

        # Verify the result is an EncryptionMaterials instance
        self.assertIsInstance(result, EncryptionMaterials)
        self.assertEqual(result.encryption_context, {"key1": "value1"})
        self.assertIsNotNone(result.encrypted_data_key)
        self.assertIsNotNone(result.plaintext_data_key)

    def test_cmm_getEncryptionMaterials_with_materials(self):
        """Test that DefaultCryptoMaterialsManager.getEncryptionMaterials properly handles EncryptionMaterials input."""
        # Create a mock keyring
        keyring = MagicMock()
        keyring.onEncrypt.return_value = EncryptionMaterials(
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

        # Call getEncryptionMaterials with an EncryptionMaterials instance
        materials = EncryptionMaterials(encryption_context={"key1": "value1"})
        result = cmm.getEncryptionMaterials(materials)

        # Verify the result is an EncryptionMaterials instance
        self.assertIsInstance(result, EncryptionMaterials)
        self.assertEqual(result.encryption_context, {"key1": "value1"})
        self.assertIsNotNone(result.encrypted_data_key)
        self.assertIsNotNone(result.plaintext_data_key)


if __name__ == "__main__":
    unittest.main()
