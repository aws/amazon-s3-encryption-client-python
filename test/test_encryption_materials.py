# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from src.s3_encryption.materials.materials import EncryptionMaterials
from src.s3_encryption.materials.encrypted_data_key import EncryptedDataKey

class TestEncryptionMaterials(unittest.TestCase):
    def test_create_encryption_materials(self):
        """Test creating an EncryptionMaterials instance."""
        materials = EncryptionMaterials()
        self.assertEqual(materials.encryption_context, {})
        self.assertIsNone(materials.encrypted_data_key)
        self.assertIsNone(materials.plaintext_data_key)
        
    def test_create_with_encryption_context(self):
        """Test creating an EncryptionMaterials instance with an encryption context."""
        encryption_context = {"key1": "value1", "key2": "value2"}
        materials = EncryptionMaterials(encryption_context=encryption_context)
        self.assertEqual(materials.encryption_context, encryption_context)
        
    def test_from_dict(self):
        """Test creating an EncryptionMaterials instance from a dictionary."""
        edk = EncryptedDataKey(
            key_provider_id=b'S3Keyring',
            key_provider_info="kms+context",
            encrypted_data_key=b'encrypted-data-key'
        )
        materials_dict = {
            'encryption_context': {"key1": "value1"},
            'encrypted_data_key': edk,
            'PDK': b'plaintext-data-key'
        }
        materials = EncryptionMaterials.from_dict(materials_dict)
        self.assertEqual(materials.encryption_context, {"key1": "value1"})
        self.assertEqual(materials.encrypted_data_key, edk)
        self.assertEqual(materials.plaintext_data_key, b'plaintext-data-key')
        
    def test_to_dict(self):
        """Test converting an EncryptionMaterials instance to a dictionary."""
        edk = EncryptedDataKey(
            key_provider_id=b'S3Keyring',
            key_provider_info="kms+context",
            encrypted_data_key=b'encrypted-data-key'
        )
        materials = EncryptionMaterials(
            encryption_context={"key1": "value1"},
            encrypted_data_key=edk,
            plaintext_data_key=b'plaintext-data-key'
        )
        materials_dict = materials.to_dict()
        self.assertEqual(materials_dict['encryption_context'], {"key1": "value1"})
        self.assertEqual(materials_dict['encrypted_data_key'], edk)
        self.assertEqual(materials_dict['PDK'], b'plaintext-data-key')

if __name__ == '__main__':
    unittest.main()
