# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import MagicMock, patch
from src.s3_encryption.materials.materials import DecryptionMaterials
from src.s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from src.s3_encryption.materials.keyring import S3Keyring
from src.s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager

class TestDecryptionMaterialsIntegration(unittest.TestCase):
    def test_keyring_onDecrypt(self):
        """Test that S3Keyring.onDecrypt properly handles DecryptionMaterials."""
        # Create a keyring
        keyring = S3Keyring()
        
        # Create an encrypted data key
        edk = EncryptedDataKey(
            key_provider_id=b'S3Keyring',
            key_provider_info="kms+context",
            encrypted_data_key=b'encrypted-data-key'
        )
        
        # Create decryption materials
        materials = DecryptionMaterials(
            iv=b'initialization-vector',
            encrypted_data_keys=[edk],
            encryption_context_stored={"key1": "value1"},
            encryption_context_from_request={"key2": "value2"}
        )
        
        # Mock the validation method to return the materials
        with patch.object(S3Keyring, 'onDecrypt', return_value=materials) as mock_onDecrypt:
            # Call onDecrypt
            result = keyring.onDecrypt(materials, [edk])
            
            # Verify the result is a DecryptionMaterials instance
            self.assertIsInstance(result, DecryptionMaterials)
            self.assertEqual(result.iv, b'initialization-vector')
            self.assertEqual(result.encrypted_data_keys, [edk])
            self.assertEqual(result.encryption_context_stored, {"key1": "value1"})
            self.assertEqual(result.encryption_context_from_request, {"key2": "value2"})
        
    def test_keyring_onDecrypt_default_EC(self):
        """Test that S3Keyring.onDecrypt properly handles DecryptionMaterials."""
        # Create a keyring
        keyring = S3Keyring()
        
        # Create an encrypted data key
        edk = EncryptedDataKey(
            key_provider_id=b'S3Keyring',
            key_provider_info="kms+context",
            encrypted_data_key=b'encrypted-data-key'
        )
        
        # Create decryption materials
        materials = DecryptionMaterials(
            iv=b'initialization-vector',
            encrypted_data_keys=[edk],
            encryption_context_stored={},
            encryption_context_from_request={}
        )
        
        # Mock the validation method to return the materials
        with patch.object(S3Keyring, 'onDecrypt', return_value=materials) as mock_onDecrypt:
            # Call onDecrypt
            result = keyring.onDecrypt(materials, [edk])
            
            # Verify the result is a DecryptionMaterials instance
            self.assertIsInstance(result, DecryptionMaterials)
            self.assertEqual(result.iv, b'initialization-vector')
            self.assertEqual(result.encrypted_data_keys, [edk])
            self.assertEqual(result.encryption_context_stored, {})
            self.assertEqual(result.encryption_context_from_request, {})
        
    def test_cmm_decryptMaterials_with_dict(self):
        """Test that DefaultCryptoMaterialsManager.decryptMaterials properly handles dictionary input."""
        # Create a mock keyring
        keyring = MagicMock()
        edk = EncryptedDataKey(
            key_provider_id=b'S3Keyring',
            key_provider_info="kms+context",
            encrypted_data_key=b'encrypted-data-key'
        )
        keyring.onDecrypt.return_value = DecryptionMaterials(
            iv=b'initialization-vector',
            encrypted_data_keys=[edk],
            encryption_context_stored={"key1": "value1"},
            encryption_context_from_request={"key2": "value2"},
            plaintext_data_key=b'plaintext-data-key'
        )
        
        # Create a CMM
        cmm = DefaultCryptoMaterialsManager(keyring=keyring)
        
        # Call decryptMaterials with a dictionary
        result = cmm.decryptMaterials({
            'iv': b'initialization-vector',
            'encrypted_data_keys': [edk],
            'encryption_context_stored': {"key1": "value1"},
            'encryption_context_from_request': {"key2": "value2"}
        })
        
        # Verify the result is a DecryptionMaterials instance
        self.assertIsInstance(result, DecryptionMaterials)
        self.assertEqual(result.iv, b'initialization-vector')
        self.assertEqual(result.encrypted_data_keys, [edk])
        self.assertEqual(result.encryption_context_stored, {"key1": "value1"})
        self.assertEqual(result.encryption_context_from_request, {"key2": "value2"})
        self.assertEqual(result.plaintext_data_key, b'plaintext-data-key')
        
    def test_cmm_decryptMaterials_with_materials(self):
        """Test that DefaultCryptoMaterialsManager.decryptMaterials properly handles DecryptionMaterials input."""
        # Create a mock keyring
        keyring = MagicMock()
        edk = EncryptedDataKey(
            key_provider_id=b'S3Keyring',
            key_provider_info="kms+context",
            encrypted_data_key=b'encrypted-data-key'
        )
        keyring.onDecrypt.return_value = DecryptionMaterials(
            iv=b'initialization-vector',
            encrypted_data_keys=[edk],
            encryption_context_stored={"key1": "value1"},
            encryption_context_from_request={"key2": "value2"},
            plaintext_data_key=b'plaintext-data-key'
        )
        
        # Create a CMM
        cmm = DefaultCryptoMaterialsManager(keyring=keyring)
        
        # Call decryptMaterials with a DecryptionMaterials instance
        materials = DecryptionMaterials(
            iv=b'initialization-vector',
            encrypted_data_keys=[edk],
            encryption_context_stored={"key1": "value1"},
            encryption_context_from_request={"key2": "value2"}
        )
        result = cmm.decryptMaterials(materials)
        
        # Verify the result is a DecryptionMaterials instance
        self.assertIsInstance(result, DecryptionMaterials)
        self.assertEqual(result.iv, b'initialization-vector')
        self.assertEqual(result.encrypted_data_keys, [edk])
        self.assertEqual(result.encryption_context_stored, {"key1": "value1"})
        self.assertEqual(result.encryption_context_from_request, {"key2": "value2"})
        self.assertEqual(result.plaintext_data_key, b'plaintext-data-key')

if __name__ == '__main__':
    unittest.main()
