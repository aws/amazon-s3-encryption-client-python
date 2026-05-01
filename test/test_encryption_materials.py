# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


from src.s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from src.s3_encryption.materials.materials import EncryptionMaterials


class TestEncryptionMaterials:
    def test_create_encryption_materials(self):
        """Test creating an EncryptionMaterials instance."""
        materials = EncryptionMaterials()
        assert materials.encryption_context == {}
        assert materials.encrypted_data_key is None
        assert materials.plaintext_data_key is None

    def test_create_with_encryption_context(self):
        """Test creating an EncryptionMaterials instance with an encryption context."""
        encryption_context = {"key1": "value1", "key2": "value2"}
        materials = EncryptionMaterials(encryption_context=encryption_context)
        assert materials.encryption_context == encryption_context

    def test_from_dict(self):
        """Test creating an EncryptionMaterials instance from a dictionary."""
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-data-key",
        )
        materials_dict = {
            "encryption_context": {"key1": "value1"},
            "encrypted_data_key": edk,
            "plaintext_data_key": b"plaintext-data-key",
        }
        materials = EncryptionMaterials.from_dict(materials_dict)
        assert materials.encryption_context == {"key1": "value1"}
        assert materials.encrypted_data_key == edk
        assert materials.plaintext_data_key == b"plaintext-data-key"

    def test_to_dict(self):
        """Test converting an EncryptionMaterials instance to a dictionary."""
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-data-key",
        )
        materials = EncryptionMaterials(
            encryption_context={"key1": "value1"},
            encrypted_data_key=edk,
            plaintext_data_key=b"plaintext-data-key",
        )
        materials_dict = materials.to_dict()
        assert materials_dict["encryption_context"] == {"key1": "value1"}
        assert materials_dict["encrypted_data_key"] == edk
        assert materials_dict["plaintext_data_key"] == b"plaintext-data-key"

    def test_from_dict_with_none_encryption_context(self):
        """EncryptionMaterials.from_dict should handle None encryption_context."""
        materials_dict = {
            "encryption_context": None,
            "encrypted_data_key": None,
            "plaintext_data_key": None,
        }
        materials = EncryptionMaterials.from_dict(materials_dict)
        assert materials.encryption_context == {}

    def test_from_dict_with_missing_encryption_context(self):
        """EncryptionMaterials.from_dict should default to {} when key is missing."""
        materials_dict = {}
        materials = EncryptionMaterials.from_dict(materials_dict)
        assert materials.encryption_context == {}
