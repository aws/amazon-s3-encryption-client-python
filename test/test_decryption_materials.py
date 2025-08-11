# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from src.s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from src.s3_encryption.materials.materials import DecryptionMaterials


class TestDecryptionMaterials:
    def test_create_decryption_materials(self):
        """Test creating a DecryptionMaterials instance."""
        materials = DecryptionMaterials()
        assert materials.encrypted_data_keys == []
        assert materials.encryption_context_stored == {}
        assert materials.encryption_context_from_request == {}
        assert materials.iv is None
        assert materials.plaintext_data_key is None

    def test_create_with_parameters(self):
        """Test creating a DecryptionMaterials instance with parameters."""
        iv = b"initialization-vector"
        encrypted_data_keys = [
            EncryptedDataKey(
                key_provider_id=b"S3Keyring",
                key_provider_info="kms+context",
                encrypted_data_key=b"encrypted-data-key",
            )
        ]
        encryption_context_stored = {"key1": "value1"}
        encryption_context_from_request = {"key2": "value2"}
        plaintext_data_key = b"plaintext-data-key"

        materials = DecryptionMaterials(
            iv=iv,
            encrypted_data_keys=encrypted_data_keys,
            encryption_context_stored=encryption_context_stored,
            encryption_context_from_request=encryption_context_from_request,
            plaintext_data_key=plaintext_data_key,
        )

        assert materials.iv == iv
        assert materials.encrypted_data_keys == encrypted_data_keys
        assert materials.encryption_context_stored == encryption_context_stored
        assert materials.encryption_context_from_request == encryption_context_from_request
        assert materials.plaintext_data_key == plaintext_data_key

    def test_from_dict(self):
        """Test creating a DecryptionMaterials instance from a dictionary."""
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-data-key",
        )
        materials_dict = {
            "iv": b"initialization-vector",
            "encrypted_data_keys": [edk],
            "encryption_context_stored": {"key1": "value1"},
            "encryption_context_from_request": {"key2": "value2"},
            "PDK": b"plaintext-data-key",
        }
        materials = DecryptionMaterials.from_dict(materials_dict)
        assert materials.iv == b"initialization-vector"
        assert materials.encrypted_data_keys == [edk]
        assert materials.encryption_context_stored == {"key1": "value1"}
        assert materials.encryption_context_from_request == {"key2": "value2"}
        assert materials.plaintext_data_key == b"plaintext-data-key"

    def test_to_dict(self):
        """Test converting a DecryptionMaterials instance to a dictionary."""
        edk = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=b"encrypted-data-key",
        )
        materials = DecryptionMaterials(
            iv=b"initialization-vector",
            encrypted_data_keys=[edk],
            encryption_context_stored={"key1": "value1"},
            encryption_context_from_request={"key2": "value2"},
            plaintext_data_key=b"plaintext-data-key",
        )
        materials_dict = materials.to_dict()
        assert materials_dict["iv"] == b"initialization-vector"
        assert materials_dict["encrypted_data_keys"] == [edk]
        assert materials_dict["encryption_context_stored"] == {"key1": "value1"}
        assert materials_dict["encryption_context_from_request"] == {"key2": "value2"}
        assert materials_dict["PDK"] == b"plaintext-data-key"
