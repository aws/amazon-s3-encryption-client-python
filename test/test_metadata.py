# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
import sys

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from s3_encryption.metadata import ObjectMetadata


class TestObjectMetadata:
    def test_from_dict(self):
        # Create a metadata dictionary
        metadata_dict = {
            "x-amz-key-v2": "encrypted-key-data",
            "x-amz-wrap-alg": "kms+context",
            "x-amz-iv": "base64-encoded-iv",
            "x-amz-cek-alg": "AES/GCM/NoPadding",
        }

        # Create an ObjectMetadata instance from the dictionary
        metadata = ObjectMetadata.from_dict(metadata_dict)

        # Verify that the fields were populated correctly
        assert metadata.encrypted_data_key_v2 == "encrypted-key-data"
        assert metadata.encrypted_data_key_algorithm == "kms+context"
        assert metadata.content_iv == "base64-encoded-iv"
        assert metadata.content_cipher == "AES/GCM/NoPadding"

        # Verify that fields not in the dictionary are None
        assert metadata.encrypted_data_key_v1 is None
        assert metadata.encrypted_data_key_context is None
        # Note: content_cipher_tag_length is None because it's not in the input dictionary
        assert metadata.content_cipher_tag_length is None
        assert metadata.instruction_file is None

    def test_to_dict(self):
        # Create an ObjectMetadata instance with some fields set
        metadata = ObjectMetadata(
            encrypted_data_key_v2="encrypted-key-data",
            encrypted_data_key_algorithm="kms+context",
            content_iv="base64-encoded-iv",
            content_cipher="AES/GCM/NoPadding",
        )

        # Convert to dictionary
        metadata_dict = metadata.to_dict()

        # Verify that the dictionary contains the expected keys and values
        assert metadata_dict["x-amz-key-v2"] == "encrypted-key-data"
        assert metadata_dict["x-amz-wrap-alg"] == "kms+context"
        assert metadata_dict["x-amz-iv"] == "base64-encoded-iv"
        assert metadata_dict["x-amz-cek-alg"] == "AES/GCM/NoPadding"

        # Verify that fields that are None are not included in the dictionary
        assert "x-amz-key" not in metadata_dict
        assert "x-amz-matdesc" not in metadata_dict
        # content_cipher_tag_length defaults to "128" for V1/V2
        assert metadata_dict.get("x-amz-tag-len") == "128"
        assert "x-amz-crypto-instr-file" not in metadata_dict

    def test_roundtrip(self):
        # Create a metadata dictionary
        original_dict = {
            "x-amz-key-v2": "encrypted-key-data",
            "x-amz-wrap-alg": "kms+context",
            "x-amz-iv": "base64-encoded-iv",
            "x-amz-cek-alg": "AES/GCM/NoPadding",
        }

        # Convert to ObjectMetadata and back to dictionary
        metadata = ObjectMetadata.from_dict(original_dict)
        result_dict = metadata.to_dict()

        # Remove the tag length field which has a default value
        if "x-amz-tag-len" in result_dict:
            result_dict.pop("x-amz-tag-len")

        # Verify that the result matches the original
        assert result_dict == original_dict

    def test_from_dict_v3_fields(self):
        # Create a metadata dictionary with V3 fields
        metadata_dict = {
            "x-amz-c": "02",
            "x-amz-3": "encrypted-key-v3",
            "x-amz-w": "12",
            "x-amz-d": "key-commitment",
            "x-amz-i": "message-id",
            "x-amz-m": "mat-desc",
            "x-amz-t": "encryption-context",
        }

        metadata = ObjectMetadata.from_dict(metadata_dict)

        assert metadata.content_cipher_v3 == "02"
        assert metadata.encrypted_data_key_v3 == "encrypted-key-v3"
        assert metadata.encrypted_data_key_algorithm_v3 == "12"
        assert metadata.key_commitment_v3 == "key-commitment"
        assert metadata.message_id_v3 == "message-id"
        assert metadata.mat_desc_v3 == "mat-desc"
        assert metadata.encryption_context_v3 == "encryption-context"

    def test_to_dict_v3_fields(self):
        # Create an ObjectMetadata instance with V3 fields
        metadata = ObjectMetadata(
            content_cipher_v3="02",
            encrypted_data_key_v3="encrypted-key-v3",
            encrypted_data_key_algorithm_v3="12",
            key_commitment_v3="key-commitment",
            message_id_v3="message-id",
            mat_desc_v3="mat-desc",
            encryption_context_v3="encryption-context",
        )

        metadata_dict = metadata.to_dict()

        assert metadata_dict["x-amz-c"] == "02"
        assert metadata_dict["x-amz-3"] == "encrypted-key-v3"
        assert metadata_dict["x-amz-w"] == "12"
        assert metadata_dict["x-amz-d"] == "key-commitment"
        assert metadata_dict["x-amz-i"] == "message-id"
        assert metadata_dict["x-amz-m"] == "mat-desc"
        assert metadata_dict["x-amz-t"] == "encryption-context"

        # V3 metadata must NOT include V1/V2-only keys like x-amz-tag-len
        assert "x-amz-tag-len" not in metadata_dict

    def test_is_v1_format(self):
        metadata = ObjectMetadata(
            content_iv="iv",
            encrypted_data_key_context={"key": "value"},
            encrypted_data_key_v1="edk-v1",
        )
        assert metadata.is_v1_format() is True

        # V2 key present should return False
        metadata_v2 = ObjectMetadata(
            content_iv="iv",
            encrypted_data_key_context={"key": "value"},
            encrypted_data_key_v1="edk-v1",
            encrypted_data_key_v2="edk-v2",
        )
        assert metadata_v2.is_v1_format() is False

    def test_is_v2_format(self):
        metadata = ObjectMetadata(
            content_cipher="AES/GCM/NoPadding",
            content_iv="iv",
            encrypted_data_key_algorithm="kms+context",
            encrypted_data_key_v2="edk-v2",
        )
        assert metadata.is_v2_format() is True

        # V1 key present should return False
        metadata_v1 = ObjectMetadata(
            content_cipher="AES/GCM/NoPadding",
            content_iv="iv",
            encrypted_data_key_algorithm="kms+context",
            encrypted_data_key_v2="edk-v2",
            encrypted_data_key_v1="edk-v1",
        )
        assert metadata_v1.is_v2_format() is False

    def test_is_v3_format(self):
        metadata = ObjectMetadata(
            content_cipher_v3="02",
            encrypted_data_key_algorithm_v3="12",
            key_commitment_v3="commitment",
            message_id_v3="msg-id",
            encrypted_data_key_v3="edk-v3",
        )
        assert metadata.is_v3_format() is True

        # V1 or V2 keys present should return False
        metadata_v2 = ObjectMetadata(
            content_cipher_v3="02",
            encrypted_data_key_algorithm_v3="12",
            key_commitment_v3="commitment",
            message_id_v3="msg-id",
            encrypted_data_key_v3="edk-v3",
            encrypted_data_key_v2="edk-v2",
        )
        assert metadata_v2.is_v3_format() is False

    def test_has_exclusive_key_collision(self):
        # No collision - only V2
        metadata_v2 = ObjectMetadata(encrypted_data_key_v2="edk-v2")
        assert metadata_v2.has_exclusive_key_collision() is False

        # Collision - V1 and V2
        metadata_collision = ObjectMetadata(
            encrypted_data_key_v1="edk-v1",
            encrypted_data_key_v2="edk-v2",
        )
        assert metadata_collision.has_exclusive_key_collision() is True

        # Collision - all three
        metadata_all = ObjectMetadata(
            encrypted_data_key_v1="edk-v1",
            encrypted_data_key_v2="edk-v2",
            encrypted_data_key_v3="edk-v3",
        )
        assert metadata_all.has_exclusive_key_collision() is True
