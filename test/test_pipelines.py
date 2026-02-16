# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import base64
import json
import os
import sys
from io import BytesIO
from unittest.mock import Mock

import pytest

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from s3_encryption.materials.keyring import S3Keyring
from s3_encryption.pipelines import GetEncryptedObjectPipeline


class TestGetEncryptedObjectPipelineInstructionFile:
    def test_decrypt_v1_from_instruction_file(self):
        """Test decrypting V1 format with instruction file."""
        # V1: Object metadata is empty, all metadata in instruction file
        object_metadata = {}

        # Instruction file contains all V1 metadata
        instruction_file_metadata = {
            "x-amz-iv": base64.b64encode(os.urandom(16)).decode("utf-8"),
            "x-amz-key-v2": base64.b64encode(b"encrypted-key-data").decode("utf-8"),
            "x-amz-wrap-alg": "kms",
            "x-amz-matdesc": json.dumps({"kms_cmk_id": "test-key-id"}),
            "x-amz-cek-alg": "AES/CBC/PKCS5Padding",
        }

        # Create mock S3 client
        mock_s3_client = Mock()
        instruction_file_body = BytesIO(json.dumps(instruction_file_metadata).encode("utf-8"))
        mock_s3_client.get_object.return_value = {
            "Body": instruction_file_body,
            "Metadata": {"x-amz-crypto-instr-file": ""},
        }

        # Create mock keyring and CMM
        mock_keyring = Mock(spec=S3Keyring)
        cmm = DefaultCryptoMaterialsManager(mock_keyring)

        # Create pipeline with mocked S3 client
        pipeline = GetEncryptedObjectPipeline(cmm, mock_s3_client)

        # Create mock response
        mock_response = {
            "Body": BytesIO(b"encrypted-test-data"),
            "Metadata": object_metadata,
        }

        # Mock the keyring to raise an error so we don't actually decrypt
        mock_keyring.on_decrypt.side_effect = Exception(
            "Keyring called - instruction file was fetched"
        )

        # Should fail when trying to decrypt (proving instruction file was fetched)
        with pytest.raises(Exception, match="Keyring called"):
            pipeline.decrypt(mock_response, bucket="test-bucket", key="test-key")

        # Verify instruction file was fetched
        mock_s3_client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key="test-key.instruction"
        )

    def test_decrypt_v2_from_instruction_file(self):
        """Test decrypting V2 format with instruction file."""
        # V2: Object metadata is empty, all metadata in instruction file
        object_metadata = {}

        # Instruction file contains all V2 metadata
        instruction_file_metadata = {
            "x-amz-iv": base64.b64encode(os.urandom(12)).decode("utf-8"),
            "x-amz-key-v2": base64.b64encode(b"encrypted-key-data").decode("utf-8"),
            "x-amz-wrap-alg": "kms+context",
            "x-amz-matdesc": json.dumps({"kms_cmk_id": "test-key-id"}),
            "x-amz-cek-alg": "AES/GCM/NoPadding",
            "x-amz-tag-len": "128",
        }

        # Create mock S3 client
        mock_s3_client = Mock()
        instruction_file_body = BytesIO(json.dumps(instruction_file_metadata).encode("utf-8"))
        mock_s3_client.get_object.return_value = {
            "Body": instruction_file_body,
            "Metadata": {"x-amz-crypto-instr-file": ""},
        }

        # Create mock keyring and CMM
        mock_keyring = Mock(spec=S3Keyring)
        cmm = DefaultCryptoMaterialsManager(mock_keyring)

        # Create pipeline with mocked S3 client
        pipeline = GetEncryptedObjectPipeline(cmm, mock_s3_client)

        # Create mock response
        mock_response = {
            "Body": BytesIO(b"encrypted-test-data"),
            "Metadata": object_metadata,
        }

        # Mock the keyring to raise an error so we don't actually decrypt
        mock_keyring.on_decrypt.side_effect = Exception(
            "Keyring called - instruction file was fetched"
        )

        # Should fail when trying to decrypt (proving instruction file was fetched)
        with pytest.raises(Exception, match="Keyring called"):
            pipeline.decrypt(mock_response, bucket="test-bucket", key="test-key")

        # Verify instruction file was fetched
        mock_s3_client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key="test-key.instruction"
        )

    def test_decrypt_v3_from_instruction_file(self):
        """Test decrypting V3 format with instruction file."""
        # Object metadata contains V3 content keys only
        object_metadata = {
            "x-amz-c": "115",  # Compressed algorithm suite
            "x-amz-d": base64.b64encode(b"key-commitment-data").decode("utf-8"),
            "x-amz-i": base64.b64encode(b"test-message-id").decode("utf-8"),
        }

        # Instruction file contains encrypted data key and wrapping algorithm
        instruction_file_metadata = {
            "x-amz-3": base64.b64encode(b"encrypted-key-data").decode("utf-8"),
            "x-amz-w": "02",  # AES/GCM
            "x-amz-m": json.dumps({"test-instruction": "material-desc-instruction"}),
        }

        # Create mock S3 client
        mock_s3_client = Mock()
        instruction_file_body = BytesIO(json.dumps(instruction_file_metadata).encode("utf-8"))
        mock_s3_client.get_object.return_value = {
            "Body": instruction_file_body,
            "Metadata": {"x-amz-crypto-instr-file": ""},
        }

        # Create mock keyring and CMM
        mock_keyring = Mock(spec=S3Keyring)
        cmm = DefaultCryptoMaterialsManager(mock_keyring)

        # Create pipeline with mocked S3 client
        pipeline = GetEncryptedObjectPipeline(cmm, mock_s3_client)

        # Create mock response with encrypted data
        iv = os.urandom(12)
        encrypted_data = b"encrypted-test-data"

        mock_response = {
            "Body": BytesIO(encrypted_data),
            "Metadata": object_metadata,
        }

        # Mock the keyring to return decryption materials
        from s3_encryption.materials.materials import DecryptionMaterials

        plaintext_data_key = os.urandom(32)

        mock_dec_materials = DecryptionMaterials(
            iv=iv,
            encrypted_data_keys=[],
            encryption_context_stored={},
            encryption_context_from_request={},
        )
        mock_dec_materials.plaintext_data_key = plaintext_data_key

        mock_keyring.on_decrypt.return_value = mock_dec_materials

        # This should fail with NotImplementedError since V3 decryption isn't implemented yet
        with pytest.raises(NotImplementedError, match="V3 decryption not yet implemented"):
            pipeline.decrypt(mock_response, bucket="test-bucket", key="test-key")

        # Verify instruction file was fetched
        mock_s3_client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key="test-key.instruction"
        )
