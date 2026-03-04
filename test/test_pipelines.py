# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import base64
import json
import os
from io import BytesIO
from unittest.mock import Mock

import pytest

from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from s3_encryption.materials.keyring import S3Keyring
from s3_encryption.pipelines import GetEncryptedObjectPipeline


class TestGetEncryptedObjectPipelineInstructionFile:
    ##= specification/s3-encryption/data-format/metadata-strategy.md#v1-v2-instruction-files
    ##= type=test
    ##% In the V1/V2 message format, all of the content metadata
    ##% MUST be stored in the Instruction File.
    def test_decrypt_v1_from_instruction_file(self):
        """Test decrypting V1 format with instruction file."""
        object_metadata = {"x-amz-meta-x-amz-unencrypted-content-length": "39"}

        # Instruction file contains all V1 metadata
        instruction_file_metadata = {
            "x-amz-iv": base64.b64encode(os.urandom(16)).decode("utf-8"),
            "x-amz-key-v2": base64.b64encode(b"encrypted-key-data").decode("utf-8"),
            "x-amz-wrap-alg": "kms",
            "x-amz-matdesc": json.dumps({"kms_cmk_id": "test-key-id"}),
            "x-amz-cek-alg": "AES/CBC/PKCS5Padding",
            "x-amz-crypto-instr-file": "",
        }

        # Create mock S3 client
        mock_s3_client = Mock()
        # Mock returns parsed metadata (simulating event handler behavior)
        mock_s3_client.get_object.return_value = {
            "Body": BytesIO(b""),  # Body is cleared by event handler
            "Metadata": instruction_file_metadata,
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

    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=test
    ##% The default Instruction File behavior uses the same S3 object key
    ##% as its associated object suffixed with ".instruction".
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
            "x-amz-crypto-instr-file": "",
        }

        # Create mock S3 client
        mock_s3_client = Mock()
        # Mock returns parsed metadata (simulating event handler behavior)
        mock_s3_client.get_object.return_value = {
            "Body": BytesIO(b""),  # Body is cleared by event handler
            "Metadata": instruction_file_metadata,
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

    ##= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
    ##= type=test
    ##% In the V3 message format, only the content metadata related to
    ##% the encrypted data is stored in the Instruction File.
    def test_decrypt_v3_from_instruction_file(self):
        """Test decrypting V3 format with instruction file (kms+context wrapping)."""
        # Object metadata contains V3 content keys only
        object_metadata = {
            "x-amz-c": "115",  # Compressed algorithm suite
            "x-amz-d": base64.b64encode(b"key-commitment-data").decode("utf-8"),
            "x-amz-i": base64.b64encode(b"test-message-id").decode("utf-8"),
        }

        # Instruction file contains encrypted data key and wrapping algorithm
        # Uses "12" (kms+context) with "x-amz-t" for encryption context
        instruction_file_metadata = {
            "x-amz-3": base64.b64encode(b"encrypted-key-data").decode("utf-8"),
            "x-amz-w": "12",  # kms+context
            "x-amz-t": json.dumps({"aws:x-amz-cek-alg": "AES/GCM/NoPadding"}),
        }

        # Create mock S3 client
        mock_s3_client = Mock()
        # Mock returns parsed metadata (simulating event handler behavior)
        mock_s3_client.get_object.return_value = {
            "Body": BytesIO(b""),  # Body is cleared by event handler
            "Metadata": instruction_file_metadata,
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

        # V3 decryption is now implemented; with fake commitment data,
        # key commitment verification will fail.
        from s3_encryption.exceptions import S3EncryptionClientSecurityError

        with pytest.raises(
            S3EncryptionClientSecurityError, match="Key commitment verification failed"
        ):
            pipeline.decrypt(mock_response, bucket="test-bucket", key="test-key")

        # Verify instruction file was fetched
        mock_s3_client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key="test-key.instruction"
        )

    def test_decrypt_v3_unsupported_wrap_alg(self):
        """Test that V3 decryption with unsupported wrapping algorithm gives a useful error."""
        from s3_encryption.exceptions import S3EncryptionClientError

        # V3 metadata with AES/GCM wrapping (02) — not supported by this client
        metadata = {
            "x-amz-c": "115",
            "x-amz-3": base64.b64encode(b"encrypted-key-data").decode("utf-8"),
            "x-amz-w": "02",  # AES/GCM — unsupported
            "x-amz-m": json.dumps({"some": "material-desc"}),
            "x-amz-d": base64.b64encode(b"key-commitment-data").decode("utf-8"),
            "x-amz-i": base64.b64encode(b"test-message-id").decode("utf-8"),
       }

        mock_keyring = Mock(spec=S3Keyring)
        cmm = DefaultCryptoMaterialsManager(mock_keyring)
        pipeline = GetEncryptedObjectPipeline(cmm)

        mock_response = {
            "Body": BytesIO(b"encrypted-test-data"),
            "Metadata": metadata,
        }

        with pytest.raises(
            S3EncryptionClientError, match="Unsupported wrapping algorithm: AES/GCM"
        ):
            pipeline.decrypt(mock_response)


    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=test
    ##% The S3EC SHOULD support providing a custom Instruction File suffix
    ##% on GetObject requests, regardless of whether or not re-encryption is supported.
    def test_decrypt_with_custom_instruction_file_suffix(self):
        """Test that a custom instruction file suffix is used when provided."""
        object_metadata = {}

        instruction_file_metadata = {
            "x-amz-iv": base64.b64encode(os.urandom(12)).decode("utf-8"),
            "x-amz-key-v2": base64.b64encode(b"encrypted-key-data").decode("utf-8"),
            "x-amz-wrap-alg": "kms+context",
            "x-amz-matdesc": json.dumps({"kms_cmk_id": "test-key-id"}),
            "x-amz-cek-alg": "AES/GCM/NoPadding",
            "x-amz-tag-len": "128",
            "x-amz-crypto-instr-file": "",
        }

        mock_s3_client = Mock()
        mock_s3_client.get_object.return_value = {
            "Body": BytesIO(b""),
            "Metadata": instruction_file_metadata,
        }

        mock_keyring = Mock(spec=S3Keyring)
        cmm = DefaultCryptoMaterialsManager(mock_keyring)
        pipeline = GetEncryptedObjectPipeline(cmm)

        mock_response = {
            "Body": BytesIO(b"encrypted-test-data"),
            "Metadata": metadata,
        }

        mock_keyring.on_decrypt.side_effect = Exception(
            "Keyring called - instruction file was fetched"
        )

        with pytest.raises(Exception, match="Keyring called"):
            pipeline.decrypt(
                mock_response,
                bucket="test-bucket",
                key="test-key",
                instruction_suffix=".custom-suffix",
            )

        mock_s3_client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key="test-key.custom-suffix"
        )