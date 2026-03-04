# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for S3EncryptionClientPlugin event handlers."""

import io
import json
from unittest.mock import Mock

import pytest
from botocore.response import StreamingBody

from s3_encryption import S3EncryptionClientConfig, S3EncryptionClientPlugin
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.keyring import S3Keyring


class TestS3EncryptionClientPlugin:
    """S3EncryptionClientPlugin event handler behavior."""

    def test_instruction_file_mode_parses_instruction_file(self):
        """Test that plaintext mode parses instruction file and returns metadata."""
        # Create plugin
        mock_keyring = Mock(spec=S3Keyring)
        config = S3EncryptionClientConfig(keyring=mock_keyring)
        plugin = S3EncryptionClientPlugin(config)

        # Set plaintext mode
        plugin._context.instruction_file_mode = True
        plugin._context.key = "test-key.instruction"

        # Create instruction file body
        instruction_metadata = {
            "x-amz-iv": "test-iv",
            "x-amz-key-v2": "test-key",
            "x-amz-wrap-alg": "kms+context",
            "x-amz-cek-alg": "AES/GCM/NoPadding",
        }
        instruction_body = json.dumps(instruction_metadata).encode("utf-8")

        # Create parsed response with instruction file marker in S3 metadata
        parsed = {
            "Body": StreamingBody(io.BytesIO(instruction_body), len(instruction_body)),
            "Metadata": {"x-amz-crypto-instr-file": ""},
        }

        # Call event handler
        plugin.on_get_object_after_call(parsed)

        # Verify metadata was updated with parsed instruction file
        assert parsed["Metadata"]["x-amz-iv"] == "test-iv"
        assert parsed["Metadata"]["x-amz-key-v2"] == "test-key"
        assert parsed["Metadata"]["x-amz-wrap-alg"] == "kms+context"
        assert parsed["Metadata"]["x-amz-cek-alg"] == "AES/GCM/NoPadding"
        assert parsed["Metadata"]["x-amz-crypto-instr-file"] == ""

        # Verify body was cleared
        assert parsed["Body"].read() == b""

    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=test
    ##% The content metadata stored in the Instruction File MUST be serialized to a JSON string.
    def test_instruction_file_mode_invalid_json_raises_error(self):
        """Test that invalid JSON in instruction file raises error."""
        # Create plugin
        mock_keyring = Mock(spec=S3Keyring)
        config = S3EncryptionClientConfig(keyring=mock_keyring)
        plugin = S3EncryptionClientPlugin(config)

        # Set plaintext mode
        plugin._context.instruction_file_mode = True
        plugin._context.key = "test-key.instruction"

        # Create invalid JSON body
        invalid_body = b"not valid json"

        # Create parsed response
        parsed = {
            "Body": StreamingBody(io.BytesIO(invalid_body), len(invalid_body)),
            "Metadata": {"x-amz-crypto-instr-file": ""},
        }

        # Should raise error
        with pytest.raises(S3EncryptionClientError, match="Instruction file is not valid JSON"):
            plugin.on_get_object_after_call(parsed)

    def test_instruction_file_mode_non_dict_json_raises_error(self):
        """Test that non-dict JSON in instruction file raises error."""
        # Create plugin
        mock_keyring = Mock(spec=S3Keyring)
        config = S3EncryptionClientConfig(keyring=mock_keyring)
        plugin = S3EncryptionClientPlugin(config)

        # Set plaintext mode
        plugin._context.instruction_file_mode = True
        plugin._context.key = "test-key.instruction"

        # Create JSON array instead of object
        invalid_body = json.dumps(["not", "a", "dict"]).encode("utf-8")

        # Create parsed response
        parsed = {
            "Body": StreamingBody(io.BytesIO(invalid_body), len(invalid_body)),
            "Metadata": {"x-amz-crypto-instr-file": ""},
        }

        # Should raise error
        with pytest.raises(
            S3EncryptionClientError, match="Instruction file must contain a JSON object"
        ):
            plugin.on_get_object_after_call(parsed)

    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=test
    ##% The serialized JSON string MUST be the only contents of the Instruction File.
    def test_instruction_file_mode_invalid_keys_raises_error(self):
        """Test that invalid keys in instruction file raises error."""
        # Create plugin
        mock_keyring = Mock(spec=S3Keyring)
        config = S3EncryptionClientConfig(keyring=mock_keyring)
        plugin = S3EncryptionClientPlugin(config)

        # Set plaintext mode
        plugin._context.instruction_file_mode = True
        plugin._context.key = "test-key.instruction"

        # Create instruction file with invalid keys
        instruction_metadata = {
            "x-amz-iv": "test-iv",
            "invalid-key": "should-not-be-here",
        }
        instruction_body = json.dumps(instruction_metadata).encode("utf-8")

        # Create parsed response
        parsed = {
            "Body": StreamingBody(io.BytesIO(instruction_body), len(instruction_body)),
            "Metadata": {"x-amz-crypto-instr-file": ""},
        }

        # Should raise error
        with pytest.raises(S3EncryptionClientError, match="Instruction file contains invalid keys"):
            plugin.on_get_object_after_call(parsed)
