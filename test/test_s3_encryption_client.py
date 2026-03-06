# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for S3EncryptionClient get_object error handling."""

from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.keyring import S3Keyring


class TestGetObjectNonExistentObject:
    """S3EncryptionClient wraps S3 errors with context, preserving the original cause."""

    def _build_client(self):
        mock_s3 = Mock()
        mock_s3.meta.events = Mock()
        mock_s3.meta.events.register = Mock()
        mock_keyring = Mock(spec=S3Keyring)
        config = S3EncryptionClientConfig(keyring=mock_keyring)
        return S3EncryptionClient(wrapped_s3_client=mock_s3, config=config), mock_s3

    def test_no_such_key_raises_s3_encryption_client_error(self):
        client, mock_s3 = self._build_client()
        error_response = {
            "Error": {"Code": "NoSuchKey", "Message": "The specified key does not exist."}
        }
        mock_s3.get_object.side_effect = ClientError(error_response, "GetObject")

        with pytest.raises(S3EncryptionClientError, match="Unable to retrieve object") as exc_info:
            client.get_object(Bucket="test-bucket", Key="nonexistent-key")

        assert isinstance(exc_info.value.__cause__, ClientError)
        assert exc_info.value.__cause__.response["Error"]["Code"] == "NoSuchKey"

    def test_access_denied_raises_s3_encryption_client_error(self):
        client, mock_s3 = self._build_client()
        error_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}
        mock_s3.get_object.side_effect = ClientError(error_response, "GetObject")

        with pytest.raises(S3EncryptionClientError, match="Unable to retrieve object") as exc_info:
            client.get_object(Bucket="test-bucket", Key="forbidden-key")

        assert isinstance(exc_info.value.__cause__, ClientError)
        assert exc_info.value.__cause__.response["Error"]["Code"] == "AccessDenied"


class TestFetchMissingInstructionFile:
    """fetch_instruction_file wraps NoSuchKey with instruction-file-specific message."""

    def test_missing_instruction_file_raises_s3_encryption_client_error(self):
        mock_s3 = Mock()
        mock_s3._s3ec_plugin_context = Mock()
        error_response = {
            "Error": {"Code": "NoSuchKey", "Message": "The specified key does not exist."}
        }
        mock_s3.get_object.side_effect = ClientError(error_response, "GetObject")

        from s3_encryption.instruction_file import fetch_instruction_file

        with pytest.raises(S3EncryptionClientError, match="fetching Instruction File") as exc_info:
            fetch_instruction_file(mock_s3, "test-bucket", "test-key.instruction")

        assert isinstance(exc_info.value.__cause__, ClientError)
        assert exc_info.value.__cause__.response["Error"]["Code"] == "NoSuchKey"
