# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for S3EncryptionClient.delete_object."""

from unittest.mock import Mock, call

import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.keyring import S3Keyring


def _make_client():
    """Create an S3EncryptionClient with a mocked wrapped S3 client."""
    mock_keyring = Mock(spec=S3Keyring)
    mock_s3 = Mock()
    mock_s3.meta.events = Mock()
    config = S3EncryptionClientConfig(keyring=mock_keyring)
    s3ec = S3EncryptionClient(wrapped_s3_client=mock_s3, config=config)
    return s3ec, mock_s3


class TestDeleteObject:
    ##= specification/s3-encryption/client.md#required-api-operations
    ##= type=test
    ##% - DeleteObject MUST delete the given object key.
    def test_deletes_object(self):
        """delete_object forwards the call to the wrapped client."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_object.return_value = {"DeleteMarker": True}

        response = s3ec.delete_object(Bucket="bucket", Key="key")

        assert response == {"DeleteMarker": True}
        assert mock_s3.delete_object.call_args_list[0] == call(Bucket="bucket", Key="key")

    ##= specification/s3-encryption/client.md#required-api-operations
    ##= type=test
    ##% - DeleteObject MUST delete the associated instruction file
    ##%   using the default instruction file suffix.
    def test_deletes_instruction_file(self):
        """delete_object also deletes the instruction file with default suffix."""
        s3ec, mock_s3 = _make_client()

        s3ec.delete_object(Bucket="bucket", Key="key")

        assert mock_s3.delete_object.call_count == 2
        assert mock_s3.delete_object.call_args_list[1] == call(
            Bucket="bucket", Key="key.instruction"
        )

    def test_returns_object_delete_response(self):
        """delete_object returns the response from the object deletion, not the instruction file."""
        s3ec, mock_s3 = _make_client()
        object_response = {"DeleteMarker": True, "VersionId": "v1"}
        instruction_response = {"DeleteMarker": False, "VersionId": "v2"}
        mock_s3.delete_object.side_effect = [object_response, instruction_response]

        response = s3ec.delete_object(Bucket="bucket", Key="key")

        assert response == object_response

    def test_wraps_unexpected_errors(self):
        """delete_object wraps unexpected errors in S3EncryptionClientError."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_object.side_effect = RuntimeError("network error")

        with pytest.raises(S3EncryptionClientError, match="Failed to delete object"):
            s3ec.delete_object(Bucket="bucket", Key="key")

    def test_reraises_s3_encryption_client_error(self):
        """delete_object re-raises S3EncryptionClientError without wrapping."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_object.side_effect = S3EncryptionClientError("original error")

        with pytest.raises(S3EncryptionClientError, match="original error"):
            s3ec.delete_object(Bucket="bucket", Key="key")

    def test_passes_extra_kwargs(self):
        """delete_object forwards extra kwargs like VersionId to the wrapped client."""
        s3ec, mock_s3 = _make_client()

        s3ec.delete_object(Bucket="bucket", Key="key", VersionId="abc123")

        assert mock_s3.delete_object.call_args_list[0] == call(
            Bucket="bucket", Key="key", VersionId="abc123"
        )

    def test_custom_instruction_file_suffix(self):
        """delete_object uses a custom instruction file suffix when provided."""
        s3ec, mock_s3 = _make_client()

        s3ec.delete_object(Bucket="bucket", Key="key", InstructionFileSuffix=".custom-suffix")

        assert mock_s3.delete_object.call_count == 2
        assert mock_s3.delete_object.call_args_list[1] == call(
            Bucket="bucket", Key="key.custom-suffix"
        )

    def test_instruction_file_suffix_not_forwarded_to_s3(self):
        """InstructionFileSuffix is popped from kwargs and not sent to S3."""
        s3ec, mock_s3 = _make_client()

        s3ec.delete_object(Bucket="bucket", Key="key", InstructionFileSuffix=".custom")

        # First call (object delete) should not contain InstructionFileSuffix
        assert mock_s3.delete_object.call_args_list[0] == call(Bucket="bucket", Key="key")
