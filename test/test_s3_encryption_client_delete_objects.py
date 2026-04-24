# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for S3EncryptionClient.delete_objects."""

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


class TestDeleteObjects:
    ##= specification/s3-encryption/client.md#required-api-operations
    ##= type=test
    ##% - DeleteObjects MUST delete each of the given objects.
    def test_deletes_objects(self):
        """delete_objects forwards the Delete parameter to the wrapped client."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_objects.return_value = {
            "Deleted": [{"Key": "key1"}, {"Key": "key2"}],
        }

        delete_param = {"Objects": [{"Key": "key1"}, {"Key": "key2"}]}
        response = s3ec.delete_objects(Bucket="bucket", Delete=delete_param)

        assert response == {"Deleted": [{"Key": "key1"}, {"Key": "key2"}]}
        assert mock_s3.delete_objects.call_args_list[0] == call(
            Bucket="bucket", Delete=delete_param
        )

    ##= specification/s3-encryption/client.md#required-api-operations
    ##= type=test
    ##% - DeleteObjects MUST delete each of the corresponding instruction files
    ##%   using the default instruction file suffix.
    def test_deletes_instruction_files(self):
        """delete_objects also deletes instruction files for each object."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_objects.return_value = {"Deleted": []}

        s3ec.delete_objects(
            Bucket="bucket",
            Delete={"Objects": [{"Key": "key1"}, {"Key": "key2"}]},
        )

        assert mock_s3.delete_objects.call_count == 2
        assert mock_s3.delete_objects.call_args_list[1] == call(
            Bucket="bucket",
            Delete={
                "Objects": [
                    {"Key": "key1.instruction"},
                    {"Key": "key2.instruction"},
                ],
            },
        )

    def test_returns_object_delete_response(self):
        """delete_objects returns the response from the object deletion, not the instruction file deletion."""
        s3ec, mock_s3 = _make_client()
        object_response = {"Deleted": [{"Key": "key1"}]}
        instruction_response = {"Deleted": [{"Key": "key1.instruction"}]}
        mock_s3.delete_objects.side_effect = [object_response, instruction_response]

        response = s3ec.delete_objects(
            Bucket="bucket",
            Delete={"Objects": [{"Key": "key1"}]},
        )

        assert response == object_response

    def test_wraps_unexpected_errors(self):
        """delete_objects wraps unexpected errors in S3EncryptionClientError."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_objects.side_effect = RuntimeError("network error")

        with pytest.raises(S3EncryptionClientError, match="Failed to delete objects"):
            s3ec.delete_objects(
                Bucket="bucket",
                Delete={"Objects": [{"Key": "key1"}]},
            )

    def test_reraises_s3_encryption_client_error(self):
        """delete_objects re-raises S3EncryptionClientError without wrapping."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_objects.side_effect = S3EncryptionClientError("original error")

        with pytest.raises(S3EncryptionClientError, match="original error"):
            s3ec.delete_objects(
                Bucket="bucket",
                Delete={"Objects": [{"Key": "key1"}]},
            )

    def test_passes_extra_kwargs(self):
        """delete_objects forwards extra kwargs to the wrapped client."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_objects.return_value = {"Deleted": []}

        s3ec.delete_objects(
            Bucket="bucket",
            Delete={"Objects": [{"Key": "key1"}]},
            RequestPayer="requester",
        )

        assert mock_s3.delete_objects.call_args_list[0] == call(
            Bucket="bucket",
            Delete={"Objects": [{"Key": "key1"}]},
            RequestPayer="requester",
        )

    def test_custom_instruction_file_suffix(self):
        """delete_objects uses a custom instruction file suffix when provided."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_objects.return_value = {"Deleted": []}

        s3ec.delete_objects(
            Bucket="bucket",
            Delete={"Objects": [{"Key": "key1"}]},
            InstructionFileSuffix=".custom-suffix",
        )

        assert mock_s3.delete_objects.call_count == 2
        assert mock_s3.delete_objects.call_args_list[1] == call(
            Bucket="bucket",
            Delete={"Objects": [{"Key": "key1.custom-suffix"}]},
        )

    def test_instruction_file_suffix_not_forwarded_to_s3(self):
        """InstructionFileSuffix is popped from kwargs and not sent to S3."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_objects.return_value = {"Deleted": []}

        s3ec.delete_objects(
            Bucket="bucket",
            Delete={"Objects": [{"Key": "key1"}]},
            InstructionFileSuffix=".custom",
        )

        assert mock_s3.delete_objects.call_args_list[0] == call(
            Bucket="bucket",
            Delete={"Objects": [{"Key": "key1"}]},
        )

    def test_preserves_version_ids_in_objects(self):
        """delete_objects preserves VersionId in the Objects list."""
        s3ec, mock_s3 = _make_client()
        mock_s3.delete_objects.return_value = {"Deleted": []}

        s3ec.delete_objects(
            Bucket="bucket",
            Delete={
                "Objects": [
                    {"Key": "key1", "VersionId": "v1"},
                    {"Key": "key2", "VersionId": "v2"},
                ]
            },
        )

        # First call preserves VersionId
        assert mock_s3.delete_objects.call_args_list[0] == call(
            Bucket="bucket",
            Delete={
                "Objects": [
                    {"Key": "key1", "VersionId": "v1"},
                    {"Key": "key2", "VersionId": "v2"},
                ]
            },
        )
        # Instruction file call does NOT include VersionId
        assert mock_s3.delete_objects.call_args_list[1] == call(
            Bucket="bucket",
            Delete={
                "Objects": [
                    {"Key": "key1.instruction"},
                    {"Key": "key2.instruction"},
                ],
            },
        )

    def test_instruction_files_not_deleted_when_disabled(self):
        """delete_objects skips instruction file deletion when disable_delete_objects is True."""
        from s3_encryption.instruction_file_config import InstructionFileConfig

        mock_keyring = Mock(spec=S3Keyring)
        mock_s3 = Mock()
        mock_s3.meta.events = Mock()
        mock_s3.delete_objects.return_value = {"Deleted": [{"Key": "key1"}, {"Key": "key2"}]}
        config = S3EncryptionClientConfig(
            keyring=mock_keyring,
            instruction_file_config=InstructionFileConfig(disable_delete_objects=True),
        )
        s3ec = S3EncryptionClient(wrapped_s3_client=mock_s3, config=config)

        s3ec.delete_objects(
            Bucket="bucket",
            Delete={"Objects": [{"Key": "key1"}, {"Key": "key2"}]},
        )

        # Only one call — the objects themselves, no instruction file delete
        assert mock_s3.delete_objects.call_count == 1
        assert mock_s3.delete_objects.call_args_list[0] == call(
            Bucket="bucket",
            Delete={"Objects": [{"Key": "key1"}, {"Key": "key2"}]},
        )
