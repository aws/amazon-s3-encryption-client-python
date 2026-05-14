# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for multipart upload encryption pipeline and client methods."""

import os
from unittest.mock import MagicMock

import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.materials import (
    AlgorithmSuite,
    CommitmentPolicy,
)
from s3_encryption.pipelines import MultipartUploadPipeline


def _mock_keyring():
    """Create a mock keyring that returns a fixed data key."""
    key = os.urandom(32)
    keyring = MagicMock()

    def on_encrypt(mats):
        from s3_encryption.materials.encrypted_data_key import EncryptedDataKey

        mats.plaintext_data_key = key
        mats.encrypted_data_key = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=os.urandom(64),
        )
        return mats

    keyring.on_encrypt = on_encrypt
    return keyring, key


def _make_client(algorithm_suite=None, commitment_policy=None):
    """Create an S3EncryptionClient with a mock keyring and mock S3 client."""
    keyring, _ = _mock_keyring()
    algo = algorithm_suite or AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
    policy = commitment_policy or CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    config = S3EncryptionClientConfig(
        keyring=keyring,
        encryption_algorithm=algo,
        commitment_policy=policy,
    )
    mock_s3 = MagicMock()
    mock_s3.meta.config.user_agent_extra = ""
    mock_s3.meta.events = MagicMock()
    return S3EncryptionClient(mock_s3, config)


class TestMultipartUploadPipeline:
    """Unit tests for the MultipartUploadPipeline cipher logic."""

    @pytest.fixture(
        params=[
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        ]
    )
    def pipeline(self, request):
        from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager

        keyring, _ = _mock_keyring()
        cmm = DefaultCryptoMaterialsManager(keyring)
        return MultipartUploadPipeline(
            cmm=cmm,
            encryption_algorithm=request.param,
        )

    def test_encrypt_single_part(self, pipeline):
        data = b"hello world"
        ct = pipeline.encrypt_part(1, data, is_last=True)
        # Ciphertext should be data + 16-byte GCM tag
        assert len(ct) == len(data) + 16
        assert pipeline.has_final_part_been_seen

    def test_encrypt_multiple_parts(self, pipeline):
        part1 = pipeline.encrypt_part(1, b"A" * 1024)
        part2 = pipeline.encrypt_part(2, b"B" * 512, is_last=True)
        assert len(part1) == 1024
        assert len(part2) == 512 + 16  # data + tag on last part
        assert pipeline.has_final_part_been_seen

    def test_out_of_order_raises(self, pipeline):
        with pytest.raises(S3EncryptionClientError, match="sequence"):
            pipeline.encrypt_part(2, b"data")

    def test_part_after_final_raises(self, pipeline):
        pipeline.encrypt_part(1, b"data", is_last=True)
        with pytest.raises(S3EncryptionClientError, match="after the final part"):
            pipeline.encrypt_part(2, b"more data")

    def test_empty_part(self, pipeline):
        ct = pipeline.encrypt_part(1, b"", is_last=True)
        # Empty data + 16-byte tag
        assert len(ct) == 16

    def test_metadata_present(self, pipeline):
        assert pipeline.metadata
        # Should have encryption metadata keys
        assert len(pipeline.metadata) > 0

    def test_string_body_converted(self, pipeline):
        ct = pipeline.encrypt_part(1, "hello", is_last=True)
        assert len(ct) == len(b"hello") + 16


class TestS3EncryptionClientMultipart:
    """Unit tests for the S3EncryptionClient multipart methods."""

    def test_create_multipart_upload(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "test-upload-id",
            "Bucket": "bucket",
            "Key": "key",
        }

        resp = s3ec.create_multipart_upload(Bucket="bucket", Key="key")
        assert resp["UploadId"] == "test-upload-id"
        s3ec.wrapped_s3_client.create_multipart_upload.assert_called_once()

    def test_upload_part_unknown_upload_id(self):
        s3ec = _make_client()
        with pytest.raises(S3EncryptionClientError, match="No multipart upload found"):
            s3ec.upload_part(
                Bucket="bucket", Key="key", UploadId="nonexistent", PartNumber=1, Body=b"data"
            )

    def test_upload_part_encrypts(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-1",
            "Bucket": "bucket",
            "Key": "key",
        }
        s3ec.wrapped_s3_client.upload_part.return_value = {"ETag": '"abc123"'}

        s3ec.create_multipart_upload(Bucket="bucket", Key="key")
        resp = s3ec.upload_part(
            Bucket="bucket",
            Key="key",
            UploadId="uid-1",
            PartNumber=1,
            Body=b"data",
            IsLastPart=True,
        )

        assert resp["ETag"] == '"abc123"'
        # Verify the body passed to S3 is ciphertext (different from plaintext)
        call_kwargs = s3ec.wrapped_s3_client.upload_part.call_args[1]
        assert call_kwargs["Body"] != b"data"

    def test_complete_without_final_part_raises(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-2",
            "Bucket": "bucket",
            "Key": "key",
        }

        s3ec.create_multipart_upload(Bucket="bucket", Key="key")

        with pytest.raises(S3EncryptionClientError, match="final part has not been uploaded"):
            s3ec.complete_multipart_upload(
                Bucket="bucket",
                Key="key",
                UploadId="uid-2",
                MultipartUpload={"Parts": []},
            )

    def test_complete_after_final_part_succeeds(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-3",
            "Bucket": "bucket",
            "Key": "key",
        }
        s3ec.wrapped_s3_client.upload_part.return_value = {"ETag": '"etag1"'}
        s3ec.wrapped_s3_client.complete_multipart_upload.return_value = {"Location": "s3://..."}

        s3ec.create_multipart_upload(Bucket="bucket", Key="key")
        s3ec.upload_part(
            Bucket="bucket",
            Key="key",
            UploadId="uid-3",
            PartNumber=1,
            Body=b"x" * 1024,
            IsLastPart=True,
        )
        resp = s3ec.complete_multipart_upload(
            Bucket="bucket",
            Key="key",
            UploadId="uid-3",
            MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": '"etag1"'}]},
        )
        assert resp["Location"] == "s3://..."

    def test_abort_cleans_up_state(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-4",
            "Bucket": "bucket",
            "Key": "key",
        }
        s3ec.wrapped_s3_client.abort_multipart_upload.return_value = {}

        s3ec.create_multipart_upload(Bucket="bucket", Key="key")
        s3ec.abort_multipart_upload(Bucket="bucket", Key="key", UploadId="uid-4")

        # After abort, upload_part should fail
        with pytest.raises(S3EncryptionClientError, match="No multipart upload found"):
            s3ec.upload_part(
                Bucket="bucket", Key="key", UploadId="uid-4", PartNumber=1, Body=b"data"
            )

    def test_complete_unknown_upload_id_raises(self):
        s3ec = _make_client()
        with pytest.raises(S3EncryptionClientError, match="No multipart upload found"):
            s3ec.complete_multipart_upload(
                Bucket="bucket",
                Key="key",
                UploadId="nonexistent",
                MultipartUpload={"Parts": []},
            )

    def test_create_multipart_with_encryption_context(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-ec",
            "Bucket": "bucket",
            "Key": "key",
        }

        s3ec.create_multipart_upload(Bucket="bucket", Key="key", EncryptionContext={"env": "test"})

        # EncryptionContext should not be passed to S3 (it's consumed by the pipeline)
        call_kwargs = s3ec.wrapped_s3_client.create_multipart_upload.call_args[1]
        assert "EncryptionContext" not in call_kwargs

    def test_metadata_merged_on_create(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-meta",
            "Bucket": "bucket",
            "Key": "key",
        }

        s3ec.create_multipart_upload(
            Bucket="bucket", Key="key", Metadata={"user-key": "user-value"}
        )

        call_kwargs = s3ec.wrapped_s3_client.create_multipart_upload.call_args[1]
        metadata = call_kwargs["Metadata"]
        # User metadata preserved
        assert metadata["user-key"] == "user-value"
        # Encryption metadata also present
        assert len(metadata) > 1


class TestUploadFileAndFileobj:
    """Unit tests for upload_file and upload_fileobj high-level methods."""

    def _setup_client(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-file",
            "Bucket": "bucket",
            "Key": "key",
        }
        s3ec.wrapped_s3_client.upload_part.return_value = {"ETag": '"etag"'}
        s3ec.wrapped_s3_client.complete_multipart_upload.return_value = {"Location": "s3://..."}
        return s3ec

    def test_upload_file_below_threshold_uses_put_object(self, tmp_path):
        s3ec = _make_client()
        # Mock put_object on the event-based path
        s3ec.wrapped_s3_client.put_object.return_value = {}

        f = tmp_path / "small.bin"
        f.write_bytes(b"small data")

        s3ec.upload_file(str(f), "bucket", "key", multipart_threshold=1024 * 1024)

        # put_object should have been called (via the event system)
        s3ec.wrapped_s3_client.put_object.assert_called_once()
        s3ec.wrapped_s3_client.create_multipart_upload.assert_not_called()

    def test_upload_file_above_threshold_uses_multipart(self, tmp_path):
        s3ec = self._setup_client()

        f = tmp_path / "large.bin"
        f.write_bytes(os.urandom(2048))

        s3ec.upload_file(
            str(f), "bucket", "key", multipart_threshold=1024, multipart_chunksize=1024
        )

        s3ec.wrapped_s3_client.create_multipart_upload.assert_called_once()
        assert s3ec.wrapped_s3_client.upload_part.call_count >= 2
        s3ec.wrapped_s3_client.complete_multipart_upload.assert_called_once()

    def test_upload_fileobj_uses_multipart(self):
        import io

        s3ec = self._setup_client()
        data = os.urandom(2048)

        s3ec.upload_fileobj(io.BytesIO(data), "bucket", "key", multipart_chunksize=1024)

        s3ec.wrapped_s3_client.create_multipart_upload.assert_called_once()
        assert s3ec.wrapped_s3_client.upload_part.call_count >= 2
        s3ec.wrapped_s3_client.complete_multipart_upload.assert_called_once()

    def test_upload_file_aborts_on_failure(self, tmp_path):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-fail",
            "Bucket": "bucket",
            "Key": "key",
        }
        s3ec.wrapped_s3_client.upload_part.side_effect = Exception("network error")
        s3ec.wrapped_s3_client.abort_multipart_upload.return_value = {}

        f = tmp_path / "fail.bin"
        f.write_bytes(os.urandom(2048))

        with pytest.raises(Exception):
            s3ec.upload_file(
                str(f), "bucket", "key", multipart_threshold=1024, multipart_chunksize=1024
            )

        s3ec.wrapped_s3_client.abort_multipart_upload.assert_called_once()

    def test_upload_file_passes_encryption_context(self, tmp_path):
        s3ec = self._setup_client()

        f = tmp_path / "ec.bin"
        f.write_bytes(os.urandom(2048))

        s3ec.upload_file(
            str(f),
            "bucket",
            "key",
            multipart_threshold=1024,
            multipart_chunksize=1024,
            EncryptionContext={"env": "test"},
        )

        # EncryptionContext consumed by create_multipart_upload, not passed to S3
        create_kwargs = s3ec.wrapped_s3_client.create_multipart_upload.call_args[1]
        assert "EncryptionContext" not in create_kwargs

    def test_upload_file_passes_user_metadata(self, tmp_path):
        s3ec = self._setup_client()

        f = tmp_path / "meta.bin"
        f.write_bytes(os.urandom(2048))

        s3ec.upload_file(
            str(f),
            "bucket",
            "key",
            multipart_threshold=1024,
            multipart_chunksize=1024,
            Metadata={"author": "test"},
        )

        create_kwargs = s3ec.wrapped_s3_client.create_multipart_upload.call_args[1]
        assert create_kwargs["Metadata"]["author"] == "test"
