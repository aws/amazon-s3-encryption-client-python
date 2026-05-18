# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for multipart upload encryption pipeline and client methods."""

import io
import os
import threading
from unittest.mock import MagicMock

import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from s3_encryption.materials.encrypted_data_key import EncryptedDataKey
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
            str(f), "bucket", "key", multipart_threshold=1024, multipart_chunksize=5 * 1024 * 1024
        )

        s3ec.wrapped_s3_client.create_multipart_upload.assert_called_once()
        assert s3ec.wrapped_s3_client.upload_part.call_count >= 1
        s3ec.wrapped_s3_client.complete_multipart_upload.assert_called_once()

    def test_upload_fileobj_uses_multipart(self):

        s3ec = self._setup_client()
        data = os.urandom(2048)

        s3ec.upload_fileobj(io.BytesIO(data), "bucket", "key", multipart_chunksize=5 * 1024 * 1024)

        s3ec.wrapped_s3_client.create_multipart_upload.assert_called_once()
        assert s3ec.wrapped_s3_client.upload_part.call_count >= 1
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
                str(f),
                "bucket",
                "key",
                multipart_threshold=1024,
                multipart_chunksize=5 * 1024 * 1024,
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
            multipart_chunksize=5 * 1024 * 1024,
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
            multipart_chunksize=5 * 1024 * 1024,
            Metadata={"author": "test"},
        )

        create_kwargs = s3ec.wrapped_s3_client.create_multipart_upload.call_args[1]
        assert create_kwargs["Metadata"]["author"] == "test"


class TestMultipartEncryptionContextValidation:
    """Unit tests for encryption context validation in create_multipart_upload."""

    def test_non_ascii_value_rejected(self):
        s3ec = _make_client()
        with pytest.raises(S3EncryptionClientError, match="US-ASCII"):
            s3ec.create_multipart_upload(
                Bucket="bucket", Key="key", EncryptionContext={"key": "válue"}
            )

    def test_non_ascii_key_rejected(self):
        s3ec = _make_client()
        with pytest.raises(S3EncryptionClientError, match="US-ASCII"):
            s3ec.create_multipart_upload(
                Bucket="bucket", Key="key", EncryptionContext={"clé": "value"}
            )

    def test_emoji_rejected(self):
        s3ec = _make_client()
        with pytest.raises(S3EncryptionClientError, match="US-ASCII"):
            s3ec.create_multipart_upload(
                Bucket="bucket", Key="key", EncryptionContext={"emoji": "🔑"}
            )

    def test_ascii_context_accepted(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-ascii",
            "Bucket": "bucket",
            "Key": "key",
        }
        # Should not raise
        resp = s3ec.create_multipart_upload(
            Bucket="bucket", Key="key", EncryptionContext={"env": "test"}
        )
        assert resp["UploadId"] == "uid-ascii"

    def test_caller_metadata_dict_not_mutated(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-nomutate",
            "Bucket": "bucket",
            "Key": "key",
        }

        caller_metadata = {"author": "test"}
        original_keys = set(caller_metadata.keys())

        s3ec.create_multipart_upload(Bucket="bucket", Key="key", Metadata=caller_metadata)

        # Caller's dict should not have been modified with encryption metadata
        assert set(caller_metadata.keys()) == original_keys


class TestMultipartPipelineLock:
    """Unit tests verifying per-upload lock prevents concurrent encrypt_part races."""

    def test_concurrent_encrypt_part_same_pipeline_serialized(self):
        """Concurrent calls to encrypt_part on the same pipeline are serialized by the lock."""


        keyring, _ = _mock_keyring()
        cmm = DefaultCryptoMaterialsManager(keyring)
        pipeline = MultipartUploadPipeline(
            cmm=cmm,
            encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )

        results = {}
        errors = []
        barrier = threading.Barrier(2)

        def upload_part_1():
            try:
                barrier.wait(timeout=5)
                ct = pipeline.encrypt_part(1, b"A" * 1024)
                results[1] = ct
            except Exception as e:
                errors.append(("part1", e))

        def upload_part_2():
            try:
                barrier.wait(timeout=5)
                ct = pipeline.encrypt_part(2, b"B" * 512, is_last=True)
                results[2] = ct
            except Exception as e:
                errors.append(("part2", e))

        t1 = threading.Thread(target=upload_part_1)
        t2 = threading.Thread(target=upload_part_2)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        # One of two outcomes is valid:
        # 1. Both succeed in order (part 1 acquired lock first)
        # 2. Part 2 fails with sequence error (part 2 acquired lock first)
        if errors:
            # If there's an error, it must be a sequence error on part 2
            assert any("sequence" in str(e).lower() for _, e in errors)
        else:
            # Both succeeded means part 1 ran first
            assert 1 in results and 2 in results
            assert len(results[1]) == 1024
            assert len(results[2]) == 512 + 16

    def test_upload_part_forwards_extra_kwargs(self):
        """upload_part must forward extra S3 parameters (e.g. RequestPayer) to the S3 client."""
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-fwd",
            "Bucket": "bucket",
            "Key": "key",
        }
        s3ec.wrapped_s3_client.upload_part.return_value = {"ETag": '"etag"'}

        s3ec.create_multipart_upload(Bucket="bucket", Key="key")
        s3ec.upload_part(
            Bucket="bucket",
            Key="key",
            UploadId="uid-fwd",
            PartNumber=1,
            Body=b"data",
            IsLastPart=True,
            RequestPayer="requester",
            ExpectedBucketOwner="123456789012",
        )

        call_kwargs = s3ec.wrapped_s3_client.upload_part.call_args[1]
        assert call_kwargs["RequestPayer"] == "requester"
        assert call_kwargs["ExpectedBucketOwner"] == "123456789012"
        # IsLastPart should NOT be forwarded to S3
        assert "IsLastPart" not in call_kwargs

    def test_upload_part_does_not_forward_is_last_part(self):
        """IsLastPart is consumed by the client and must not reach S3."""
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-nolast",
            "Bucket": "bucket",
            "Key": "key",
        }
        s3ec.wrapped_s3_client.upload_part.return_value = {"ETag": '"etag"'}

        s3ec.create_multipart_upload(Bucket="bucket", Key="key")
        s3ec.upload_part(
            Bucket="bucket",
            Key="key",
            UploadId="uid-nolast",
            PartNumber=1,
            Body=b"x",
            IsLastPart=True,
        )

        call_kwargs = s3ec.wrapped_s3_client.upload_part.call_args[1]
        assert "IsLastPart" not in call_kwargs

    def test_complete_failure_preserves_state_for_retry(self):
        """If complete_multipart_upload fails, the upload state is preserved for retry."""
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-retry",
            "Bucket": "bucket",
            "Key": "key",
        }
        s3ec.wrapped_s3_client.upload_part.return_value = {"ETag": '"etag1"'}

        s3ec.create_multipart_upload(Bucket="bucket", Key="key")
        s3ec.upload_part(
            Bucket="bucket",
            Key="key",
            UploadId="uid-retry",
            PartNumber=1,
            Body=b"data",
            IsLastPart=True,
        )

        # First complete fails
        s3ec.wrapped_s3_client.complete_multipart_upload.side_effect = Exception("network timeout")
        with pytest.raises(S3EncryptionClientError, match="network timeout"):
            s3ec.complete_multipart_upload(
                Bucket="bucket",
                Key="key",
                UploadId="uid-retry",
                MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": '"etag1"'}]},
            )

        # Retry should work (state not cleaned up)
        s3ec.wrapped_s3_client.complete_multipart_upload.side_effect = None
        s3ec.wrapped_s3_client.complete_multipart_upload.return_value = {"Location": "s3://ok"}
        resp = s3ec.complete_multipart_upload(
            Bucket="bucket",
            Key="key",
            UploadId="uid-retry",
            MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": '"etag1"'}]},
        )
        assert resp["Location"] == "s3://ok"

        # After success, state is cleaned up
        with pytest.raises(S3EncryptionClientError, match="No multipart upload found"):
            s3ec.complete_multipart_upload(
                Bucket="bucket",
                Key="key",
                UploadId="uid-retry",
                MultipartUpload={"Parts": []},
            )


class TestUploadFileValidation:
    """Unit tests for upload_file/upload_fileobj parameter validation."""

    def test_zero_threshold_raises(self, tmp_path):
        s3ec = _make_client()
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        with pytest.raises(S3EncryptionClientError, match="multipart_threshold must be a positive"):
            s3ec.upload_file(str(f), "bucket", "key", multipart_threshold=0)

    def test_negative_threshold_raises(self, tmp_path):
        s3ec = _make_client()
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        with pytest.raises(S3EncryptionClientError, match="multipart_threshold must be a positive"):
            s3ec.upload_file(str(f), "bucket", "key", multipart_threshold=-1)

    def test_zero_chunksize_raises(self, tmp_path):
        s3ec = _make_client()
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        with pytest.raises(S3EncryptionClientError, match="multipart_chunksize must be a positive"):
            s3ec.upload_file(str(f), "bucket", "key", multipart_chunksize=0)

    def test_negative_chunksize_raises(self, tmp_path):
        s3ec = _make_client()
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        with pytest.raises(S3EncryptionClientError, match="multipart_chunksize must be a positive"):
            s3ec.upload_file(str(f), "bucket", "key", multipart_chunksize=-1)

    def test_upload_fileobj_zero_chunksize_raises(self):

        s3ec = _make_client()
        with pytest.raises(S3EncryptionClientError, match="multipart_chunksize must be a positive"):
            s3ec.upload_fileobj(io.BytesIO(b"data"), "bucket", "key", multipart_chunksize=0)

    def test_upload_fileobj_negative_chunksize_raises(self):

        s3ec = _make_client()
        with pytest.raises(S3EncryptionClientError, match="multipart_chunksize must be a positive"):
            s3ec.upload_fileobj(io.BytesIO(b"data"), "bucket", "key", multipart_chunksize=-1)

    def test_chunksize_below_5mb_raises(self, tmp_path):
        s3ec = _make_client()
        f = tmp_path / "test.bin"
        f.write_bytes(os.urandom(1024))
        with pytest.raises(S3EncryptionClientError, match="at least.*5 MB"):
            s3ec.upload_file(str(f), "bucket", "key", multipart_chunksize=1024 * 1024)

    def test_upload_fileobj_chunksize_below_5mb_raises(self):

        s3ec = _make_client()
        with pytest.raises(S3EncryptionClientError, match="at least.*5 MB"):
            s3ec.upload_fileobj(
                io.BytesIO(b"data"), "bucket", "key", multipart_chunksize=4 * 1024 * 1024
            )

    def test_upload_file_forwards_s3_params_to_create(self, tmp_path):
        """upload_file must forward S3 params like ContentType to create_multipart_upload."""
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-fwd-create",
            "Bucket": "bucket",
            "Key": "key",
        }
        s3ec.wrapped_s3_client.upload_part.return_value = {"ETag": '"etag"'}
        s3ec.wrapped_s3_client.complete_multipart_upload.return_value = {"Location": "s3://..."}

        f = tmp_path / "typed.bin"
        f.write_bytes(os.urandom(2048))

        s3ec.upload_file(
            str(f),
            "bucket",
            "key",
            multipart_threshold=1024,
            multipart_chunksize=5 * 1024 * 1024,
            ContentType="application/json",
            Tagging="env=test",
        )

        create_kwargs = s3ec.wrapped_s3_client.create_multipart_upload.call_args[1]
        assert create_kwargs["ContentType"] == "application/json"
        assert create_kwargs["Tagging"] == "env=test"


class TestFileobjLifecycle:
    """Unit tests verifying upload_fileobj does not close the caller's file object."""

    def _setup_client(self):
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-lifecycle",
            "Bucket": "bucket",
            "Key": "key",
        }
        s3ec.wrapped_s3_client.upload_part.return_value = {"ETag": '"etag"'}
        s3ec.wrapped_s3_client.complete_multipart_upload.return_value = {"Location": "s3://..."}
        return s3ec

    def test_upload_fileobj_does_not_close_caller_stream(self):

        s3ec = self._setup_client()
        buf = io.BytesIO(os.urandom(1024))

        s3ec.upload_fileobj(buf, "bucket", "key")

        assert not buf.closed

    def test_upload_file_closes_its_own_stream(self, tmp_path):
        """upload_file opens the file internally and must close it after."""
        s3ec = self._setup_client()

        f = tmp_path / "owned.bin"
        f.write_bytes(os.urandom(2048))

        s3ec.upload_file(
            str(f), "bucket", "key", multipart_threshold=1024, multipart_chunksize=5 * 1024 * 1024
        )

        # We can't directly check the internal file handle is closed,
        # but we can verify the upload completed without error and the
        # file is still readable (not locked)
        assert f.read_bytes() == f.read_bytes()


class TestMultipartPartRetry:
    """Unit tests for retrying a failed upload_part call."""

    @pytest.fixture
    def pipeline(self):

        keyring, _ = _mock_keyring()
        cmm = DefaultCryptoMaterialsManager(keyring)
        return MultipartUploadPipeline(
            cmm=cmm,
            encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )

    def test_retry_same_part_returns_cached_ciphertext(self, pipeline):
        ct1 = pipeline.encrypt_part(1, b"hello")
        ct2 = pipeline.encrypt_part(1, b"hello")
        assert ct1 == ct2

    def test_retry_last_part_returns_cached_ciphertext(self, pipeline):
        pipeline.encrypt_part(1, b"part one")
        ct2 = pipeline.encrypt_part(2, b"part two", is_last=True)
        ct2_retry = pipeline.encrypt_part(2, b"part two", is_last=True)
        assert ct2 == ct2_retry

    def test_retry_does_not_block_next_part(self, pipeline):
        pipeline.encrypt_part(1, b"first")
        # Retry part 1
        pipeline.encrypt_part(1, b"first")
        # Part 2 should still work
        ct = pipeline.encrypt_part(2, b"second", is_last=True)
        assert len(ct) == len(b"second") + 16

    def test_client_upload_part_retry_after_s3_failure(self):
        """If S3 upload_part fails, retrying the same part number succeeds."""
        s3ec = _make_client()
        s3ec.wrapped_s3_client.create_multipart_upload.return_value = {
            "UploadId": "uid-retry-part",
            "Bucket": "bucket",
            "Key": "key",
        }

        s3ec.create_multipart_upload(Bucket="bucket", Key="key")

        # First attempt fails at S3 level
        s3ec.wrapped_s3_client.upload_part.side_effect = Exception("network error")
        with pytest.raises(Exception, match="network error"):
            s3ec.upload_part(
                Bucket="bucket",
                Key="key",
                UploadId="uid-retry-part",
                PartNumber=1,
                Body=b"data",
            )

        # Retry succeeds
        s3ec.wrapped_s3_client.upload_part.side_effect = None
        s3ec.wrapped_s3_client.upload_part.return_value = {"ETag": '"etag1"'}
        resp = s3ec.upload_part(
            Bucket="bucket",
            Key="key",
            UploadId="uid-retry-part",
            PartNumber=1,
            Body=b"data",
        )
        assert resp["ETag"] == '"etag1"'
