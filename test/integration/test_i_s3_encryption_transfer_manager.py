# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for S3EncryptionClient with boto3's S3Transfer / upload_file.

These tests verify that the S3EncryptionClient's upload_file and upload_fileobj
methods correctly handle the multipart threshold boundary, produce objects
decryptable by get_object, and behave correctly with various TransferConfig-like
parameters.

boto3's native upload_file (via s3transfer) calls create_multipart_upload,
upload_part, and complete_multipart_upload directly on the client it wraps.
Since those calls would bypass encryption if made on the raw S3 client,
the S3EncryptionClient provides its own upload_file / upload_fileobj that
route through the encrypted multipart pipeline.
"""

import io
import os
import tempfile
from datetime import datetime

import boto3
import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.kms_keyring import KmsKeyring
from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy

bucket = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
region = os.environ.get("CI_AWS_REGION", "us-west-2")
kms_key_id = os.environ.get(
    "CI_KMS_KEY_ALIAS", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"
)

ALGORITHM_CONFIGS = [
    pytest.param(
        AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        id="AES_GCM",
    ),
    pytest.param(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        id="KC_GCM",
    ),
]

ONE_MB = 1024 * 1024


def _make_client(algorithm_suite, commitment_policy, **extra_config):
    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        encryption_algorithm=algorithm_suite,
        commitment_policy=commitment_policy,
        **extra_config,
    )
    return S3EncryptionClient(wrapped_client, config)


def _unique_key(prefix):
    return prefix + datetime.now().strftime("%Y-%m-%d-%H:%M:%S-%f")


def _write_temp_file(data):
    """Write data to a temp file and return the path."""
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(data)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# upload_file: below threshold → put_object path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_below_threshold(algorithm_suite, commitment_policy):
    """Files smaller than the threshold should use put_object internally."""
    key = _unique_key("tm-below-")
    data = os.urandom(1024)
    tmp = _write_temp_file(data)

    try:
        s3ec = _make_client(algorithm_suite, commitment_policy)
        s3ec.upload_file(tmp, bucket, key)
        assert s3ec.get_object(Bucket=bucket, Key=key)["Body"].read() == data
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# upload_file: above threshold → multipart path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_above_default_threshold(algorithm_suite, commitment_policy):
    """Files larger than the default 8 MB threshold trigger multipart upload."""
    key = _unique_key("tm-above-default-")
    data = os.urandom(9 * ONE_MB)
    tmp = _write_temp_file(data)

    try:
        s3ec = _make_client(algorithm_suite, commitment_policy)
        s3ec.upload_file(tmp, bucket, key)
        assert s3ec.get_object(Bucket=bucket, Key=key)["Body"].read() == data
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# upload_file: custom threshold
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_custom_threshold(algorithm_suite, commitment_policy):
    """A custom multipart_threshold forces multipart for smaller files."""
    key = _unique_key("tm-custom-thresh-")
    # 6 MB file with a 5 MB threshold → multipart
    data = os.urandom(6 * ONE_MB)
    tmp = _write_temp_file(data)

    try:
        s3ec = _make_client(algorithm_suite, commitment_policy)
        s3ec.upload_file(tmp, bucket, key, multipart_threshold=5 * ONE_MB)
        assert s3ec.get_object(Bucket=bucket, Key=key)["Body"].read() == data
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# upload_file: custom chunksize
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_custom_chunksize(algorithm_suite, commitment_policy):
    """A custom multipart_chunksize controls part size (more parts)."""
    key = _unique_key("tm-custom-chunk-")
    # 11 MB file with 5 MB chunks → 3 parts (5 + 5 + 1)
    data = os.urandom(11 * ONE_MB)
    tmp = _write_temp_file(data)

    try:
        s3ec = _make_client(algorithm_suite, commitment_policy)
        s3ec.upload_file(
            tmp,
            bucket,
            key,
            multipart_threshold=5 * ONE_MB,
            multipart_chunksize=5 * ONE_MB,
        )
        assert s3ec.get_object(Bucket=bucket, Key=key)["Body"].read() == data
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# upload_file: exactly at threshold boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_exactly_at_threshold(algorithm_suite, commitment_policy):
    """A file exactly equal to the threshold should use put_object (< not <=)."""
    key = _unique_key("tm-exact-thresh-")
    threshold = 5 * ONE_MB
    data = os.urandom(threshold)
    tmp = _write_temp_file(data)

    try:
        s3ec = _make_client(algorithm_suite, commitment_policy)
        s3ec.upload_file(tmp, bucket, key, multipart_threshold=threshold)
        assert s3ec.get_object(Bucket=bucket, Key=key)["Body"].read() == data
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# upload_fileobj: basic round-trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_fileobj_roundtrip(algorithm_suite, commitment_policy):
    """upload_fileobj encrypts a BytesIO via multipart and decrypts correctly."""
    key = _unique_key("tm-fileobj-")
    data = os.urandom(9 * ONE_MB)

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.upload_fileobj(io.BytesIO(data), bucket, key)
    assert s3ec.get_object(Bucket=bucket, Key=key)["Body"].read() == data


# ---------------------------------------------------------------------------
# upload_fileobj: small object (single part)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_fileobj_small(algorithm_suite, commitment_policy):
    """upload_fileobj with a small object still works (single multipart part)."""
    key = _unique_key("tm-fileobj-small-")
    data = os.urandom(1024)

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.upload_fileobj(io.BytesIO(data), bucket, key)
    assert s3ec.get_object(Bucket=bucket, Key=key)["Body"].read() == data


# ---------------------------------------------------------------------------
# upload_file with encryption context
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_with_encryption_context(algorithm_suite, commitment_policy):
    """upload_file passes EncryptionContext through to the multipart pipeline."""
    key = _unique_key("tm-ec-")
    data = os.urandom(9 * ONE_MB)
    ec = {"purpose": "transfer-manager-test"}
    tmp = _write_temp_file(data)

    try:
        s3ec = _make_client(algorithm_suite, commitment_policy)
        s3ec.upload_file(tmp, bucket, key, EncryptionContext=ec)
        assert s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext=ec)["Body"].read() == data
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# upload_file with user metadata
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_with_user_metadata(algorithm_suite, commitment_policy):
    """User-provided Metadata is preserved through upload_file multipart path."""
    key = _unique_key("tm-meta-")
    data = os.urandom(9 * ONE_MB)
    user_meta = {"author": "test", "version": "3"}
    tmp = _write_temp_file(data)

    try:
        s3ec = _make_client(algorithm_suite, commitment_policy)
        s3ec.upload_file(tmp, bucket, key, Metadata=user_meta)

        response = s3ec.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read() == data
        returned = response.get("Metadata", {})
        for k, v in user_meta.items():
            assert returned.get(k) == v
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# Delayed-auth decryption of transfer-manager-uploaded objects
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_decrypt_delayed_auth(algorithm_suite, commitment_policy):
    """Objects uploaded via upload_file are decryptable in delayed-auth mode."""
    key = _unique_key("tm-delayed-")
    data = os.urandom(9 * ONE_MB)
    tmp = _write_temp_file(data)

    try:
        writer = _make_client(algorithm_suite, commitment_policy)
        writer.upload_file(tmp, bucket, key)

        reader = _make_client(
            algorithm_suite, commitment_policy, enable_delayed_authentication=True
        )
        response = reader.get_object(Bucket=bucket, Key=key)
        result = b""
        while chunk := response["Body"].read(65536):
            result += chunk
        assert result == data
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# Parameter validation: zero/negative threshold and chunksize
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_zero_threshold_raises(algorithm_suite, commitment_policy, tmp_path):
    """upload_file with multipart_threshold=0 must raise."""
    s3ec = _make_client(algorithm_suite, commitment_policy)
    f = tmp_path / "test.bin"
    f.write_bytes(os.urandom(1024))

    with pytest.raises(S3EncryptionClientError, match="multipart_threshold must be a positive"):
        s3ec.upload_file(str(f), bucket, "unused-key", multipart_threshold=0)


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_zero_chunksize_raises(algorithm_suite, commitment_policy, tmp_path):
    """upload_file with multipart_chunksize=0 must raise."""
    s3ec = _make_client(algorithm_suite, commitment_policy)
    f = tmp_path / "test.bin"
    f.write_bytes(os.urandom(1024))

    with pytest.raises(S3EncryptionClientError, match="multipart_chunksize must be a positive"):
        s3ec.upload_file(str(f), bucket, "unused-key", multipart_chunksize=0)


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_fileobj_zero_chunksize_raises(algorithm_suite, commitment_policy):
    """upload_fileobj with multipart_chunksize=0 must raise."""
    s3ec = _make_client(algorithm_suite, commitment_policy)

    with pytest.raises(S3EncryptionClientError, match="multipart_chunksize must be a positive"):
        s3ec.upload_fileobj(io.BytesIO(b"data"), bucket, "unused-key", multipart_chunksize=0)


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_chunksize_below_5mb_raises(algorithm_suite, commitment_policy, tmp_path):
    """upload_file with chunksize below S3's 5 MB minimum must raise."""
    s3ec = _make_client(algorithm_suite, commitment_policy)
    f = tmp_path / "test.bin"
    f.write_bytes(os.urandom(1024))

    with pytest.raises(S3EncryptionClientError, match="at least.*5 MB"):
        s3ec.upload_file(str(f), bucket, "unused-key", multipart_chunksize=1024 * 1024)


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_fileobj_chunksize_below_5mb_raises(algorithm_suite, commitment_policy):
    """upload_fileobj with chunksize below S3's 5 MB minimum must raise."""
    s3ec = _make_client(algorithm_suite, commitment_policy)

    with pytest.raises(S3EncryptionClientError, match="at least.*5 MB"):
        s3ec.upload_fileobj(
            io.BytesIO(b"data"), bucket, "unused-key", multipart_chunksize=4 * ONE_MB
        )


# ---------------------------------------------------------------------------
# S3 parameters forwarded through upload_file to create_multipart_upload
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_file_forwards_content_type(algorithm_suite, commitment_policy, tmp_path):
    """upload_file must forward ContentType to the multipart upload."""
    key = _unique_key("tm-content-type-")
    data = os.urandom(9 * ONE_MB)
    tmp = _write_temp_file(data)

    try:
        s3ec = _make_client(algorithm_suite, commitment_policy)
        s3ec.upload_file(tmp, bucket, key, ContentType="application/octet-stream")

        # Verify ContentType was set on the object
        plain_s3 = boto3.client("s3")
        head = plain_s3.head_object(Bucket=bucket, Key=key)
        assert head["ContentType"] == "application/octet-stream"

        # Verify data round-trips
        assert s3ec.get_object(Bucket=bucket, Key=key)["Body"].read() == data
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# upload_fileobj does not close the caller's file object
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_fileobj_does_not_close_caller_stream(algorithm_suite, commitment_policy):
    """upload_fileobj must not close the caller's file-like object."""
    key = _unique_key("tm-no-close-")
    data = os.urandom(9 * ONE_MB)
    buf = io.BytesIO(data)

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.upload_fileobj(buf, bucket, key)

    assert not buf.closed

    # Verify the upload worked
    assert s3ec.get_object(Bucket=bucket, Key=key)["Body"].read() == data
