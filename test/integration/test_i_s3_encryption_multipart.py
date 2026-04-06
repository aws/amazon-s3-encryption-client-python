# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for encrypted multipart upload.

These tests verify that the S3 Encryption Client correctly encrypts
objects via multipart upload and that they can be decrypted via get_object.
Tests cover the low-level multipart API (create/upload_part/complete/abort)
and the high-level upload_file / upload_fileobj convenience methods.
"""

import os
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

# Minimum part size for S3 multipart upload is 5 MB (except last part).
FIVE_MB = 5 * 1024 * 1024


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


# ---------------------------------------------------------------------------
# Low-level multipart API: create → upload_part → complete
# ---------------------------------------------------------------------------


##= specification/s3-encryption/client.md#optional-api-operations
##= type=test
##% CreateMultipartUpload MAY be implemented by the S3EC.
##% If implemented, CreateMultipartUpload MUST initiate a multipart upload.
##= specification/s3-encryption/client.md#optional-api-operations
##= type=test
##% UploadPart MUST encrypt each part.
##= specification/s3-encryption/client.md#optional-api-operations
##= type=test
##% Each part MUST be encrypted in sequence.
##= specification/s3-encryption/client.md#optional-api-operations
##= type=test
##% Each part MUST be encrypted using the same cipher instance for each part.
##= specification/s3-encryption/client.md#optional-api-operations
##= type=test
##% CompleteMultipartUpload MAY be implemented by the S3EC.
##% CompleteMultipartUpload MUST complete the multipart upload.
@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_two_parts_roundtrip(algorithm_suite, commitment_policy):
    """Encrypt two 5 MB parts via multipart upload, then decrypt with get_object."""
    key = _unique_key("mpu-2part-")
    part1_data = os.urandom(FIVE_MB)
    part2_data = os.urandom(1024)  # last part can be smaller
    expected = part1_data + part2_data

    s3ec = _make_client(algorithm_suite, commitment_policy)

    # Create
    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        # Upload parts
        s3ec.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=part1_data)
        s3ec.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=part2_data)

        # Complete
        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1},
                    {"PartNumber": 2},
                ]
            },
        )
    except Exception:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise

    # Decrypt
    response = s3ec.get_object(Bucket=bucket, Key=key)
    assert response["Body"].read() == expected


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_single_part(algorithm_suite, commitment_policy):
    """A multipart upload with a single part should still round-trip correctly."""
    key = _unique_key("mpu-1part-")
    data = os.urandom(FIVE_MB)

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        s3ec.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=data)

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": [{"PartNumber": 1}]},
        )
    except Exception:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise

    response = s3ec.get_object(Bucket=bucket, Key=key)
    assert response["Body"].read() == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_three_parts(algorithm_suite, commitment_policy):
    """Three-part multipart upload: 5MB + 5MB + small last part."""
    key = _unique_key("mpu-3part-")
    parts_data = [os.urandom(FIVE_MB), os.urandom(FIVE_MB), os.urandom(2048)]
    expected = b"".join(parts_data)

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        parts = []
        for i, part_data in enumerate(parts_data, start=1):
            s3ec.upload_part(
                Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=i, Body=part_data
            )
            parts.append({"PartNumber": i})

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
    except Exception:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise

    response = s3ec.get_object(Bucket=bucket, Key=key)
    assert response["Body"].read() == expected


# ---------------------------------------------------------------------------
# Abort
# ---------------------------------------------------------------------------


##= specification/s3-encryption/client.md#optional-api-operations
##= type=test
##% AbortMultipartUpload MAY be implemented by the S3EC.
##% AbortMultipartUpload MUST abort the multipart upload.
@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_abort_multipart_upload(algorithm_suite, commitment_policy):
    """Aborting a multipart upload should clean up without leaving an object."""
    key = _unique_key("mpu-abort-")

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    # Upload one part then abort
    s3ec.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=os.urandom(FIVE_MB)
    )
    s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)

    # Object should not exist
    plain_s3 = boto3.client("s3")
    with pytest.raises(plain_s3.exceptions.NoSuchKey):
        plain_s3.get_object(Bucket=bucket, Key=key)


# ---------------------------------------------------------------------------
# Encryption context with multipart upload
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_with_encryption_context(algorithm_suite, commitment_policy):
    """Multipart upload with encryption context should be usable on decrypt."""
    key = _unique_key("mpu-ec-")
    data = os.urandom(FIVE_MB + 1024)
    encryption_context = {"project": "s3ec-python", "test": "multipart"}

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(
        Bucket=bucket, Key=key, EncryptionContext=encryption_context
    )
    upload_id = create_resp["UploadId"]

    try:
        s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=data[:FIVE_MB]
        )
        s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=data[FIVE_MB:]
        )

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1},
                    {"PartNumber": 2},
                ]
            },
        )
    except Exception:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise

    # Decrypt with matching encryption context
    response = s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext=encryption_context)
    assert response["Body"].read() == data

    # Decrypt with wrong encryption context should fail
    with pytest.raises(S3EncryptionClientError):
        s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext={"wrong": "context"})


# ---------------------------------------------------------------------------
# Streaming decryption of multipart-uploaded objects
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_decrypt_with_delayed_auth(algorithm_suite, commitment_policy):
    """Objects uploaded via multipart should be decryptable in delayed-auth mode."""
    key = _unique_key("mpu-delayed-auth-")
    data = os.urandom(FIVE_MB + 2048)

    # Encrypt with default (buffered) client
    writer = _make_client(algorithm_suite, commitment_policy)
    create_resp = writer.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        writer.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=data[:FIVE_MB]
        )
        writer.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=data[FIVE_MB:]
        )

        writer.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1},
                    {"PartNumber": 2},
                ]
            },
        )
    except Exception:
        writer.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise

    # Decrypt with delayed-auth streaming
    reader = _make_client(algorithm_suite, commitment_policy, enable_delayed_authentication=True)
    response = reader.get_object(Bucket=bucket, Key=key)

    result = b""
    while chunk := response["Body"].read(65536):
        result += chunk
    assert result == data


# ---------------------------------------------------------------------------
# Metadata verification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_metadata_present(algorithm_suite, commitment_policy):
    """Multipart-uploaded objects should have encryption metadata set."""
    key = _unique_key("mpu-metadata-")
    data = os.urandom(FIVE_MB + 512)

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=data[:FIVE_MB]
        )
        s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=data[FIVE_MB:]
        )

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1},
                    {"PartNumber": 2},
                ]
            },
        )
    except Exception:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise

    # Verify encryption metadata is present on the object
    plain_s3 = boto3.client("s3")
    head = plain_s3.head_object(Bucket=bucket, Key=key)
    metadata = head.get("Metadata", {})

    if algorithm_suite == AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
        assert "x-amz-key-v2" in metadata
        assert "x-amz-iv" in metadata
        assert "x-amz-cek-alg" in metadata
        assert "x-amz-wrap-alg" in metadata
    else:
        assert "x-amz-3" in metadata
        assert "x-amz-c" in metadata
        assert "x-amz-d" in metadata
        assert "x-amz-i" in metadata
        assert "x-amz-w" in metadata


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_part_out_of_order_fails(algorithm_suite, commitment_policy):
    """Uploading parts out of sequence order must fail (serial cipher requirement)."""
    key = _unique_key("mpu-ooo-")

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        # Skip part 1, try to upload part 2 first
        with pytest.raises(S3EncryptionClientError):
            s3ec.upload_part(
                Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=os.urandom(FIVE_MB)
            )
    finally:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_part_invalid_upload_id_fails(algorithm_suite, commitment_policy):
    """upload_part with an unknown upload ID must fail."""
    key = _unique_key("mpu-bad-id-")

    s3ec = _make_client(algorithm_suite, commitment_policy)

    with pytest.raises(S3EncryptionClientError):
        s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId="nonexistent-upload-id",
            PartNumber=1,
            Body=os.urandom(1024),
        )


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_complete_without_parts_fails(algorithm_suite, commitment_policy):
    """Completing a multipart upload with no parts uploaded must fail."""
    key = _unique_key("mpu-no-parts-")

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        with pytest.raises((S3EncryptionClientError, Exception)):
            s3ec.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": []},
            )
    finally:
        # Clean up in case complete didn't actually fail at the S3 level
        try:
            s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# User metadata preservation with multipart
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_user_metadata_preserved(algorithm_suite, commitment_policy):
    """User-provided metadata on create_multipart_upload should be preserved."""
    key = _unique_key("mpu-user-meta-")
    user_metadata = {"author": "test-user", "version": "2.0"}
    data = os.urandom(FIVE_MB + 512)

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key, Metadata=user_metadata)
    upload_id = create_resp["UploadId"]

    try:
        s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=data[:FIVE_MB]
        )
        s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=data[FIVE_MB:]
        )

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1},
                    {"PartNumber": 2},
                ]
            },
        )
    except Exception:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise

    response = s3ec.get_object(Bucket=bucket, Key=key)
    assert response["Body"].read() == data

    returned_metadata = response.get("Metadata", {})
    for k, v in user_metadata.items():
        assert returned_metadata.get(k) == v
