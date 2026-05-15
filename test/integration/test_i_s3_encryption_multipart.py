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
        resp1 = s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=part1_data
        )
        resp2 = s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=2,
            Body=part2_data,
            IsLastPart=True,
        )

        # Complete
        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1, "ETag": resp1["ETag"]},
                    {"PartNumber": 2, "ETag": resp2["ETag"]},
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
        resp = s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=1,
            Body=data,
            IsLastPart=True,
        )

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": resp["ETag"]}]},
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
            is_last = i == len(parts_data)
            resp = s3ec.upload_part(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=i,
                Body=part_data,
                IsLastPart=is_last,
            )
            parts.append({"PartNumber": i, "ETag": resp["ETag"]})

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
        resp1 = s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=data[:FIVE_MB]
        )
        resp2 = s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=2,
            Body=data[FIVE_MB:],
            IsLastPart=True,
        )

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1, "ETag": resp1["ETag"]},
                    {"PartNumber": 2, "ETag": resp2["ETag"]},
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
        resp1 = writer.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=data[:FIVE_MB]
        )
        resp2 = writer.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=2,
            Body=data[FIVE_MB:],
            IsLastPart=True,
        )

        writer.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1, "ETag": resp1["ETag"]},
                    {"PartNumber": 2, "ETag": resp2["ETag"]},
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
        resp1 = s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=data[:FIVE_MB]
        )
        resp2 = s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=2,
            Body=data[FIVE_MB:],
            IsLastPart=True,
        )

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1, "ETag": resp1["ETag"]},
                    {"PartNumber": 2, "ETag": resp2["ETag"]},
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
    """Completing a multipart upload without marking a final part must fail."""
    key = _unique_key("mpu-no-parts-")

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        with pytest.raises(S3EncryptionClientError, match="final part has not been uploaded"):
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
        resp1 = s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=data[:FIVE_MB]
        )
        resp2 = s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=2,
            Body=data[FIVE_MB:],
            IsLastPart=True,
        )

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1, "ETag": resp1["ETag"]},
                    {"PartNumber": 2, "ETag": resp2["ETag"]},
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


# ---------------------------------------------------------------------------
# Upload part after final part
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_part_after_final_part_fails(algorithm_suite, commitment_policy):
    """Uploading a part after IsLastPart=True must fail."""
    key = _unique_key("mpu-after-final-")

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=1,
            Body=os.urandom(FIVE_MB),
            IsLastPart=True,
        )

        with pytest.raises(S3EncryptionClientError):
            s3ec.upload_part(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=2,
                Body=os.urandom(1024),
            )
    finally:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)


# ---------------------------------------------------------------------------
# Empty body multipart
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_empty_final_part(algorithm_suite, commitment_policy):
    """A multipart upload where the last part has an empty body should still work."""
    key = _unique_key("mpu-empty-last-")
    part1_data = os.urandom(FIVE_MB)

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        resp1 = s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=part1_data
        )
        resp2 = s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=2,
            Body=b"",
            IsLastPart=True,
        )

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1, "ETag": resp1["ETag"]},
                    {"PartNumber": 2, "ETag": resp2["ETag"]},
                ]
            },
        )
    except Exception:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise

    response = s3ec.get_object(Bucket=bucket, Key=key)
    assert response["Body"].read() == part1_data


# ---------------------------------------------------------------------------
# Many parts (stress sequential cipher)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_many_parts(algorithm_suite, commitment_policy):
    """Multipart upload with 10+ parts to stress the sequential cipher."""
    key = _unique_key("mpu-many-parts-")
    num_parts = 12
    parts_data = [os.urandom(FIVE_MB) for _ in range(num_parts - 1)]
    parts_data.append(os.urandom(1024))  # small last part
    expected = b"".join(parts_data)

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        parts = []
        for i, part_data in enumerate(parts_data, start=1):
            is_last = i == num_parts
            resp = s3ec.upload_part(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=i,
                Body=part_data,
                IsLastPart=is_last,
            )
            parts.append({"PartNumber": i, "ETag": resp["ETag"]})

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
# Non-ASCII encryption context rejected on multipart
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_non_ascii_encryption_context_rejected(algorithm_suite, commitment_policy):
    """Non-ASCII encryption context must be rejected on create_multipart_upload."""
    key = _unique_key("mpu-non-ascii-ec-")
    non_ascii_contexts = [
        {"department": "ingeniería"},
        {"部門": "engineering"},
        {"emoji": "🔑"},
    ]

    s3ec = _make_client(algorithm_suite, commitment_policy)

    for ec in non_ascii_contexts:
        with pytest.raises(S3EncryptionClientError, match="US-ASCII"):
            s3ec.create_multipart_upload(Bucket=bucket, Key=key, EncryptionContext=ec)


# ---------------------------------------------------------------------------
# Caller metadata dict not mutated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_multipart_caller_metadata_not_mutated(algorithm_suite, commitment_policy):
    """create_multipart_upload must not mutate the caller's Metadata dict."""
    key = _unique_key("mpu-no-mutate-")
    caller_metadata = {"author": "test"}
    original_keys = set(caller_metadata.keys())

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key, Metadata=caller_metadata)
    upload_id = create_resp["UploadId"]

    # Clean up
    s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)

    assert set(caller_metadata.keys()) == original_keys


# ---------------------------------------------------------------------------
# Per-upload lock does not block independent uploads
# ---------------------------------------------------------------------------


def test_per_upload_lock_independent_uploads():
    """Per-upload locks must not block concurrent uploads to different objects."""
    import threading

    s3ec = _make_client(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )

    barrier = threading.Barrier(2)
    results = {}
    errors = []

    def do_upload(thread_id):
        try:
            key = _unique_key(f"mpu-lock-{thread_id}-")
            data = os.urandom(FIVE_MB + 512)

            create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
            upload_id = create_resp["UploadId"]

            try:
                # Sync so both threads call upload_part simultaneously
                barrier.wait(timeout=30)

                resp1 = s3ec.upload_part(
                    Bucket=bucket,
                    Key=key,
                    UploadId=upload_id,
                    PartNumber=1,
                    Body=data[:FIVE_MB],
                )

                barrier.wait(timeout=30)

                resp2 = s3ec.upload_part(
                    Bucket=bucket,
                    Key=key,
                    UploadId=upload_id,
                    PartNumber=2,
                    Body=data[FIVE_MB:],
                    IsLastPart=True,
                )

                s3ec.complete_multipart_upload(
                    Bucket=bucket,
                    Key=key,
                    UploadId=upload_id,
                    MultipartUpload={
                        "Parts": [
                            {"PartNumber": 1, "ETag": resp1["ETag"]},
                            {"PartNumber": 2, "ETag": resp2["ETag"]},
                        ]
                    },
                )
            except Exception:
                s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
                raise

            response = s3ec.get_object(Bucket=bucket, Key=key)
            assert response["Body"].read() == data
            results[thread_id] = True

        except Exception as e:
            errors.append(f"Thread {thread_id}: {e}")

    t1 = threading.Thread(target=do_upload, args=(0,))
    t2 = threading.Thread(target=do_upload, args=(1,))
    t1.start()
    t2.start()
    t1.join(timeout=120)
    t2.join(timeout=120)

    if errors:
        raise AssertionError(
            "Per-upload lock test failed:\n" + "\n".join(f"  - {e}" for e in errors)
        )
    assert len(results) == 2


# ---------------------------------------------------------------------------
# Extra kwargs forwarded through upload_part
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_part_forwards_expected_bucket_owner(algorithm_suite, commitment_policy):
    """upload_part must forward ExpectedBucketOwner to S3 without error."""
    key = _unique_key("mpu-fwd-kwargs-")
    data = os.urandom(FIVE_MB + 512)

    s3ec = _make_client(algorithm_suite, commitment_policy)

    # Get the account ID that owns the bucket (same account we're authed as)
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        resp1 = s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=1,
            Body=data[:FIVE_MB],
            ExpectedBucketOwner=account_id,
        )
        resp2 = s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=2,
            Body=data[FIVE_MB:],
            IsLastPart=True,
            ExpectedBucketOwner=account_id,
        )

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1, "ETag": resp1["ETag"]},
                    {"PartNumber": 2, "ETag": resp2["ETag"]},
                ]
            },
        )
    except Exception:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise

    response = s3ec.get_object(Bucket=bucket, Key=key)
    assert response["Body"].read() == data


# ---------------------------------------------------------------------------
# Complete failure preserves state for retry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_complete_retryable_after_failure(algorithm_suite, commitment_policy):
    """If complete_multipart_upload fails, the upload can be retried."""
    key = _unique_key("mpu-retry-complete-")
    data = os.urandom(FIVE_MB + 512)

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        resp1 = s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=data[:FIVE_MB]
        )
        resp2 = s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=2,
            Body=data[FIVE_MB:],
            IsLastPart=True,
        )

        parts = [
            {"PartNumber": 1, "ETag": resp1["ETag"]},
            {"PartNumber": 2, "ETag": resp2["ETag"]},
        ]

        # First attempt: deliberately pass bad parts to trigger S3 error
        try:
            s3ec.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": [{"PartNumber": 99, "ETag": '"bogus"'}]},
            )
        except S3EncryptionClientError:
            pass  # Expected failure

        # Retry with correct parts should succeed (state preserved)
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
    assert response["Body"].read() == data


# ---------------------------------------------------------------------------
# Retry upload_part with same part number
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_upload_part_retry_same_part_number(algorithm_suite, commitment_policy):
    """Calling upload_part twice with the same part number returns cached ciphertext and decrypts."""
    key = _unique_key("mpu-retry-part-")
    part1_data = os.urandom(FIVE_MB)
    part2_data = os.urandom(1024)
    expected = part1_data + part2_data

    s3ec = _make_client(algorithm_suite, commitment_policy)

    create_resp = s3ec.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create_resp["UploadId"]

    try:
        # Upload part 1 twice (simulating a retry after transient failure)
        resp1_first = s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=part1_data
        )
        resp1_retry = s3ec.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=part1_data
        )
        # Both should produce the same ETag (same ciphertext uploaded)
        assert resp1_first["ETag"] == resp1_retry["ETag"]

        resp2 = s3ec.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=2,
            Body=part2_data,
            IsLastPart=True,
        )

        s3ec.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1, "ETag": resp1_retry["ETag"]},
                    {"PartNumber": 2, "ETag": resp2["ETag"]},
                ]
            },
        )
    except Exception:
        s3ec.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise

    response = s3ec.get_object(Bucket=bucket, Key=key)
    assert response["Body"].read() == expected
