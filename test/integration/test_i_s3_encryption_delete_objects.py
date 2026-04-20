# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for S3EncryptionClient.delete_objects."""

import os
from datetime import datetime

import boto3
import pytest
from botocore.exceptions import ClientError

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
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


def _make_client(algorithm_suite, commitment_policy):
    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        encryption_algorithm=algorithm_suite,
        commitment_policy=commitment_policy,
    )
    return S3EncryptionClient(wrapped_client, config)


def _unique_key(prefix):
    return prefix + datetime.now().strftime("%Y-%m-%d-%H:%M:%S-%f")


def _object_exists(key):
    """Return True if the object exists in the test bucket."""
    s3 = boto3.client("s3")
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return False
        raise


##= specification/s3-encryption/client.md#required-api-operations
##= type=test
##% - DeleteObjects MUST delete each of the given objects.
@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_delete_objects_deletes_objects(algorithm_suite, commitment_policy):
    """delete_objects removes the encrypted objects from S3."""
    s3ec = _make_client(algorithm_suite, commitment_policy)
    keys = [_unique_key("del-objs-"), _unique_key("del-objs-")]

    for key in keys:
        s3ec.put_object(Bucket=bucket, Key=key, Body=b"data")

    s3ec.delete_objects(
        Bucket=bucket,
        Delete={"Objects": [{"Key": k} for k in keys]},
    )

    for key in keys:
        assert not _object_exists(key)


##= specification/s3-encryption/client.md#required-api-operations
##= type=test
##% - DeleteObjects MUST delete each of the corresponding instruction files
##%   using the default instruction file suffix.
@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_delete_objects_deletes_instruction_files(algorithm_suite, commitment_policy):
    """delete_objects also removes the .instruction files from S3."""
    s3ec = _make_client(algorithm_suite, commitment_policy)
    keys = [_unique_key("del-objs-instr-"), _unique_key("del-objs-instr-")]

    # Put instruction-file-based objects by uploading instruction files manually
    plain_s3 = boto3.client("s3")
    for key in keys:
        s3ec.put_object(Bucket=bucket, Key=key, Body=b"data")
        # Also create a fake instruction file to verify it gets deleted
        plain_s3.put_object(Bucket=bucket, Key=key + ".instruction", Body=b"{}")

    s3ec.delete_objects(
        Bucket=bucket,
        Delete={"Objects": [{"Key": k} for k in keys]},
    )

    for key in keys:
        assert not _object_exists(key)
        assert not _object_exists(key + ".instruction")


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_delete_objects_returns_response(algorithm_suite, commitment_policy):
    """delete_objects returns the S3 response from the object deletion."""
    s3ec = _make_client(algorithm_suite, commitment_policy)
    key = _unique_key("del-objs-resp-")
    s3ec.put_object(Bucket=bucket, Key=key, Body=b"data")

    response = s3ec.delete_objects(
        Bucket=bucket,
        Delete={"Objects": [{"Key": key}]},
    )

    assert "Deleted" in response
    deleted_keys = [d["Key"] for d in response["Deleted"]]
    assert key in deleted_keys
