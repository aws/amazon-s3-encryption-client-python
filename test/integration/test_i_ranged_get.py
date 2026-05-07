# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration test for ranged get (Range parameter on get_object).

The S3 Encryption Client does not support ranged gets because decryption
requires the full ciphertext (IV, encrypted data, and auth tag). Passing
a Range parameter retrieves only a slice of the ciphertext, which causes
decryption to fail.
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


def _make_client(algorithm_suite, commitment_policy):
    """Create an S3EncryptionClient with the given algorithm config."""
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
    """Generate a unique S3 key with a timestamp suffix."""
    return prefix + datetime.now().strftime("%Y-%m-%d-%H:%M:%S-%f")


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


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_ranged_get_fails(algorithm_suite, commitment_policy):
    """A ranged get on an encrypted object should fail because the client
    cannot decrypt a partial ciphertext."""
    key = _unique_key("ranged-get-")
    # Use a body large enough that a byte-range is meaningful
    data = b"A" * 1024

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)

    # Attempt a ranged get — should raise immediately with a clear message
    with pytest.raises(S3EncryptionClientError, match="Ranged gets are not supported"):
        s3ec.get_object(Bucket=bucket, Key=key, Range="bytes=0-255")
