# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for performance tests."""

import os

import boto3
import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring
from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy

BUCKET = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
REGION = os.environ.get("CI_AWS_REGION", "us-west-2")
KMS_KEY_ID = os.environ.get(
    "CI_KMS_KEY_ALIAS", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"
)

# Performance test configuration
NUM_ROUNDS = int(os.environ.get("PERF_NUM_ROUNDS", "5"))
OBJECT_SIZES_MB = [10, 25, 50]


def _make_s3ec(algorithm_suite, commitment_policy):
    kms_client = boto3.client("kms", region_name=REGION)
    keyring = KmsKeyring(kms_client, KMS_KEY_ID)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        encryption_algorithm=algorithm_suite,
        commitment_policy=commitment_policy,
    )
    return S3EncryptionClient(wrapped_client, config)


@pytest.fixture(scope="module")
def s3ec_v2():
    return _make_s3ec(
        AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
    )


@pytest.fixture(scope="module")
def s3ec_v3():
    return _make_s3ec(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )


@pytest.fixture(scope="module")
def plain_s3():
    return boto3.client("s3", region_name=REGION)


@pytest.fixture(scope="module")
def kms_client():
    return boto3.client("kms", region_name=REGION)
