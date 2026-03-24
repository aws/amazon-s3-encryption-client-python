# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for streaming decryption modes (buffered vs delayed-auth).

These tests verify that BufferedDecryptingGCMStream and DelayedAuthGCMDecryptingStream
produce correct plaintext for real S3 round-trips across algorithm suites.
"""

import os
from datetime import datetime

import boto3
import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring
from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy
from s3_encryption.stream import (
    BufferedDecryptingGCMStream,
    DelayedAuthGCMDecryptingStream,
)

bucket = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
region = os.environ.get("CI_AWS_REGION", "us-west-2")
kms_key_id = os.environ.get(
    "CI_KMS_KEY_ALIAS", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"
)

GCM_CONFIGS = [
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


def _make_client(algorithm_suite, commitment_policy, delayed_auth):
    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        encryption_algorithm=algorithm_suite,
        commitment_policy=commitment_policy,
        enable_delayed_authentication=delayed_auth,
    )
    return S3EncryptionClient(wrapped_client, config)


def _unique_key(prefix):
    return prefix + datetime.now().strftime("%Y-%m-%d-%H:%M:%S-%f")


# ---------------------------------------------------------------------------
# Buffered mode: verifies tag before releasing plaintext
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", GCM_CONFIGS)
def test_buffered_roundtrip(algorithm_suite, commitment_policy):
    """Buffered mode decrypts correctly for a simple round-trip."""
    key = _unique_key("buffered-rt-")
    data = b"buffered mode round trip test data"

    s3ec = _make_client(algorithm_suite, commitment_policy, delayed_auth=False)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    response = s3ec.get_object(Bucket=bucket, Key=key)

    body = response["Body"]
    assert isinstance(body, BufferedDecryptingGCMStream)
    assert body.read() == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", GCM_CONFIGS)
def test_buffered_partial_reads(algorithm_suite, commitment_policy):
    """Buffered mode supports partial read(amt) calls."""
    key = _unique_key("buffered-partial-")
    data = os.urandom(1024)

    s3ec = _make_client(algorithm_suite, commitment_policy, delayed_auth=False)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    response = s3ec.get_object(Bucket=bucket, Key=key)

    result = b""
    while chunk := response["Body"].read(100):
        result += chunk
    assert result == data


# ---------------------------------------------------------------------------
# Delayed-auth mode: releases plaintext before tag verification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", GCM_CONFIGS)
def test_delayed_auth_roundtrip(algorithm_suite, commitment_policy):
    """Delayed-auth mode decrypts correctly for a simple round-trip."""
    key = _unique_key("delayed-rt-")
    data = b"delayed auth round trip test data"

    s3ec = _make_client(algorithm_suite, commitment_policy, delayed_auth=True)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    response = s3ec.get_object(Bucket=bucket, Key=key)

    body = response["Body"]
    assert isinstance(body, DelayedAuthGCMDecryptingStream)
    assert body.read() == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", GCM_CONFIGS)
def test_delayed_auth_chunked_reads(algorithm_suite, commitment_policy):
    """Delayed-auth mode supports chunked streaming reads."""
    key = _unique_key("delayed-chunked-")
    data = os.urandom(4096)

    s3ec = _make_client(algorithm_suite, commitment_policy, delayed_auth=True)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    response = s3ec.get_object(Bucket=bucket, Key=key)

    result = b""
    while chunk := response["Body"].read(256):
        result += chunk
    assert result == data


# ---------------------------------------------------------------------------
# Both modes produce identical plaintext
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", GCM_CONFIGS)
def test_buffered_and_delayed_produce_same_plaintext(algorithm_suite, commitment_policy):
    """Both streaming modes must produce identical plaintext for the same object."""
    key = _unique_key("same-plaintext-")
    data = os.urandom(2048)

    # Encrypt once
    writer = _make_client(algorithm_suite, commitment_policy, delayed_auth=False)
    writer.put_object(Bucket=bucket, Key=key, Body=data)

    # Decrypt with buffered
    buffered = _make_client(algorithm_suite, commitment_policy, delayed_auth=False)
    resp_buf = buffered.get_object(Bucket=bucket, Key=key)
    plaintext_buf = resp_buf["Body"].read()

    # Decrypt with delayed-auth
    delayed = _make_client(algorithm_suite, commitment_policy, delayed_auth=True)
    resp_del = delayed.get_object(Bucket=bucket, Key=key)
    plaintext_del = resp_del["Body"].read()

    assert plaintext_buf == plaintext_del == data


# ---------------------------------------------------------------------------
# Empty body
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("delayed_auth", [False, True], ids=["buffered", "delayed-auth"])
@pytest.mark.parametrize("algorithm_suite,commitment_policy", GCM_CONFIGS)
def test_empty_body_roundtrip(algorithm_suite, commitment_policy, delayed_auth):
    """Both modes handle empty plaintext correctly."""
    key = _unique_key("empty-stream-")

    s3ec = _make_client(algorithm_suite, commitment_policy, delayed_auth=delayed_auth)
    s3ec.put_object(Bucket=bucket, Key=key, Body=b"")
    response = s3ec.get_object(Bucket=bucket, Key=key)
    assert response["Body"].read() == b""


# ---------------------------------------------------------------------------
# Large object streaming
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", GCM_CONFIGS)
def test_delayed_auth_large_object(algorithm_suite, commitment_policy):
    """Delayed-auth streams a 1 MB object correctly via chunked reads."""
    key = _unique_key("delayed-large-")
    data = os.urandom(1024 * 1024)  # 1 MB

    s3ec = _make_client(algorithm_suite, commitment_policy, delayed_auth=True)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    response = s3ec.get_object(Bucket=bucket, Key=key)

    result = b""
    while chunk := response["Body"].read(65536):
        result += chunk
    assert result == data
