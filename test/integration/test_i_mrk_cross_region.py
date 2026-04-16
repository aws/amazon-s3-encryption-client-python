# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for Multi-Region Key (MRK) cross-region encrypt/decrypt.

These tests verify that data encrypted with a KMS MRK primary key in one region
can be decrypted using the MRK replica in another region, and vice versa.

Prerequisites:
  - A KMS MRK primary key in us-west-2 (created by CDK stack)
  - A KMS MRK replica of the same key in us-east-1 (created manually after CDK deploy)
  - Both keys share the same key ID (mrk-...) but have different region ARNs

Environment variables:
  CI_MRK_KEY_ID_PRIMARY: ARN or alias of the MRK primary in us-west-2
  CI_MRK_KEY_ID_REPLICA: ARN of the MRK replica in us-east-1
  CI_S3_BUCKET: S3 bucket for test objects (us-west-2)
"""

import os
from datetime import datetime

import boto3
import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.kms_keyring import KmsKeyring

bucket = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
primary_region = os.environ.get("CI_AWS_REGION", "us-west-2")
replica_region = "us-east-1"

mrk_primary = os.environ.get(
    "CI_MRK_KEY_ID_PRIMARY",
    "arn:aws:kms:us-west-2:370957321024:key/mrk-cea4cf67c6a046ba829f61f69db5c191",
)
mrk_replica = os.environ.get(
    "CI_MRK_KEY_ID_REPLICA",
    "arn:aws:kms:us-east-1:370957321024:key/mrk-cea4cf67c6a046ba829f61f69db5c191",
)


def _make_client(kms_region, kms_key_id):
    """Create an S3EncryptionClient using a KMS client in the given region."""
    kms_client = boto3.client("kms", region_name=kms_region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    # Always use a primary region S3 client
    wrapped_client = boto3.client("s3", region_name=primary_region)
    config = S3EncryptionClientConfig(keyring=keyring)
    return S3EncryptionClient(wrapped_client, config)


def _unique_key(prefix):
    return prefix + datetime.now().strftime("%Y-%m-%d-%H:%M:%S-%f")


class TestMRKCrossRegion:
    """Verify MRK encrypt/decrypt works across regions."""

    def test_encrypt_primary_decrypt_replica(self):
        """Data encrypted with MRK primary MUST decrypt with MRK replica."""
        key = _unique_key("mrk-primary-to-replica-")
        data = b"MRK cross-region: primary -> replica"

        writer = _make_client(primary_region, mrk_primary)
        writer.put_object(Bucket=bucket, Key=key, Body=data)

        reader = _make_client(replica_region, mrk_replica)
        response = reader.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read() == data

    def test_encrypt_replica_decrypt_primary(self):
        """Data encrypted with MRK replica MUST decrypt with MRK primary."""
        key = _unique_key("mrk-replica-to-primary-")
        data = b"MRK cross-region: replica -> primary"

        writer = _make_client(replica_region, mrk_replica)
        writer.put_object(Bucket=bucket, Key=key, Body=data)

        reader = _make_client(primary_region, mrk_primary)
        response = reader.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read() == data

    def test_encrypt_and_decrypt_same_region_primary(self):
        """MRK primary round-trip in the same region MUST work."""
        key = _unique_key("mrk-same-region-primary-")
        data = b"MRK same-region primary round trip"

        s3ec = _make_client(primary_region, mrk_primary)
        s3ec.put_object(Bucket=bucket, Key=key, Body=data)
        response = s3ec.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read() == data

    def test_encrypt_and_decrypt_same_region_replica(self):
        """MRK replica round-trip in the same region MUST work."""
        key = _unique_key("mrk-same-region-replica-")
        data = b"MRK same-region replica round trip"

        s3ec = _make_client(replica_region, mrk_replica)
        s3ec.put_object(Bucket=bucket, Key=key, Body=data)
        response = s3ec.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read() == data


class TestMRKNonReplicatedRegionFails:
    """Verify that using an MRK in a region where it hasn't been replicated fails."""

    def test_decrypt_with_wrong_region_kms_client_fails(self):
        """Decrypting with a KMS client pointed at a non-replicated region MUST fail."""
        key = _unique_key("mrk-wrong-region-")
        data = b"MRK wrong region test"

        # Encrypt with primary
        writer = _make_client(primary_region, mrk_primary)
        writer.put_object(Bucket=bucket, Key=key, Body=data)

        # Try to decrypt using a KMS client in a region where the MRK doesn't exist.
        # Use eu-west-1 as a region that almost certainly has no replica.
        non_replicated_region = "eu-west-1"
        reader = _make_client(non_replicated_region, mrk_primary)

        with pytest.raises(S3EncryptionClientError):
            reader.get_object(Bucket=bucket, Key=key)
