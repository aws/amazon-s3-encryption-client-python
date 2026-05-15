#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Post-release validation: install the published package and do a round-trip.

This script is run after publishing to TestPyPI or PyPI to verify that
the released artifact works correctly for consumers.
"""

import os
import sys
import uuid

import boto3

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption._utils import _PACKAGE_VERSION
from s3_encryption.materials.kms_keyring import KmsKeyring

BUCKET = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
KMS_KEY_ID = os.environ.get(
    "CI_KMS_KEY_ALIAS", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"
)
REGION = "us-west-2"


def main():
    print(f"Validating amazon-s3-encryption-client-python v{_PACKAGE_VERSION}")

    kms_client = boto3.client("kms", region_name=REGION)
    keyring = KmsKeyring(kms_client, KMS_KEY_ID)
    s3_client = boto3.client("s3", region_name=REGION)
    config = S3EncryptionClientConfig(keyring=keyring)
    s3ec = S3EncryptionClient(s3_client, config)

    key = f"release-validation/{uuid.uuid4()}"
    plaintext = b"Release validation round-trip test"

    # Put
    print(f"  Encrypting and uploading to s3://{BUCKET}/{key}")
    s3ec.put_object(Bucket=BUCKET, Key=key, Body=plaintext)

    # Get
    print(f"  Downloading and decrypting from s3://{BUCKET}/{key}")
    response = s3ec.get_object(Bucket=BUCKET, Key=key)
    result = response["Body"].read()

    assert result == plaintext, f"Round-trip failed: expected {plaintext!r}, got {result!r}"

    # Cleanup
    s3_client.delete_object(Bucket=BUCKET, Key=key)

    print("  Round-trip validation passed!")
    print(f"  Version: {_PACKAGE_VERSION}")
    print(f"  User-Agent includes: S3ECPy/{_PACKAGE_VERSION}")
    sys.exit(0)


if __name__ == "__main__":
    main()
