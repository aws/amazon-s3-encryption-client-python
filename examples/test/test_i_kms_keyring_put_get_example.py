# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the KMS Keyring put/get example."""
import boto3
import pytest

from ..src.kms_keyring_put_get_example import kms_keyring_put_get

pytestmark = [pytest.mark.examples]

BUCKET = "s3ec-python-github-test-bucket"
KEY = "examples/kms-keyring-put-get"
KMS_KEY_ID = "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"


def test_kms_keyring_put_get():
    s3_client = boto3.client("s3", region_name="us-west-2")
    kms_client = boto3.client("kms", region_name="us-west-2")
    kms_keyring_put_get(
        s3_client=s3_client,
        kms_client=kms_client,
        kms_key_id=KMS_KEY_ID,
        bucket=BUCKET,
        key=KEY,
    )
    # Clean up
    s3_client.delete_object(Bucket=BUCKET, Key=KEY)
