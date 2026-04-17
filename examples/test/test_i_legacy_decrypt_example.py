# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the legacy decrypt example."""
import boto3
import pytest

from ..src.legacy_decrypt_example import decrypt_legacy_object

pytestmark = [pytest.mark.examples]

BUCKET = "s3ec-static-test-objects"
KEY = "static-v1-instruction-file-from-java-v1"
KMS_KEY_ID = "arn:aws:kms:us-west-2:370957321024:key/a3889cd9-99eb-4138-a93a-aea9d52ec2ef"


def test_decrypt_legacy_object():
    s3_client = boto3.client("s3", region_name="us-west-2")
    kms_client = boto3.client("kms", region_name="us-west-2")
    plaintext = decrypt_legacy_object(
        s3_client=s3_client,
        kms_client=kms_client,
        kms_key_id=KMS_KEY_ID,
        bucket=BUCKET,
        key=KEY,
    )
    assert plaintext == KEY.encode("utf-8")
    # Avoid deleting the static object, it is used in the integration tests
