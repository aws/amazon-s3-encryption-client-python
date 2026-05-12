# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the delayed auth streaming decrypt example."""

import uuid

import boto3
import pytest

from ..src.delayed_auth_streaming_example import delayed_auth_streaming_decrypt

pytestmark = [pytest.mark.examples]

BUCKET = "s3ec-python-github-test-bucket"
KMS_KEY_ID = "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"


def test_delayed_auth_streaming_decrypt():
    key = f"examples/delayed-auth-streaming-{uuid.uuid4()}"
    s3_client = boto3.client("s3", region_name="us-west-2")
    kms_client = boto3.client("kms", region_name="us-west-2")
    delayed_auth_streaming_decrypt(
        s3_client=s3_client,
        kms_client=kms_client,
        kms_key_id=KMS_KEY_ID,
        bucket=BUCKET,
        key=key,
    )
    s3_client.delete_object(Bucket=BUCKET, Key=key)
