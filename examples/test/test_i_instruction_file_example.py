# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the instruction file example."""
import boto3
import pytest

from ..src.instruction_file_example import instruction_file_get

pytestmark = [pytest.mark.examples]

BUCKET = "s3ec-static-test-objects"
KEY = "static-v3-instruction-file-from-java-v4"
KMS_KEY_ID = "arn:aws:kms:us-west-2:370957321024:key/a3889cd9-99eb-4138-a93a-aea9d52ec2ef"


# TODO(#152): Move instruction_file_suffix from config to get_object request context
# so a single S3EncryptionClient can use different suffixes per request.
@pytest.mark.xfail(reason="instruction_file_suffix is per-client, not per-request")
def test_instruction_file_get():
    s3_client = boto3.client("s3", region_name="us-west-2")
    kms_client = boto3.client("kms", region_name="us-west-2")
    instruction_file_get(
        s3_client=s3_client,
        kms_client=kms_client,
        kms_key_id=KMS_KEY_ID,
        bucket=BUCKET,
        key=KEY,
        expected_plaintext=KEY.encode("utf-8"),
    )
