# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from datetime import datetime

import boto3

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring

bucket = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
region = os.environ.get("CI_AWS_REGION", "us-west-2")
kms_key_id = os.environ.get(
    "CI_KMS_KEY_ALIAS", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"
)


def test_simple_roundtrip():
    key = "simple-rt"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    data = "test input for simple v3 round trip"

    kms_client = boto3.client("kms", region_name=region)

    keyring = KmsKeyring(kms_client, kms_key_id)

    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    get_req = {"Bucket": bucket, "Key": key}
    response = s3ec.get_object(**get_req)
    output = response["Body"].read().decode("utf-8")
    if output != data:
        print("Uh oh! Input and output don't match!")
        print("Input:")
        print(input)
        print("Output:")
        print(output)
        raise RuntimeError
    print("Success!")


def test_empty_string_roundtrip():
    key = "empty-string-rt"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    data = ""  # Empty string as test data

    kms_client = boto3.client("kms", region_name=region)

    keyring = KmsKeyring(kms_client, kms_key_id)

    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    get_req = {"Bucket": bucket, "Key": key}
    response = s3ec.get_object(**get_req)
    output = response["Body"].read().decode("utf-8")
    if output != data:
        print("Uh oh! Input and output don't match!")
        print("Input:")
        print(repr(data))  # Using repr to clearly show it's an empty string
        print("Output:")
        print(repr(output))
        raise RuntimeError
    print("Success! Empty string encrypted and decrypted correctly.")


def test_no_body_roundtrip():
    key = "no-body-rt"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    # Expected data when no Body is provided (empty bytes)
    expected_data = b""

    kms_client = boto3.client("kms", region_name=region)

    keyring = KmsKeyring(kms_client, kms_key_id)

    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    # Call put_object without providing a Body parameter
    s3ec.put_object(Bucket=bucket, Key=key)

    get_req = {"Bucket": bucket, "Key": key}
    response = s3ec.get_object(**get_req)
    output = response["Body"].read()

    if output != expected_data:
        print("Uh oh! Output doesn't match expected empty bytes!")
        print("Expected:")
        print(repr(expected_data))
        print("Output:")
        print(repr(output))
        raise RuntimeError
    print(
        "Success! Object with no Body parameter encrypted and decrypted correctly as empty bytes."
    )
