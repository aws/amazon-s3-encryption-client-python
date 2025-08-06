# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from datetime import datetime
from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring

bucket = "s3-ec-python-v3-test"

def test_simple_roundtrip():
    key = "simple-rt"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    data = "test input for simple v3 round trip"

    kms_key_id = "arn:aws:kms:us-east-2:657301468084:key/1f469b1a-5cfa-4879-9bdf-27b3abd9b8d5"
    kms_client = boto3.client("kms", region_name="us-east-2")

    keyring = KmsKeyring(kms_client, kms_key_id)

    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)
    s3ec.put_object(Bucket=bucket, Key=key, Data=data)
    print("put object success!")
    get_req = {
        'Bucket': bucket,
        'Key': key
    }
    response = s3ec.get_object(**get_req)
    output = response['Body'].read().decode('utf-8')
    print("get succeeded!")
    print(response)
    if output != data:
        print("Uh oh! Input and output don't match!")
        print("Input:")
        print(input)
        print("Output:")
        print(output)
    else: 
        print("Success!")