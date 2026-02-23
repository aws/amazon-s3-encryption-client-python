# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os

import boto3
import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring

# TODO(instructionFiles): Create a Static Bucket for Instruction File Messages
# TODO(instructionFiles): Add Static Bucket for Instruction File Messages to test env
bucket = os.environ.get("CI_S3_INSTRUCTION_BUCKET", "s3ec-github-test-bucket")
region = os.environ.get("CI_AWS_REGION", "us-west-2")
# TODO(instructionFiles): Add INS FILES KMS Key to test env
kms_key_id = os.environ.get(
    "CI_KMS_KEY_INSTRUCTION_FILES",
    "arn:aws:kms:us-west-2:370957321024:key/c3eafb5f-e87d-4584-9400-cf419ce5d782",
)

# Test keys for objects encrypted by Java S3EC with instruction files
TEST_OBJECTS = {
    # TODO(instructionFiles): V1 Instruction File
    "v1_instruction_file": "test-v1-cbc-instruction",
    # TODO(instructionFiles): Proper V2 Instruction File
    "v2_instruction_file": "kms-instruction-file-test-260220-105428-19668",
    # TODO(instructionFiles): V3 Instruction File
    "v3_instruction_file": "test-v3-instruction",
}


@pytest.mark.skip(reason="Requires pre-existing test objects encrypted by Java S3EC")
def test_decrypt_v1_instruction_file():
    """Test decrypting V1 object with instruction file."""
    key = TEST_OBJECTS["v1_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")

    assert output == "test data v1 cbc"
    print("Success! V1 instruction file decryption completed.")


# @pytest.mark.skip(reason="Requires pre-existing test objects encrypted by Java S3EC")
def test_decrypt_v2_instruction_file():
    """Test decrypting V2 object with instruction file."""
    key = TEST_OBJECTS["v2_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")

    assert output == "Testing encryption of instruction file with KMS Keyring"
    print("Success! V2 instruction file decryption completed.")


@pytest.mark.skip(reason="TODO: Implement test for invalid instruction file parsing")
def test_parse_invalid_instruction_file():
    """Test that parsing an invalid instruction file raises an error."""
    from s3_encryption.exceptions import S3EncryptionClientError
    from s3_encryption.instruction_file import parse_instruction_file

    # TODO: Provide invalid instruction file data
    invalid_data = b""

    with pytest.raises(S3EncryptionClientError, match="file must contain a JSON object"):
        parse_instruction_file(invalid_data, "test-key.instruction")
