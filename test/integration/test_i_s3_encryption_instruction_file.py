# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
import uuid

import boto3
import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring
from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy

# Static test objects bucket
bucket = os.environ.get("CI_S3_STATIC_TEST_BUCKET", "s3ec-static-test-objects")
region = os.environ.get("CI_AWS_REGION", "us-west-2")
# KMS key used for static test objects (S3ECTestServerKMSKey)
kms_key_id = os.environ.get(
    "CI_KMS_KEY_STATIC_TESTS",
    "arn:aws:kms:us-west-2:370957321024:key/a3889cd9-99eb-4138-a93a-aea9d52ec2ef",
)

# Static test object keys created by Java S3EC V4
TEST_OBJECTS = {
    "v1_instruction_file": "static-v1-instruction-file-from-java-v1",
    "v2_instruction_file": "static-v2-instruction-file-from-java-v4",
    "v3_instruction_file": "static-v3-instruction-file-from-java-v4",
    "negative_v2_instruction_file": "NEGATIVE-static-v2-instruction-file-test-from-java-v4",
    "large_v2_instruction_file": "static-large-v2-instruction-file-from-java-v4-52428800",
    "large_v3_instruction_file": "static-large-v3-instruction-file-from-java-v4-52428800",
}


def test_decrypt_v1_instruction_file():
    """Test decrypting V1 object with instruction file.

    V1 format uses ALG_AES_256_CBC_IV16_NO_KDF (CBC mode, no key commitment).
    Object encrypted by Java S3EC V1 with instruction file enabled.
    """
    key = TEST_OBJECTS["v1_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id, enable_legacy_wrapping_algorithms=True)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        enable_legacy_unauthenticated_modes=True,
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")

    assert output == "static-v1-instruction-file-from-java-v1"
    print("Success! V1 instruction file decryption completed.")


@pytest.mark.parametrize("delayed_auth", [False, True], ids=["buffered", "delayed-auth"])
def test_decrypt_v2_instruction_file(delayed_auth):
    """Test decrypting V2 object with instruction file.

    V2 format uses ALG_AES_256_GCM_IV12_TAG16_NO_KDF (no key commitment).
    Object encrypted by Java S3EC V4 with instruction file enabled.
    """
    key = TEST_OBJECTS["v2_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        enable_delayed_authentication=delayed_auth,
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")

    assert output == "static-v2-instruction-file-from-java-v4"
    print("Success! V2 instruction file decryption completed.")


def test_decrypt_v3_instruction_file():
    """Test decrypting V3 object with instruction file.

    V3 format uses ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY (with key commitment).
    Object encrypted by Java S3EC V4 with instruction file enabled.
    """
    key = TEST_OBJECTS["v3_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")

    assert output == "static-v3-instruction-file-from-java-v4"
    print("Success! V3 instruction file decryption completed.")


def test_decrypt_invalid_instruction_file():
    """Test that decrypting with an invalid instruction file raises an error.

    The NEGATIVE test object has an invalid instruction file that should
    cause the S3 Encryption Client to raise an exception during decryption.
    """
    from s3_encryption.exceptions import S3EncryptionClientError

    key = TEST_OBJECTS["negative_v2_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    with pytest.raises(S3EncryptionClientError) as exc_info:
        s3ec.get_object(Bucket=bucket, Key=key)

    print(f"Error message: {exc_info.value}")


def test_decrypt_instruction_file_wrong_suffix_raises():
    """Decryption MUST fail when the instruction file suffix doesn't match the actual S3 object."""
    from s3_encryption.exceptions import S3EncryptionClientError

    key = TEST_OBJECTS["v3_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        instruction_file_suffix=".wrong-suffix",
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    with pytest.raises(S3EncryptionClientError, match="Instruction file body is empty"):
        s3ec.get_object(Bucket=bucket, Key=key)


def test_decrypt_v3_instruction_file_custom_suffix():
    """Test decrypting V3 object with a custom instruction file suffix."""
    key = TEST_OBJECTS["v3_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(
        Bucket=bucket, Key=key, InstructionFileSuffix=".custom-suffix-instruction"
    )
    output = response["Body"].read().decode("utf-8")

    assert output == "static-v3-instruction-file-from-java-v4"
    print("Success! V3 custom suffix instruction file decryption completed.")


@pytest.mark.parametrize("delayed_auth", [False, True], ids=["buffered", "delayed-auth"])
def test_decrypt_v2_instruction_file_custom_suffix(delayed_auth):
    """Test decrypting V2 object with a custom instruction file suffix."""
    key = TEST_OBJECTS["v2_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        enable_delayed_authentication=delayed_auth,
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(
        Bucket=bucket, Key=key, InstructionFileSuffix=".custom-suffix-instruction"
    )
    output = response["Body"].read().decode("utf-8")

    assert output == "static-v2-instruction-file-from-java-v4"
    print("Success! V2 custom suffix instruction file decryption completed.")


def test_get_nonexistent_object_raises_s3_encryption_client_error():
    """Test that getting a non-existent object raises S3EncryptionClientError.

    Matches Java S3EC behavior: NoSuchKeyException is wrapped in
    S3EncryptionClientException with the original as the cause.
    """
    from botocore.exceptions import ClientError

    from s3_encryption.exceptions import S3EncryptionClientError

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")

    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    with pytest.raises(
        S3EncryptionClientError, match="Failed to retrieve and/or decrypt object"
    ) as exc_info:
        s3ec.get_object(Bucket=bucket, Key="this-object-does-not-exist")

    assert isinstance(exc_info.value.__cause__, ClientError)


def test_get_object_with_missing_instruction_file_raises_s3_encryption_client_error():
    """Test that a missing instruction file raises S3EncryptionClientError.

    When an object has no encryption metadata and the instruction file
    also doesn't exist, the error should indicate the instruction file issue.
    """
    from s3_encryption.exceptions import S3EncryptionClientError

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")

    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    # Use a separate plain S3 client to put an unencrypted object
    plain_s3 = boto3.client("s3")
    test_key = f"plain-object-no-instruction-file-{uuid.uuid4()}"
    plain_s3.put_object(Bucket=bucket, Key=test_key, Body=b"hello")

    try:
        with pytest.raises(S3EncryptionClientError, match="Instruction file body is empty"):
            s3ec.get_object(Bucket=bucket, Key=test_key)
    finally:
        plain_s3.delete_object(Bucket=bucket, Key=test_key)


LARGE_FILE_SIZE = 52428800  # 50 MB


def test_decrypt_large_v2_instruction_file_delayed_auth():
    """Test streaming decryption of a 50 MB V2 object with delayed authentication."""
    key = TEST_OBJECTS["large_v2_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")

    config = S3EncryptionClientConfig(
        keyring,
        enable_delayed_authentication=True,
        encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(Bucket=bucket, Key=key)
    total = 0
    while chunk := response["Body"].read(65536):
        total += len(chunk)

    assert total == LARGE_FILE_SIZE


@pytest.mark.skip(reason="V3 large file not yet written to static bucket")
def test_decrypt_large_v3_instruction_file_delayed_auth():
    """Test streaming decryption of a 50 MB V3 object with delayed authentication."""
    key = TEST_OBJECTS["large_v3_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring, enable_delayed_authentication=True)
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(Bucket=bucket, Key=key)
    total = 0
    while chunk := response["Body"].read(65536):
        total += len(chunk)

    assert total == LARGE_FILE_SIZE
