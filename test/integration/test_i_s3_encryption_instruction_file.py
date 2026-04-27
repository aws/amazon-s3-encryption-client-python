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
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    with pytest.raises(S3EncryptionClientError, match="Instruction file body is empty"):
        s3ec.get_object(Bucket=bucket, Key=key, InstructionFileSuffix=".wrong-suffix")


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


# --- InstructionFileConfig integration tests ---


def test_instruction_file_config_disabled_raises_on_instruction_file_object():
    """When instruction file get is disabled, decrypting an instruction-file object MUST fail."""
    from s3_encryption.exceptions import S3EncryptionClientError
    from s3_encryption.instruction_file_config import InstructionFileConfig

    key = TEST_OBJECTS["v3_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        instruction_file_config=InstructionFileConfig(disable_get_object=True),
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    with pytest.raises(
        S3EncryptionClientError, match="Exception encountered while fetching Instruction File"
    ):
        s3ec.get_object(Bucket=bucket, Key=key)


def test_instruction_file_config_enabled_still_decrypts():
    """When instruction file get is explicitly enabled, decryption MUST succeed as before."""
    from s3_encryption.instruction_file_config import InstructionFileConfig

    key = TEST_OBJECTS["v3_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        instruction_file_config=InstructionFileConfig(disable_get_object=False),
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")

    assert output == "static-v3-instruction-file-from-java-v4"


def test_instruction_file_config_disabled_allows_non_instruction_file_objects():
    """When instruction file get is disabled, objects with metadata in headers MUST still decrypt."""
    from s3_encryption.instruction_file_config import InstructionFileConfig

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")

    # First, put an object using default config (metadata in object headers)
    put_config = S3EncryptionClientConfig(keyring)
    put_client = S3EncryptionClient(boto3.client("s3"), put_config)

    test_key = f"instruction-file-config-test-{uuid.uuid4()}"
    plaintext = b"hello from instruction file config test"
    put_client.put_object(Bucket=bucket, Key=test_key, Body=plaintext)

    try:
        # Now decrypt with instruction file get disabled
        config = S3EncryptionClientConfig(
            keyring,
            instruction_file_config=InstructionFileConfig(disable_get_object=True),
        )
        s3ec = S3EncryptionClient(wrapped_client, config)

        response = s3ec.get_object(Bucket=bucket, Key=test_key)
        output = response["Body"].read()

        assert output == plaintext
    finally:
        wrapped_client.delete_object(Bucket=bucket, Key=test_key)


def test_instruction_file_config_default_still_decrypts_instruction_files():
    """Default InstructionFileConfig (no explicit config) MUST still decrypt instruction files."""
    key = TEST_OBJECTS["v3_instruction_file"]

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    # No instruction_file_config specified — should use default (enabled)
    config = S3EncryptionClientConfig(
        keyring,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")

    assert output == "static-v3-instruction-file-from-java-v4"


# --- InstructionFileConfig delete_object / delete_objects integration tests ---


def _object_exists(bucket_name, key_name):
    """Return True if the object exists in the bucket."""
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3")
    try:
        s3.head_object(Bucket=bucket_name, Key=key_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return False
        raise


def test_delete_object_skips_instruction_file_when_disabled():
    """delete_object with disable_delete_object=True must NOT delete the instruction file."""
    from s3_encryption.instruction_file_config import InstructionFileConfig

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    plain_s3 = boto3.client("s3")

    test_key = f"ifc-delete-obj-skip-{uuid.uuid4()}"
    instr_key = test_key + ".instruction"

    # Put an encrypted object and a fake instruction file
    default_client = S3EncryptionClient(boto3.client("s3"), S3EncryptionClientConfig(keyring))
    default_client.put_object(Bucket=bucket, Key=test_key, Body=b"data")
    plain_s3.put_object(Bucket=bucket, Key=instr_key, Body=b"{}")

    try:
        # Delete with instruction file deletion disabled
        config = S3EncryptionClientConfig(
            keyring,
            instruction_file_config=InstructionFileConfig(disable_delete_object=True),
        )
        s3ec = S3EncryptionClient(boto3.client("s3"), config)
        s3ec.delete_object(Bucket=bucket, Key=test_key)

        # Object should be gone, instruction file should remain
        assert not _object_exists(bucket, test_key)
        assert _object_exists(bucket, instr_key)
    finally:
        # Clean up the instruction file
        plain_s3.delete_object(Bucket=bucket, Key=instr_key)


def test_delete_object_deletes_instruction_file_when_not_disabled():
    """delete_object with default config must delete the instruction file."""
    from s3_encryption.instruction_file_config import InstructionFileConfig

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    plain_s3 = boto3.client("s3")

    test_key = f"ifc-delete-obj-default-{uuid.uuid4()}"
    instr_key = test_key + ".instruction"

    default_client = S3EncryptionClient(boto3.client("s3"), S3EncryptionClientConfig(keyring))
    default_client.put_object(Bucket=bucket, Key=test_key, Body=b"data")
    plain_s3.put_object(Bucket=bucket, Key=instr_key, Body=b"{}")

    # Delete with default config (instruction file deletion enabled)
    config = S3EncryptionClientConfig(
        keyring,
        instruction_file_config=InstructionFileConfig(disable_delete_object=False),
    )
    s3ec = S3EncryptionClient(boto3.client("s3"), config)
    s3ec.delete_object(Bucket=bucket, Key=test_key)

    assert not _object_exists(bucket, test_key)
    assert not _object_exists(bucket, instr_key)


def test_delete_objects_skips_instruction_files_when_disabled():
    """delete_objects with disable_delete_objects=True must NOT delete instruction files."""
    from s3_encryption.instruction_file_config import InstructionFileConfig

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    plain_s3 = boto3.client("s3")

    keys = [f"ifc-delete-objs-skip-{uuid.uuid4()}" for _ in range(2)]
    instr_keys = [k + ".instruction" for k in keys]

    default_client = S3EncryptionClient(boto3.client("s3"), S3EncryptionClientConfig(keyring))
    for key in keys:
        default_client.put_object(Bucket=bucket, Key=key, Body=b"data")
    for instr_key in instr_keys:
        plain_s3.put_object(Bucket=bucket, Key=instr_key, Body=b"{}")

    try:
        config = S3EncryptionClientConfig(
            keyring,
            instruction_file_config=InstructionFileConfig(disable_delete_objects=True),
        )
        s3ec = S3EncryptionClient(boto3.client("s3"), config)
        s3ec.delete_objects(
            Bucket=bucket,
            Delete={"Objects": [{"Key": k} for k in keys]},
        )

        for key in keys:
            assert not _object_exists(bucket, key)
        for instr_key in instr_keys:
            assert _object_exists(bucket, instr_key)
    finally:
        plain_s3.delete_objects(
            Bucket=bucket,
            Delete={"Objects": [{"Key": k} for k in instr_keys]},
        )


def test_delete_objects_deletes_instruction_files_when_not_disabled():
    """delete_objects with default config must delete instruction files."""
    from s3_encryption.instruction_file_config import InstructionFileConfig

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    plain_s3 = boto3.client("s3")

    keys = [f"ifc-delete-objs-default-{uuid.uuid4()}" for _ in range(2)]
    instr_keys = [k + ".instruction" for k in keys]

    default_client = S3EncryptionClient(boto3.client("s3"), S3EncryptionClientConfig(keyring))
    for key in keys:
        default_client.put_object(Bucket=bucket, Key=key, Body=b"data")
    for instr_key in instr_keys:
        plain_s3.put_object(Bucket=bucket, Key=instr_key, Body=b"{}")

    config = S3EncryptionClientConfig(
        keyring,
        instruction_file_config=InstructionFileConfig(disable_delete_objects=False),
    )
    s3ec = S3EncryptionClient(boto3.client("s3"), config)
    s3ec.delete_objects(
        Bucket=bucket,
        Delete={"Objects": [{"Key": k} for k in keys]},
    )

    for key in keys:
        assert not _object_exists(bucket, key)
    for instr_key in instr_keys:
        assert not _object_exists(bucket, instr_key)
