# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from datetime import datetime

import boto3
import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.kms_keyring import KmsKeyring
from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy

bucket = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
region = os.environ.get("CI_AWS_REGION", "us-west-2")
kms_key_id = os.environ.get(
    "CI_KMS_KEY_ALIAS", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"
)

# Parameterized algorithm suite configurations.
# Each entry is (algorithm_suite, commitment_policy, id_label).
# "default" uses the client defaults (KC GCM + Require/Require).
ALGORITHM_CONFIGS = [
    pytest.param(
        AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        id="AES_GCM",
    ),
    pytest.param(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        id="KC_GCM",
    ),
]


def _make_client(algorithm_suite, commitment_policy):
    """Create an S3EncryptionClient with the given algorithm config."""
    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        encryption_algorithm=algorithm_suite,
        commitment_policy=commitment_policy,
    )
    return S3EncryptionClient(wrapped_client, config)


def _unique_key(prefix):
    """Generate a unique S3 key with a timestamp suffix."""
    return prefix + datetime.now().strftime("%Y-%m-%d-%H:%M:%S-%f")


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_simple_roundtrip_ascii_string(algorithm_suite, commitment_policy):
    key = _unique_key("simple-rt-")
    data = "test input for simple v3 round trip"

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")
    assert output == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_empty_string_roundtrip(algorithm_suite, commitment_policy):
    key = _unique_key("empty-string-rt-")
    data = ""

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")
    assert output == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_no_body_roundtrip(algorithm_suite, commitment_policy):
    key = _unique_key("no-body-rt-")
    expected_data = b""

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key)
    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read()
    assert output == expected_data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_unicode_string_roundtrip(algorithm_suite, commitment_policy):
    key = _unique_key("unicode-string-rt-")
    data = "Unicode test: 你好, こんにちは, 안녕하세요, Привет, مرحبا, ¡Hola!, ½⅓¼⅕⅙⅐⅛⅑⅒⅔⅖⅗⅘⅙⅚⅜⅝⅞"

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")
    assert output == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_specific_encoding_utf8_roundtrip(algorithm_suite, commitment_policy):
    key = _unique_key("utf8-encoding-rt-")
    data = "UTF-8 encoding test: 你好, こんにちは, 안녕하세요, Привет, مرحبا, ¡Hola!"
    encoded_data = data.encode("utf-8")

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=encoded_data)
    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("utf-8")
    assert output == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_specific_encoding_latin1_roundtrip(algorithm_suite, commitment_policy):
    key = _unique_key("latin1-encoding-rt-")
    data = "Latin-1 encoding test: éèêë àâäãåá çñ ¿¡ øæå ØÆÅÉÈÊËÀÂÄÃÅÁ"
    encoded_data = data.encode("latin-1")

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=encoded_data)
    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read().decode("latin-1")
    assert output == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_binary_data_roundtrip(algorithm_suite, commitment_policy):
    key = _unique_key("binary-data-rt-")
    data = bytes(range(256))

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read()
    assert output == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_bytesio_body_roundtrip(algorithm_suite, commitment_policy):
    """Test that a BytesIO body is encrypted and decrypted correctly."""
    from io import BytesIO

    key = _unique_key("bytesio-body-rt-")
    data = b"BytesIO round trip test data"

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=BytesIO(data))
    response = s3ec.get_object(Bucket=bucket, Key=key)
    output = response["Body"].read()
    assert output == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_invalid_body_types(algorithm_suite, commitment_policy):
    """Test that put_object raises an exception when given invalid body types."""
    key = _unique_key("invalid-body-type-")

    s3ec = _make_client(algorithm_suite, commitment_policy)

    for body in [42, 3.14, [1, 2, 3], {"key": "value"}, True, None]:
        with pytest.raises(S3EncryptionClientError) as excinfo:
            s3ec.put_object(Bucket=bucket, Key=key, Body=body)
        assert "Invalid type for parameter Body" in str(excinfo.value)


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_user_metadata_preservation(algorithm_suite, commitment_policy):
    """Test that user-provided metadata is preserved during encryption."""
    key = _unique_key("metadata-preservation-rt-")
    data = "Test data with user metadata"
    user_metadata = {
        "author": "test-user",
        "version": "1.0",
        "description": "Test object with custom metadata",
    }

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data, Metadata=user_metadata)
    response = s3ec.get_object(Bucket=bucket, Key=key)

    output = response["Body"].read().decode("utf-8")
    assert output == data

    returned_metadata = response.get("Metadata", {})
    for key_name, expected_value in user_metadata.items():
        assert key_name in returned_metadata, f"User metadata key '{key_name}' is missing"
        assert returned_metadata[key_name] == expected_value


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_encryption_context_roundtrip(algorithm_suite, commitment_policy):
    """Test that EncryptionContext is properly used during encryption and required for decryption."""
    key = _unique_key("encryption-context-rt-")
    data = "Test data with encryption context"
    encryption_context = {
        "department": "engineering",
        "project": "s3-encryption",
        "environment": "test",
    }

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)
    response = s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext=encryption_context)

    output = response["Body"].read().decode("utf-8")
    assert output == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_encryption_context_mismatch(algorithm_suite, commitment_policy):
    """Test that decryption fails when EncryptionContext doesn't match."""
    key = _unique_key("encryption-context-mismatch-")
    data = "Test data with encryption context"
    encryption_context = {"department": "engineering", "project": "s3-encryption"}
    wrong_encryption_context = {"department": "marketing", "project": "s3-encryption"}

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

    with pytest.raises(S3EncryptionClientError):
        s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext=wrong_encryption_context)


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_encryption_context_missing_on_decrypt(algorithm_suite, commitment_policy):
    """Test that decryption fails when encryption context is not provided for an object encrypted with context."""
    key = _unique_key("encryption-context-missing-")
    data = "Test data with encryption context"
    encryption_context = {"department": "engineering", "project": "s3-encryption"}

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

    with pytest.raises(S3EncryptionClientError):
        s3ec.get_object(Bucket=bucket, Key=key)


# Expected metadata key that identifies the content encryption algorithm,
# keyed by algorithm suite.
_EXPECTED_ALGORITHM_METADATA = {
    AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF: ("x-amz-cek-alg", "AES/GCM/NoPadding"),
    AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY: ("x-amz-c", "115"),
}


##= specification/s3-encryption/encryption.md#content-encryption
##= type=test
##% The S3EC MUST use the encryption algorithm configured during
##% [client](./client.md) initialization.
@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_put_object_uses_configured_algorithm(algorithm_suite, commitment_policy):
    """PutObject MUST encrypt using the algorithm suite configured at client init."""
    key = _unique_key("configured-alg-")
    data = b"test configured algorithm"

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)

    # Read back with a plain S3 client to inspect the raw metadata
    plain_s3 = boto3.client("s3")
    response = plain_s3.head_object(Bucket=bucket, Key=key)
    metadata = response.get("Metadata", {})

    meta_key, expected_value = _EXPECTED_ALGORITHM_METADATA[algorithm_suite]
    assert meta_key in metadata, f"Expected metadata key '{meta_key}' not found in {metadata}"
    assert metadata[meta_key] == expected_value


##= specification/s3-encryption/client.md#enable-delayed-authentication
##= type=test
##% The S3EC MUST support the option to enable or disable Delayed Authentication mode.
@pytest.mark.parametrize("enable_delayed_auth", [False, True], ids=["buffered", "delayed-auth"])
def test_delayed_authentication_mode(enable_delayed_auth):
    """S3EC MUST support enabling and disabling delayed authentication."""
    key = _unique_key("delayed-auth-mode-")
    data = b"test delayed authentication mode"

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        enable_delayed_authentication=enable_delayed_auth,
    )
    s3ec = S3EncryptionClient(wrapped_client, config)

    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    response = s3ec.get_object(Bucket=bucket, Key=key)
    assert response["Body"].read() == data


def test_inaccessible_kms_key_raises_access_denied():
    """put_object with a KMS key we lack permission for MUST surface AccessDeniedException."""
    from botocore.exceptions import ClientError

    fake_key_arn = "arn:aws:kms:us-west-2:123456789012:key/00000000-0000-0000-0000-000000000000"
    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, fake_key_arn)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring=keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    key = _unique_key("access-denied-")

    with pytest.raises(S3EncryptionClientError, match="Failed to encrypt object") as exc_info:
        s3ec.put_object(Bucket=bucket, Key=key, Body=b"should fail")

    # Unwrap and verify the root cause is AccessDeniedException
    cause = exc_info.value.__cause__
    assert isinstance(cause, ClientError)
    assert cause.response["Error"]["Code"] == "AccessDeniedException"


def test_get_nonexistent_object_raises_no_such_key():
    """get_object for a key that doesn't exist MUST surface NoSuchKey."""
    from botocore.exceptions import ClientError

    s3ec = _make_client(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )

    with pytest.raises(S3EncryptionClientError, match="NoSuchKey") as exc_info:
        s3ec.get_object(Bucket=bucket, Key="this-key-definitely-does-not-exist")

    cause = exc_info.value.__cause__
    assert isinstance(cause, ClientError)
    assert cause.response["Error"]["Code"] == "NoSuchKey"


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_s3_passthrough_options_preserved(algorithm_suite, commitment_policy):
    """S3 options unrelated to encryption (e.g. StorageClass, ContentType) MUST be applied."""
    key = _unique_key("passthrough-opts-")
    data = b'{"message": "hello"}'

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        StorageClass="STANDARD_IA",
        ContentType="application/json",
        ContentDisposition="attachment; filename=test.json",
    )

    # Read back with head_object via the S3EC instance to verify the options were applied
    head = s3ec.head_object(Bucket=bucket, Key=key)
    assert head["StorageClass"] == "STANDARD_IA"
    assert head["ContentType"] == "application/json"
    assert head["ContentDisposition"] == "attachment; filename=test.json"

    # Also verify the data round-trips correctly
    response = s3ec.get_object(Bucket=bucket, Key=key)
    assert response["Body"].read() == data


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
def test_copy_object_then_decrypt(algorithm_suite, commitment_policy):
    """An encrypted object copied via CopyObject MUST still decrypt correctly."""
    src_key = _unique_key("copy-src-")
    dst_key = _unique_key("copy-dst-")
    data = b"copy object round trip test"

    s3ec = _make_client(algorithm_suite, commitment_policy)
    s3ec.put_object(Bucket=bucket, Key=src_key, Body=data)

    # Copy using the S3EC instance (copy_object proxies to the wrapped S3 client)
    s3ec.copy_object(
        Bucket=bucket,
        Key=dst_key,
        CopySource={"Bucket": bucket, "Key": src_key},
        MetadataDirective="COPY",
    )

    # Decrypt the copied object
    response = s3ec.get_object(Bucket=bucket, Key=dst_key)
    assert response["Body"].read() == data
