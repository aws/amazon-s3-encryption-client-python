# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from datetime import datetime

import boto3
import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.kms_keyring import KmsKeyring

bucket = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
region = os.environ.get("CI_AWS_REGION", "us-west-2")
kms_key_id = os.environ.get(
    "CI_KMS_KEY_ALIAS", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"
)


def test_simple_roundtrip_ascii_string():
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


def test_unicode_string_roundtrip():
    key = "unicode-string-rt"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    # String with unusual Unicode characters
    data = "Unicode test: 你好, こんにちは, 안녕하세요, Привет, مرحبا, ¡Hola!, ½⅓¼⅕⅙⅐⅛⅑⅒⅔⅖⅗⅘⅙⅚⅜⅝⅞"

    kms_client = boto3.client("kms", region_name=region)

    keyring = KmsKeyring(kms_client, kms_key_id)

    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)
    get_req = {"Bucket": bucket, "Key": key}
    response = s3ec.get_object(**get_req)

    # Boto3 encodes to utf-8 in put_object but does not
    # decode in get_object; do so manually to complete the
    # round trip
    output = response["Body"].read().decode("utf-8")
    if output != data:
        print("Uh oh! Input and output don't match!")
        print("Input:")
        print(repr(data))
        print("Output:")
        print(repr(output))
        raise RuntimeError
    print("Success! Unicode string encrypted and decrypted correctly.")


def test_specific_encoding_utf8_roundtrip():
    key = "utf8-encoding-rt"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    # String with mixed characters
    data = "UTF-8 encoding test: 你好, こんにちは, 안녕하세요, Привет, مرحبا, ¡Hola!"

    # Explicitly encode as UTF-8 before sending
    encoded_data = data.encode("utf-8")

    kms_client = boto3.client("kms", region_name=region)

    keyring = KmsKeyring(kms_client, kms_key_id)

    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    # Pass the pre-encoded bytes to put_object
    s3ec.put_object(Bucket=bucket, Key=key, Body=encoded_data)

    get_req = {"Bucket": bucket, "Key": key}
    response = s3ec.get_object(**get_req)

    # Read raw bytes and decode with the same encoding
    output = response["Body"].read().decode("utf-8")

    if output != data:
        print("Uh oh! Input and output don't match!")
        print("Input:")
        print(repr(data))
        print("Output:")
        print(repr(output))
        raise RuntimeError
    print("Success! UTF-8 encoded string encrypted and decrypted correctly.")


def test_specific_encoding_latin1_roundtrip():
    key = "latin1-encoding-rt"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    # String with Latin-1 compatible characters
    data = "Latin-1 encoding test: éèêë àâäãåá çñ ¿¡ øæå ØÆÅÉÈÊËÀÂÄÃÅÁ"

    # Explicitly encode as Latin-1 before sending
    encoded_data = data.encode("latin-1")

    kms_client = boto3.client("kms", region_name=region)

    keyring = KmsKeyring(kms_client, kms_key_id)

    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    # Pass the pre-encoded bytes to put_object
    s3ec.put_object(Bucket=bucket, Key=key, Body=encoded_data)

    get_req = {"Bucket": bucket, "Key": key}
    response = s3ec.get_object(**get_req)

    # Read raw bytes and decode with the same encoding
    output = response["Body"].read().decode("latin-1")

    if output != data:
        print("Uh oh! Input and output don't match!")
        print("Input:")
        print(repr(data))
        print("Output:")
        print(repr(output))
        raise RuntimeError
    print("Success! Latin-1 encoded string encrypted and decrypted correctly.")


def test_binary_data_roundtrip():
    key = "binary-data-rt"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    # Create some binary data (not valid in any particular encoding)
    data = bytes([i for i in range(256)])

    kms_client = boto3.client("kms", region_name=region)

    keyring = KmsKeyring(kms_client, kms_key_id)

    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    # Pass the binary data directly
    s3ec.put_object(Bucket=bucket, Key=key, Body=data)

    get_req = {"Bucket": bucket, "Key": key}
    response = s3ec.get_object(**get_req)

    # Read raw bytes without decoding
    output = response["Body"].read()

    if output != data:
        print("Uh oh! Input and output don't match!")
        print("Input:")
        print(repr(data))
        print("Output:")
        print(repr(output))
        raise RuntimeError
    print("Success! Binary data encrypted and decrypted correctly.")


def test_invalid_body_types():
    """Test that put_object raises an exception when given invalid body types."""
    key = "invalid-body-type"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config)

    # Test with integer
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body=42)
    assert "not an acceptable type" in str(excinfo.value)

    # Test with float
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body=3.14)
    assert "not an acceptable type" in str(excinfo.value)

    # Test with list
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body=[1, 2, 3])
    assert "not an acceptable type" in str(excinfo.value)

    # Test with dictionary
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body={"key": "value"})
    assert "not an acceptable type" in str(excinfo.value)

    # Test with boolean
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body=True)
    assert "not an acceptable type" in str(excinfo.value)

    # Test with None (also raises an exception)
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body=None)
    assert "not an acceptable type" in str(excinfo.value)

    print("Success! All invalid body types correctly raised exceptions.")
