# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from datetime import datetime

import boto3
import pytest

from s3_encryption import InstructionFileSetting, S3EncryptionClient, S3EncryptionClientConfig
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
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )
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
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )
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
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )

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
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )
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
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )

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
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )

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
    data = bytes(range(256))

    kms_client = boto3.client("kms", region_name=region)

    keyring = KmsKeyring(kms_client, kms_key_id)

    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )

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
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )

    # Test with integer
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body=42)
    assert "Invalid type for parameter Body" in str(excinfo.value)

    # Test with float
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body=3.14)
    assert "Invalid type for parameter Body" in str(excinfo.value)

    # Test with list
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body=[1, 2, 3])
    assert "Invalid type for parameter Body" in str(excinfo.value)

    # Test with dictionary
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body={"key": "value"})
    assert "Invalid type for parameter Body" in str(excinfo.value)

    # Test with boolean
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body=True)
    assert "Invalid type for parameter Body" in str(excinfo.value)

    # Test with None (also raises an exception)
    with pytest.raises(S3EncryptionClientError) as excinfo:
        s3ec.put_object(Bucket=bucket, Key=key, Body=None)
    assert "Invalid type for parameter Body" in str(excinfo.value)

    print("Success! All invalid body types correctly raised exceptions.")


def test_user_metadata_preservation():
    """Test that user-provided metadata is preserved during encryption."""
    key = "metadata-preservation-rt"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    data = "Test data with user metadata"

    # User metadata to include
    user_metadata = {
        "author": "test-user",
        "version": "1.0",
        "description": "Test object with custom metadata",
    }

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )

    # Put object with user metadata
    s3ec.put_object(Bucket=bucket, Key=key, Body=data, Metadata=user_metadata)

    # Get the object back
    get_req = {"Bucket": bucket, "Key": key}
    response = s3ec.get_object(**get_req)

    # Verify the data decrypts correctly
    output = response["Body"].read().decode("utf-8")
    if output != data:
        print("Uh oh! Input and output don't match!")
        print("Input:")
        print(repr(data))
        print("Output:")
        print(repr(output))
        raise RuntimeError

    # Verify user metadata is preserved
    returned_metadata = response.get("Metadata", {})

    for key_name, expected_value in user_metadata.items():
        if key_name not in returned_metadata:
            print(f"Uh oh! User metadata key '{key_name}' is missing!")
            print("Expected metadata:")
            print(user_metadata)
            print("Returned metadata:")
            print(returned_metadata)
            raise RuntimeError

        if returned_metadata[key_name] != expected_value:
            print(f"Uh oh! User metadata value for '{key_name}' doesn't match!")
            print(f"Expected: {expected_value}")
            print(f"Got: {returned_metadata[key_name]}")
            raise RuntimeError

    print("Success! User metadata preserved correctly during encryption/decryption.")
    print(f"User metadata: {user_metadata}")
    print(f"Returned metadata keys: {list(returned_metadata.keys())}")


def test_encryption_context_roundtrip():
    """Test that EncryptionContext is properly used during encryption and required for decryption."""
    key = "encryption-context-rt"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    data = "Test data with encryption context"

    # Encryption context to use for additional authenticated data
    encryption_context = {
        "department": "engineering",
        "project": "s3-encryption",
        "environment": "test",
    }

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )

    # Put object with encryption context
    s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

    # Get the object back WITH the same encryption context
    get_req = {"Bucket": bucket, "Key": key, "EncryptionContext": encryption_context}
    response = s3ec.get_object(**get_req)

    # Verify the data decrypts correctly
    output = response["Body"].read().decode("utf-8")
    if output != data:
        print("Uh oh! Input and output don't match!")
        print("Input:")
        print(repr(data))
        print("Output:")
        print(repr(output))
        raise RuntimeError

    print("Success! Encryption context used correctly during encryption/decryption.")
    print(f"Encryption context: {encryption_context}")


def test_encryption_context_mismatch():
    """Test that decryption fails when EncryptionContext doesn't match."""
    key = "encryption-context-mismatch"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    data = "Test data with encryption context"

    # Original encryption context
    encryption_context = {"department": "engineering", "project": "s3-encryption"}

    # Wrong encryption context for decryption
    wrong_encryption_context = {"department": "marketing", "project": "s3-encryption"}

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )

    # Put object with encryption context
    s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

    # Try to get the object back with WRONG encryption context - should fail
    get_req = {"Bucket": bucket, "Key": key, "EncryptionContext": wrong_encryption_context}

    try:
        s3ec.get_object(**get_req)
        # If we get here, the test failed - decryption should have failed
        print("Uh oh! Decryption succeeded with wrong encryption context!")
        print(f"Original context: {encryption_context}")
        print(f"Wrong context used: {wrong_encryption_context}")
        raise RuntimeError("Expected decryption to fail with mismatched encryption context")
    except S3EncryptionClientError as e:
        # This is expected - decryption should fail
        print("Success! Decryption correctly failed with mismatched encryption context.")
        print(f"Error message: {str(e)}")
    except Exception as e:
        # Some other error occurred
        print(f"Unexpected error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        raise


def test_encryption_context_missing_on_decrypt():
    """Test that decryption fails when encryption context is not provided for an object encrypted with context."""
    key = "encryption-context-missing"
    key += datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

    data = "Test data with encryption context"

    # Encryption context used during encryption
    encryption_context = {"department": "engineering", "project": "s3-encryption"}

    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(
        wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE
    )

    # Put object with encryption context
    s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

    # Try to get the object back WITHOUT encryption context - should fail
    get_req = {"Bucket": bucket, "Key": key}

    try:
        s3ec.get_object(**get_req)
        # If we get here, the test failed - decryption should have failed
        print("Uh oh! Decryption succeeded without providing required encryption context!")
        print(f"Original context: {encryption_context}")
        raise RuntimeError("Expected decryption to fail when encryption context not provided")
    except S3EncryptionClientError as e:
        # This is expected - decryption should fail
        print("Success! Decryption correctly failed when encryption context was not provided.")
        print(f"Error message: {str(e)}")
    except Exception as e:
        # Some other error occurred
        print(f"Unexpected error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        raise
