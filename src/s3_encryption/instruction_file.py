# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Instruction file handling for S3 Encryption Client.

This module provides utilities for fetching and parsing instruction files
that contain encryption metadata for S3 objects.
"""

import json
from typing import Any

from botocore.exceptions import ClientError

from .exceptions import S3EncryptionClientError
from .metadata import VALID_S3EC_METADATA_KEYS


def parse_instruction_file(instruction_data: bytes, key: str) -> dict[str, Any]:
    """Parse and validate instruction file data.

    This function strictly validates that:
    1. The instruction file body is valid JSON
    2. The JSON contains only S3 Encryption Client metadata keys

    Args:
        instruction_data: Raw bytes from instruction file body
        key: Instruction file key (for error messages)

    Returns:
        dict: Parsed JSON metadata from instruction file

    Raises:
        S3EncryptionClientError: If the instruction file is not valid JSON
            or contains non-S3EC metadata keys
    """
    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=implementation
    ##% The content metadata stored in the Instruction File MUST be serialized to a JSON string.

    # Validate JSON format
    try:
        metadata = json.loads(instruction_data)
    except json.JSONDecodeError as e:
        raise S3EncryptionClientError(f"Instruction file is not valid JSON: {key}") from e

    # Validate that it's a dictionary
    if not isinstance(metadata, dict):
        raise S3EncryptionClientError(
            f"Instruction file must contain a JSON object, " f"got {type(metadata).__name__}: {key}"
        )

    # Validate that all keys are S3EC metadata keys
    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=implementation
    ##% The serialized JSON string MUST be the only contents of the Instruction File.
    invalid_keys = set(metadata.keys()) - VALID_S3EC_METADATA_KEYS
    if invalid_keys:
        raise S3EncryptionClientError(
            f"Instruction file contains invalid keys: {invalid_keys} in {key}"
        )

    return metadata


def fetch_instruction_file(s3_client, bucket: str, key: str) -> dict[str, Any]:
    """Fetch and parse an instruction file from S3.

    This function:
    1. Fetches the instruction file in plaintext mode
    2. Returns the parsed metadata from the response Metadata field

    S3EncryptionClientPlugin's event handler (on_get_object_after_call) handles:
    - Parsing and validating the instruction file content
    - Placing parsed metadata in response["Metadata"]

    Args:
        s3_client: Boto3 S3 client to use for fetching
        bucket: S3 bucket name
        key: S3 object key
    Returns:
        dict: Parsed JSON metadata from instruction file

    Raises:
        S3EncryptionClientError: If the instruction file is not valid JSON,
            or contains non-S3EC metadata keys
    """
    # Set plaintext mode flag in thread-local context before calling get_object
    # This will be checked by the event handler to skip decryption
    if hasattr(s3_client, "_s3ec_plugin_context"):
        s3_client._s3ec_plugin_context.instruction_file_mode = True
        s3_client._s3ec_plugin_context.key = key
    else:
        raise S3EncryptionClientError(
            f"Could not fetch instruction file without "
            f"the S3 Encryption Client Plugin installed. Instruction key: {key}"
        )

    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
    except ClientError as e:
        raise S3EncryptionClientError(
            "Exception encountered while fetching Instruction File."
            " Ensure the object you are attempting to decrypt has been encrypted"
            " using the S3 Encryption Client and instruction files are enabled."
        ) from e
    finally:
        # Clear the flags after the call
        if hasattr(s3_client, "_s3ec_plugin_context"):
            s3_client._s3ec_plugin_context.instruction_file_mode = False

    # In plaintext mode, the event handler places parsed metadata in Metadata field
    metadata = response.get("Metadata", {})

    # Verify metadata is not empty
    if not metadata:
        raise S3EncryptionClientError(f"Instruction file returned empty metadata: {key}")

    # Verify metadata contains at least one S3EC key
    has_s3ec_key = any(key in VALID_S3EC_METADATA_KEYS for key in metadata)
    if not has_s3ec_key:
        raise S3EncryptionClientError(
            f"Instruction file metadata does not contain any S3EC keys: {key}"
        )

    return metadata
