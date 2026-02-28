# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Instruction file handling for S3 Encryption Client.

This module provides utilities for fetching and parsing instruction files
that contain encryption metadata for S3 objects.
"""

import json
from typing import Any

from .exceptions import S3EncryptionClientError
from .metadata import VALID_S3EC_METADATA_KEYS


def parse_instruction_file(instruction_data: bytes, instruction_key: str) -> dict[str, Any]:
    """Parse and validate instruction file data.

    This function strictly validates that:
    1. The instruction file body is valid JSON
    2. The JSON contains only S3 Encryption Client metadata keys

    Args:
        instruction_data: Raw bytes from instruction file body
        instruction_key: Instruction file key (for error messages)

    Returns:
        dict: Parsed JSON metadata from instruction file

    Raises:
        S3EncryptionClientError: If the instruction file is not valid JSON
            or contains non-S3EC metadata keys
    """
    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=citation
    ##% The content metadata stored in the Instruction File MUST be serialized to a JSON string.

    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=citation
    ##% The serialized JSON string MUST be the only contents of the Instruction File.

    # Validate JSON format
    try:
        metadata = json.loads(instruction_data)
    except json.JSONDecodeError as e:
        raise S3EncryptionClientError(
            f"Instruction file is not valid JSON: {instruction_key}"
        ) from e

    # Validate that it's a dictionary
    if not isinstance(metadata, dict):
        raise S3EncryptionClientError(
            f"Instruction file must contain a JSON object, "
            f"got {type(metadata).__name__}: {instruction_key}"
        )

    # Validate that all keys are S3EC metadata keys
    invalid_keys = set(metadata.keys()) - VALID_S3EC_METADATA_KEYS
    if invalid_keys:
        raise S3EncryptionClientError(
            f"Instruction file contains invalid keys: {invalid_keys} in {instruction_key}"
        )

    return metadata


def fetch_instruction_file(
    s3_client, bucket: str, key: str, suffix: str = ".instruction"
) -> dict[str, Any]:
    """Fetch and parse an instruction file from S3.

    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=citation
    ##% The S3EC SHOULD support providing a custom Instruction File suffix
    ##% on GetObject requests, regardless of whether or not re-encryption is supported.

    This function:
    1. Fetches the instruction file in plaintext mode
    2. Returns the parsed metadata from the response Metadata field

    S3EncryptionClientPlugin's event handler (on_get_object_after_call) handles:
    - Verifying the x-amz-crypto-instr-file marker is present
    - Parsing and validating the instruction file content
    - Placing parsed metadata in response["Metadata"]

    Args:
        s3_client: Boto3 S3 client to use for fetching
        bucket: S3 bucket name
        key: S3 object key
        suffix: Instruction file suffix (default: .instruction)

    Returns:
        dict: Parsed JSON metadata from instruction file

    Raises:
        S3EncryptionClientError: If the instruction file marker is missing,
            the instruction file is not valid JSON, or contains non-S3EC metadata keys
    """
    instruction_key = key + suffix

    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=citation
    ##% The default Instruction File behavior uses the same S3 object key
    ##% as its associated object suffixed with ".instruction".

    # Set plaintext mode flag in thread-local context before calling get_object
    # This will be checked by the event handler to skip decryption
    if hasattr(s3_client, "_s3ec_plugin_context"):
        s3_client._s3ec_plugin_context.plaintext_mode = True
        s3_client._s3ec_plugin_context.key = instruction_key
    else:
        raise S3EncryptionClientError(
            f"Could not fetch instruction file without "
            f"the S3 Encryption Client Plugin installed. Instruction key: {instruction_key}"
        )

    try:
        response = s3_client.get_object(Bucket=bucket, Key=instruction_key)
    finally:
        # Clear the flags after the call
        if hasattr(s3_client, "_s3ec_plugin_context"):
            s3_client._s3ec_plugin_context.plaintext_mode = False

    # In plaintext mode, the event handler places parsed metadata in Metadata field
    metadata = response.get("Metadata", {})

    # Verify metadata is not empty
    if not metadata:
        raise S3EncryptionClientError(
            f"Instruction file returned empty metadata: {instruction_key}"
        )

    # Verify metadata contains at least one S3EC key
    has_s3ec_key = any(key in VALID_S3EC_METADATA_KEYS for key in metadata)
    if not has_s3ec_key:
        raise S3EncryptionClientError(
            f"Instruction file metadata does not contain any S3EC keys: {instruction_key}"
        )

    return metadata
