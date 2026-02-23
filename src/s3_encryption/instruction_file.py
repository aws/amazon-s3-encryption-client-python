# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Instruction file handling for S3 Encryption Client.

This module provides utilities for fetching and parsing instruction files
that contain encryption metadata for S3 objects.
"""

import json
from typing import Any

from .exceptions import S3EncryptionClientError

# Valid S3 Encryption Client metadata keys
VALID_S3EC_METADATA_KEYS = {
    # V1/V2 format keys
    "x-amz-key",
    "x-amz-key-v2",
    "x-amz-wrap-alg",
    "x-amz-matdesc",
    "x-amz-iv",
    "x-amz-cek-alg",
    "x-amz-tag-len",
    "x-amz-crypto-instr-file",
    # V3 format keys (compressed)
    "x-amz-c",
    "x-amz-3",
    "x-amz-m",
    "x-amz-t",
    "x-amz-w",
    "x-amz-d",
    "x-amz-i",
}


def fetch_instruction_file(
    s3_client, bucket: str, key: str, suffix: str = ".instruction"
) -> dict[str, Any]:
    """Fetch and parse an instruction file from S3.

    This function strictly validates that:
    1. The instruction file response metadata contains the x-amz-crypto-instr-file marker
    2. The instruction file body is valid JSON
    3. The JSON contains only S3 Encryption Client metadata keys

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
    response = s3_client.get_object(
        Bucket=bucket, Key=instruction_key, s3ec_internal_plaintext_mode=True
    )

    # Verify instruction file marker is present in response metadata
    response_metadata = response.get("Metadata", {})
    if "x-amz-crypto-instr-file" not in response_metadata:
        raise S3EncryptionClientError(
            f"Instruction file metadata does not contain "
            f"x-amz-crypto-instr-file marker: {instruction_key}"
        )

    instruction_data = response["Body"].read()

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
