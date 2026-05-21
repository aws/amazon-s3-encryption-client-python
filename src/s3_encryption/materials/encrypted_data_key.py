# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Encrypted data key module for S3 Encryption Client.

This module provides the EncryptedDataKey class which represents an encrypted
data key used in the S3 encryption process.
"""

from attrs import define


@define
class EncryptedDataKey:
    """Class representing an encrypted data key.

    An encrypted data key contains information about the key provider
    and the encrypted data key itself.

    Attributes:
        key_provider_info (str): Information about the key provider
        key_provider_id (bytes): Identifier for the key provider
        encrypted_data_key (bytes): The encrypted data key
    """

    key_provider_info: str
    key_provider_id: bytes
    encrypted_data_key: bytes
