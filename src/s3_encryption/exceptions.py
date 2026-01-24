# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exceptions for the S3 Encryption Client.

This module contains custom exception classes used throughout the S3 Encryption Client.
"""

from botocore.exceptions import BotoCoreError


class S3EncryptionClientError(BotoCoreError):
    """Exception class for non-Security S3 Encryption Client errors."""

    fmt = "{msg}"

    def __init__(self, message="An unspecified S3 Encryption Client error occurred"):
        """Initialize the exception with a message."""
        super().__init__(msg=message)


class S3EncryptionClientSecurityError(BotoCoreError):
    """Security Exceptions for S3 Encryption Client errors."""

    fmt = "{msg}"

    def __init__(self, message="An unspecified S3 Encryption Client Security error occurred"):
        """Initialize the exception with a message."""
        super().__init__(msg=message)
