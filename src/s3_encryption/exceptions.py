# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exceptions for the S3 Encryption Client.

This module contains custom exception classes used throughout the S3 Encryption Client.
"""

# TODO: Data Key may be the wrong term. Materials MAY be a better term.
# To resolve, will look at the other S3 implementations.


# TODO: Should this extend BotoCoreError?
# That way a customer can catch all AWS exceptions,
# regardless if it is Crypto Tools or something else.
class S3EncryptionClientError(Exception):
    """Exception class for S3 Encryption Client errors."""


class DecryptEncryptedDataKeyError(S3EncryptionClientError):
    """The encrypted data key could not be decrypted."""


# TODO: Technically, S3EC may never encrypt data keys, just generate them...
class EncryptDataKeyError(S3EncryptionClientError):
    """The data key could not be encrypted."""


class GenerateDataKeyError(S3EncryptionClientError):
    """The data key could not be generated."""


class CommitmentPolicyError(S3EncryptionClientError):
    """The request or object does not comply with the commitment policy."""


class CommitmentViolationError(S3EncryptionClientError):
    """The object failed the Key Commitment check."""


class AlgorithmSuiteNotSupportedError(S3EncryptionClientError):
    """The request utilizes an unsupported or unkown algorithm suite."""
