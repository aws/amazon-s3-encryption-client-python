# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example demonstrates decrypting S3 objects that store their encryption
metadata in instruction files rather than S3 object metadata.

An instruction file is a companion S3 object that contains the encryption
metadata (encrypted data key, IV, algorithm, etc.) as JSON. By default,
the instruction file has the same key as the encrypted object with a
".instruction" suffix appended.

You can also use a custom instruction file suffix. This requires configuring
the S3 Encryption Client with the matching suffix.

NOTE: At this time, the S3 Encryption Client in Python ONLY supports decrypting
(reading) with instruction files; encrypting with instruction files is not supported
at this time.

This example:
1. Decrypts an object using the default instruction file suffix (".instruction")
2. Decrypts the same object using a custom instruction file suffix
"""

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring


def instruction_file_get(
    s3_client, kms_client, kms_key_id: str, bucket: str, key: str, expected_plaintext: bytes
):
    """Demonstrate decrypting objects with default and custom instruction file suffixes.

    Args:
        s3_client: boto3 S3 client.
        kms_client: boto3 KMS client.
        kms_key_id: KMS key ARN or alias used to encrypt the object.
        bucket: S3 bucket containing the encrypted object and instruction files.
        key: S3 object key of the encrypted object.
        expected_plaintext: Expected plaintext content for verification.
    """
    keyring = KmsKeyring(kms_client=kms_client, kms_key_id=kms_key_id)

    # 1. Decrypt using the default instruction file suffix (".instruction").
    # The client will fetch "<key>.instruction" for the encryption metadata.
    config = S3EncryptionClientConfig(keyring=keyring)
    s3ec = S3EncryptionClient(wrapped_s3_client=s3_client, config=config)

    response = s3ec.get_object(Bucket=bucket, Key=key)
    plaintext = response["Body"].read()
    assert plaintext == expected_plaintext, "Default suffix: decrypted plaintext does not match"

    # 2. Decrypt while specifying the Instruction File Suffix
    # InstructionFileSuffix is a per-request keyword argument on get_object,
    # so the same client can use different suffixes per request.
    response = s3ec.get_object(
        Bucket=bucket, Key=key, InstructionFileSuffix=".custom-suffix-instruction"
    )
    plaintext = response["Body"].read()
    assert plaintext == expected_plaintext, "Custom suffix: decrypted plaintext does not match"
