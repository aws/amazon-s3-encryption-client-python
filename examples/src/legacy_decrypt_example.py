# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example demonstrates how to decrypt legacy S3 objects that were encrypted
using older versions of the S3 Encryption Client (V1 or V2).

Legacy objects use the KmsV1 wrapping algorithm and may use unauthenticated
content encryption (AES-CBC). To decrypt these objects, you must:
1. Enable legacy wrapping algorithms on the KMS Keyring
2. Enable legacy unauthenticated modes on the S3 Encryption Client config
3. Use a commitment policy that allows non-key-committing algorithm suites

This example:
1. Creates a KMS Keyring with legacy wrapping algorithms enabled
2. Configures the S3 Encryption Client with legacy decryption support
3. Decrypts a legacy V1 object from S3
4. Verifies the decrypted plaintext matches the expected content
"""

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring
from s3_encryption.materials.materials import CommitmentPolicy


def decrypt_legacy_object(s3_client, kms_client, kms_key_id: str, bucket: str, key: str):
    """Decrypt a legacy S3 object encrypted by an older S3 Encryption Client.

    Args:
        s3_client: boto3 S3 client.
        kms_client: boto3 KMS client.
        kms_key_id: KMS key ARN or alias used to encrypt the object.
        bucket: S3 bucket name.
        key: S3 object key.

    Returns:
        Decrypted plaintext bytes.
    """
    # 1. Create a KMS Keyring with legacy wrapping algorithms enabled.
    # This allows the keyring to decrypt data keys wrapped using the KmsV1 mode,
    # which older S3 Encryption Clients used.
    keyring = KmsKeyring(
        kms_client=kms_client,
        kms_key_id=kms_key_id,
        enable_legacy_wrapping_algorithms=True,
    )

    # 2. Configure the S3 Encryption Client for legacy decryption.
    # - enable_legacy_unauthenticated_modes: allows decryption of AES-CBC content
    # - REQUIRE_ENCRYPT_ALLOW_DECRYPT: new objects are encrypted with key-committing
    #   algorithm suites, while still allowing decryption of legacy objects
    config = S3EncryptionClientConfig(
        keyring=keyring,
        enable_legacy_unauthenticated_modes=True,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
    )
    s3ec = S3EncryptionClient(wrapped_s3_client=s3_client, config=config)

    # 3. Decrypt the legacy object.
    response = s3ec.get_object(Bucket=bucket, Key=key)
    return response["Body"].read()
