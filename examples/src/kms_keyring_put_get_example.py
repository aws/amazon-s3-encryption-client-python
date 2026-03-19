# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example demonstrates a basic put/get roundtrip using the S3 Encryption Client
with a KMS Keyring.

The KMS Keyring uses a symmetric KMS key to generate and decrypt data keys.
The S3 Encryption Client encrypts the object before uploading to S3 and decrypts
it on download, so the data is protected at rest.

This example:
1. Creates a KMS Keyring with the provided KMS key ID
2. Wraps a boto3 S3 client with the S3 Encryption Client
3. Creates an encryption context bound to the S3 bucket and key
4. Puts an encrypted object to S3
5. Gets and decrypts the object from S3
6. Verifies the decrypted plaintext matches the original

Here is an example KMS Key Policy statement that would validate the
Encryption Context used in this example::

    Sid: RestrictToEncryptionContextBucket
    Effect: Allow
    Principal:
      AWS: "arn:aws:iam::<account-id>:role/<role-name>"
    Action:
      - kms:GenerateDataKey
      - kms:Decrypt
    Resource: "*"
    Condition:
      StringEquals:
        "kms:EncryptionContext:aws-s3-bucket": "<bucket>"
"""

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring

EXAMPLE_DATA: bytes = b"Hello, S3 Encryption Client!"


def kms_keyring_put_get(s3_client, kms_client, kms_key_id: str, bucket: str, key: str):
    """Demonstrate an encrypt/decrypt cycle using a KMS Keyring with S3.

    Args:
        s3_client: boto3 S3 client.
        kms_client: boto3 KMS client.
        kms_key_id: KMS key ARN or alias to use for encryption/decryption.
        bucket: S3 bucket name.
        key: S3 object key.
    """
    # 1. Create a KMS Keyring.
    keyring = KmsKeyring(kms_client=kms_client, kms_key_id=kms_key_id)

    # 2. Wrap the S3 client with the S3 Encryption Client.
    # The default commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    # which enforces key-committing algorithm suites on both encrypt and decrypt.
    config = S3EncryptionClientConfig(keyring=keyring)
    s3ec = S3EncryptionClient(wrapped_s3_client=s3_client, config=config)

    # 3. Create an encryption context.
    # The encryption context is a set of key-value pairs that are bound to the ciphertext.
    # Including the bucket and key ensures the ciphertext is tied to this specific S3 object.
    # This will also be visible to KMS when evaluating key policies.
    # See the example KMS Key Policy in this module's docstring.
    # The encryption context is optional, but strongly recommended.
    encryption_context = {
        "aws-s3-bucket": bucket,
        "aws-s3-key": key,
    }

    # 4. Put an encrypted object.
    s3ec.put_object(Bucket=bucket, Key=key, Body=EXAMPLE_DATA, EncryptionContext=encryption_context)

    # 5. Get and decrypt the object.
    # If you specified an encryption context during encryption,
    # you must provide the same encryption context during decryption.
    response = s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext=encryption_context)
    plaintext = response["Body"].read()

    # 6. Optional Verify the decrypted plaintext matches the original.
    assert plaintext == EXAMPLE_DATA, "Decrypted plaintext does not match original data"
