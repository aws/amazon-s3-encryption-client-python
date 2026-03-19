# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example demonstrates streaming decryption with delayed authentication
using the S3 Encryption Client.

By default, the S3 Encryption Client buffers the entire ciphertext and verifies
the authentication tag before releasing any plaintext. This is the safest mode,
but requires holding the entire object in memory.

With delayed authentication enabled, plaintext is released incrementally as it
is decrypted, before the authentication tag has been verified. This allows
processing large files without buffering the entire object in memory.

WARNING: With delayed authentication, plaintext is released before it has been
authenticated. An attacker could modify the ciphertext and the client would
release tampered plaintext before detecting the modification. Only use this
mode when you need to process files too large to buffer in memory and you
understand the security implications.

This example:
1. Creates a KMS Keyring
2. Configures the S3 Encryption Client with delayed authentication enabled
3. Encrypts and uploads a large object to S3
4. Streams the decrypted object back, reading it in chunks
5. Verifies the decrypted content matches the original
"""

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring

# 10 MB of example data
EXAMPLE_DATA: bytes = b"A" * (10 * 1024 * 1024)
CHUNK_SIZE = 1024 * 1024  # 1 MB


def delayed_auth_streaming_decrypt(
    s3_client, kms_client, kms_key_id: str, bucket: str, key: str
):
    """Demonstrate streaming decryption with delayed authentication.

    Args:
        s3_client: boto3 S3 client.
        kms_client: boto3 KMS client.
        kms_key_id: KMS key ARN or alias to use for encryption/decryption.
        bucket: S3 bucket name.
        key: S3 object key.
    """
    # 1. Create a KMS Keyring.
    keyring = KmsKeyring(kms_client=kms_client, kms_key_id=kms_key_id)

    # 2. Configure the S3 Encryption Client with delayed authentication.
    config = S3EncryptionClientConfig(
        keyring=keyring,
        enable_delayed_authentication=True,
    )
    s3ec = S3EncryptionClient(wrapped_s3_client=s3_client, config=config)

    # 3. Encrypt and upload the object.
    s3ec.put_object(Bucket=bucket, Key=key, Body=EXAMPLE_DATA)

    # 4. Stream the decrypted object back in chunks.
    # With delayed authentication, plaintext is released incrementally
    # without buffering the entire object in memory.
    response = s3ec.get_object(Bucket=bucket, Key=key)
    body = response["Body"]

    chunks = []
    while True:
        chunk = body.read(CHUNK_SIZE)
        if not chunk:
            break
        chunks.append(chunk)

    plaintext = b"".join(chunks)

    # 5. Verify the decrypted content matches the original.
    assert plaintext == EXAMPLE_DATA, "Decrypted plaintext does not match original data"
