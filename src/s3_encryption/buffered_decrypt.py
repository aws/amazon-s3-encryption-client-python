# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""One Shot decryption into a buffer."""

from io import BytesIO

from botocore.response import StreamingBody

from s3_encryption.decryptor import Decryptor


def one_shot_decrypt(streaming_body: StreamingBody, decryptor: Decryptor):
    """Decrypt a streaming object.

    Args:
        streaming_body (object): A streaming object.
        decryptor (Decryptor): Decryptor object.
    """
    plaintext = decryptor.finalize(streaming_body.read())
    return StreamingBody(BytesIO(plaintext), len(plaintext))
