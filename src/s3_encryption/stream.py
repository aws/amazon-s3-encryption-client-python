# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Streaming decryption support for S3 Encryption Client."""

import io

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import S3EncryptionClientError


class BufferedDecryptingStream:
    """A stream that buffers all ciphertext, verifies the GCM auth tag, then releases plaintext.

    This matches the Java S3EC's BufferedCipherSubscriber behavior: no plaintext
    is released until the entire ciphertext has been read and authenticated.

    Implements the same read interface as botocore's StreamingBody so it can be
    used as a drop-in replacement for parsed["Body"].
    """

    def __init__(self, streaming_body, key, nonce):
        """Initialize the buffered decrypting stream.

        Args:
            streaming_body: The original StreamingBody containing ciphertext.
            key: The plaintext data key (bytes).
            nonce: The IV/nonce for AES-GCM decryption (bytes).
        """
        self._body = streaming_body
        self._key = key
        self._nonce = nonce
        self._plaintext = None

    def _decrypt(self):
        """Read all ciphertext, decrypt and verify, cache plaintext."""
        if self._plaintext is not None:
            return
        try:
            ciphertext = self._body.read()
            aesgcm = AESGCM(self._key)
            decrypted = aesgcm.decrypt(nonce=self._nonce, data=ciphertext, associated_data=None)
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to decrypt object: {e}") from e
        self._plaintext = io.BytesIO(decrypted)

    def read(self, amt=None):
        """Read decrypted data.

        Args:
            amt: Number of bytes to read. If None, reads all remaining data.

        Returns:
            bytes: Decrypted plaintext bytes.
        """
        self._decrypt()
        if amt is None:
            return self._plaintext.read()
        return self._plaintext.read(amt)

    def iter_chunks(self, chunk_size=1024):
        """Iterate over decrypted data in chunks.

        Args:
            chunk_size: Size of each chunk in bytes.

        Yields:
            bytes: Chunks of decrypted plaintext.
        """
        self._decrypt()
        while True:
            chunk = self._plaintext.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def close(self):
        """Close the underlying stream."""
        if hasattr(self._body, "close"):
            self._body.close()
