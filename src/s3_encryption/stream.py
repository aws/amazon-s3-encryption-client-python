# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Streaming decryption support for S3 Encryption Client."""

import io

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import S3EncryptionClientError

GCM_TAG_LENGTH = 16


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


##= specification/s3-encryption/client.md#enable-delayed-authentication
##= type=implementation
##% When enabled, the S3EC MAY release plaintext from a stream which has not been authenticated.
class DelayedAuthDecryptingStream:
    """A stream that releases plaintext before GCM tag verification.

    Matches the Java S3EC's CipherSubscriber: plaintext is released incrementally
    via cipher.update(), and the GCM tag is only verified when the stream is fully
    consumed. Data read before finalization is unauthenticated.
    """

    def __init__(self, streaming_body, key, nonce):
        """Initialize the delayed-auth decrypting stream.

        Args:
            streaming_body: The original StreamingBody containing ciphertext.
            key: The plaintext data key (bytes).
            nonce: The IV/nonce for AES-GCM decryption (bytes).
        """
        self._body = streaming_body
        self._decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
        self._tag_buffer = b""
        self._finalized = False

    def read(self, amt=None):
        """Read and decrypt data, releasing plaintext before authentication.

        The last 16 bytes of ciphertext are the GCM tag. We hold back a
        rolling buffer of 16 bytes so the tag is never passed to update().
        """
        if self._finalized:
            return b""

        raw = self._body.read(amt)
        if not raw and not self._tag_buffer:
            return b""

        data = self._tag_buffer + raw
        if len(data) <= GCM_TAG_LENGTH:
            if raw:
                self._tag_buffer = data
                return b""
            return self._finalize(tag=data)

        self._tag_buffer = data[-GCM_TAG_LENGTH:]
        ciphertext = data[:-GCM_TAG_LENGTH]
        plaintext = self._decryptor.update(ciphertext)

        # Check if underlying stream is exhausted
        peek = self._body.read(1)
        if peek:
            self._tag_buffer = self._tag_buffer + peek
            if len(self._tag_buffer) > GCM_TAG_LENGTH:
                extra_ct = self._tag_buffer[:-GCM_TAG_LENGTH]
                self._tag_buffer = self._tag_buffer[-GCM_TAG_LENGTH:]
                plaintext += self._decryptor.update(extra_ct)
        else:
            plaintext += self._finalize(tag=self._tag_buffer)

        return plaintext

    def _finalize(self, tag):
        """Verify the GCM tag and finalize decryption."""
        self._finalized = True
        self._tag_buffer = b""
        try:
            return self._decryptor.finalize_with_tag(tag)
        except Exception as e:
            raise S3EncryptionClientError(f"GCM tag verification failed: {e}") from e

    def close(self):
        """Close the underlying stream."""
        if hasattr(self._body, "close"):
            self._body.close()
