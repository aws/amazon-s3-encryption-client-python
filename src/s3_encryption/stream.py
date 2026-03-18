# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Streaming decryption support for S3 Encryption Client."""

import io

from .exceptions import S3EncryptionClientError

GCM_TAG_LENGTH = 16


class BufferedDecryptingStream:
    """A stream that buffers all ciphertext, decrypts, then releases plaintext.

    For authenticated ciphers (GCM), no plaintext is released until the entire
    ciphertext has been read and the auth tag verified. For unauthenticated
    ciphers (CBC), all ciphertext is still buffered before decryption.

    Implements the same read interface as botocore's StreamingBody so it can be
    used as a drop-in replacement for parsed["Body"].
    """

    def __init__(self, streaming_body, decryptor, tag_length=0):
        """Initialize the buffered decrypting stream.

        Args:
            streaming_body: The original StreamingBody containing ciphertext.
            decryptor: A cipher decryptor object supporting update()/finalize()
                       (or finalize_with_tag() when tag_length > 0).
            tag_length: Length of the auth tag appended to ciphertext (0 for CBC).
        """
        self._body = streaming_body
        self._decryptor = decryptor
        self._tag_length = tag_length
        self._plaintext = None

    def _decrypt(self):
        """Read all ciphertext, decrypt and verify, cache plaintext."""
        if self._plaintext is not None:
            return
        try:
            data = self._body.read()
            if self._tag_length > 0:
                ciphertext, tag = data[: -self._tag_length], data[-self._tag_length :]
                plaintext = self._decryptor.update(ciphertext) + self._decryptor.finalize_with_tag(
                    tag
                )
            else:
                plaintext = self._decryptor.update(data) + self._decryptor.finalize()
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to decrypt object: {e}") from e
        self._plaintext = io.BytesIO(plaintext)

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
    """A stream that releases plaintext before full verification.

    Plaintext is released incrementally via cipher.update(). For authenticated
    ciphers (GCM), the auth tag is only verified when the stream is fully
    consumed. For unauthenticated ciphers (CBC), this behaves identically
    to streaming decryption with no tag holdback.
    """

    def __init__(self, streaming_body, decryptor, tag_length=0):
        """Initialize the delayed-auth decrypting stream.

        Args:
            streaming_body: The original StreamingBody containing ciphertext.
            decryptor: A cipher decryptor object supporting update()/finalize()
                       (or finalize_with_tag() when tag_length > 0).
            tag_length: Length of the auth tag appended to ciphertext (0 for CBC).
        """
        self._body = streaming_body
        self._decryptor = decryptor
        self._tag_length = tag_length
        self._tag_buffer = b""
        self._finalized = False

    def read(self, amt=None):
        """Read and decrypt data, releasing plaintext before authentication.

        When tag_length > 0, the last tag_length bytes of ciphertext are the
        auth tag. We hold back a rolling buffer so the tag is never passed
        to update().
        """
        if self._finalized:
            return b""

        raw = self._body.read(amt)
        if not raw and not self._tag_buffer:
            return b""

        if self._tag_length == 0:
            # No tag to hold back (e.g. CBC)
            if not raw:
                return self._finalize(tag=b"")
            return self._decryptor.update(raw)

        data = self._tag_buffer + raw
        if len(data) <= self._tag_length:
            if raw:
                self._tag_buffer = data
                return b""
            return self._finalize(tag=data)

        self._tag_buffer = data[-self._tag_length :]
        ciphertext = data[: -self._tag_length]
        plaintext = self._decryptor.update(ciphertext)

        # Check if underlying stream is exhausted
        peek = self._body.read(1)
        if peek:
            self._tag_buffer = self._tag_buffer + peek
            if len(self._tag_buffer) > self._tag_length:
                extra_ct = self._tag_buffer[: -self._tag_length]
                self._tag_buffer = self._tag_buffer[-self._tag_length :]
                plaintext += self._decryptor.update(extra_ct)
        else:
            plaintext += self._finalize(tag=self._tag_buffer)

        return plaintext

    def _finalize(self, tag):
        """Finalize decryption, verifying the auth tag if present."""
        self._finalized = True
        self._tag_buffer = b""
        try:
            if tag:
                return self._decryptor.finalize_with_tag(tag)
            return self._decryptor.finalize()
        except Exception as e:
            raise S3EncryptionClientError(f"Decryption finalization failed: {e}") from e

    def close(self):
        """Close the underlying stream."""
        if hasattr(self._body, "close"):
            self._body.close()
