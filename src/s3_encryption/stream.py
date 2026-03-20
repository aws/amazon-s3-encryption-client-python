# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Streaming decryption support for S3 Encryption Client."""

import io

from .exceptions import S3EncryptionClientError

##= specification/s3-encryption/client.md#set-buffer-size
##= type=exception
##= reason=Optional Feature that is a two-way door to implement later
##% The S3EC SHOULD accept a configurable buffer size which refers to the maximum ciphertext length in bytes to store in memory when Delayed Authentication mode is disabled.
##= specification/s3-encryption/client.md#set-buffer-size
##= type=exception
##= reason=Optional Feature that is a two-way door to implement later
##% If Delayed Authentication mode is enabled, and the buffer size has been set to a value other than its default, the S3EC MUST throw an exception.
##= specification/s3-encryption/client.md#set-buffer-size
##= type=exception
##= reason=Optional Feature that is a two-way door to implement later
##% If Delayed Authentication mode is disabled, and no buffer size is provided, the S3EC MUST set the buffer size to a reasonable default.


def _unpad(plaintext, unpadder):
    """Apply unpadder if provided, otherwise return plaintext as-is."""
    if unpadder is None:
        return plaintext
    return unpadder.update(plaintext) + unpadder.finalize()


class BufferedDecryptingStream:
    """A stream that buffers all ciphertext, decrypts, then releases plaintext.

    Implements the same read interface as botocore's StreamingBody so it can be
    used as a drop-in replacement for parsed["Body"].
    """

    def __init__(self, streaming_body, decryptor, tag_length, unpadder=None):
        """Initialize the buffered decrypting stream.

        Args:
            streaming_body: The original StreamingBody containing ciphertext.
            decryptor: A cipher decryptor object supporting update()/finalize()
                       (or finalize_with_tag() when tag_length > 0).
            tag_length: Length of the auth tag appended to ciphertext (0 for CBC).
            unpadder: Optional PKCS7 unpadder for CBC mode.
        """
        self._body = streaming_body
        self._decryptor = decryptor
        self._tag_length = tag_length
        self._unpadder = unpadder
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
            plaintext = _unpad(plaintext, self._unpadder)
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to decrypt object: {e}") from e
        self._plaintext = io.BytesIO(plaintext)

    def read(self, amt=None):
        """Reads the entire ciphertext stream and then returns decrypted data.

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
        """Reads the entire ciphertext stream and then iterates over decrypted data in chunks.

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

    def __init__(self, streaming_body, decryptor, tag_length, unpadder=None):
        """Initialize the delayed-auth decrypting stream.

        Args:
            streaming_body: The original StreamingBody containing ciphertext.
            decryptor: A cipher decryptor object supporting update()/finalize()
                       (or finalize_with_tag() when tag_length > 0).
            tag_length: Length of the auth tag appended to ciphertext (0 for CBC).
            unpadder: Optional PKCS7 unpadder for CBC mode.
        """
        self._body = streaming_body
        self._decryptor = decryptor
        self._tag_length = tag_length
        self._unpadder = unpadder
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
            data = self._tag_buffer + raw
            self._tag_buffer = b""
            if not data:
                return self._finalize(tag=b"")
            plaintext = self._decryptor.update(data)
            if self._unpadder:
                plaintext = self._unpadder.update(plaintext)
            peek = self._body.read(1)
            if peek:
                self._tag_buffer = peek
            else:
                plaintext += self._finalize(tag=b"")
            return plaintext

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
                plaintext = self._decryptor.finalize_with_tag(tag)
            else:
                plaintext = self._decryptor.finalize()
            if self._unpadder:
                plaintext = self._unpadder.update(plaintext) + self._unpadder.finalize()
            return plaintext
        except Exception as e:
            raise S3EncryptionClientError(f"Decryption finalization failed: {e}") from e

    def close(self):
        """Close the underlying stream."""
        if hasattr(self._body, "close"):
            self._body.close()
