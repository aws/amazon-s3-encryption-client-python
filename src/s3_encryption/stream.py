# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Streaming decryption support for S3 Encryption Client."""

import io

from attrs import define, field
from botocore.response import StreamingBody

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


# slots=False because StreamingBody extends IOBase which already has __weakref__.
@define(slots=False)
class BufferedDecryptingGCMStream(StreamingBody):
    """A stream that buffers all ciphertext, decrypts, then releases plaintext.

    Extends botocore's StreamingBody so it can be used as a drop-in replacement
    for parsed["Body"], inheriting iter_chunks, iter_lines, __iter__, etc.
    """

    _body: object = field()
    _decryptor: object = field()
    _tag_length: int = field()
    _plaintext: object = field(init=False, default=None)

    def __attrs_post_init__(self):  # noqa: D105
        # Initialize StreamingBody with a placeholder; _raw_stream is replaced
        # on first read after decryption.
        super().__init__(io.BytesIO(), content_length=None)

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
        self._raw_stream = self._plaintext

    # Inherited iter_chunks, iter_lines, __iter__, and __next__ all delegate
    # to self.read(), which calls _decrypt(). No override needed.

    def readable(self):  # noqa: D102
        self._decrypt()
        return self._raw_stream.readable()

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

    def readinto(self, b):  # noqa: D102
        self._decrypt()
        return self._raw_stream.readinto(b)

    def tell(self):  # noqa: D102
        self._decrypt()
        return self._raw_stream.tell()

    def __enter__(self):  # noqa: D105
        self._decrypt()
        return self._raw_stream

    def close(self):
        """Close the underlying stream."""
        if hasattr(self._body, "close"):
            self._body.close()


##= specification/s3-encryption/client.md#enable-delayed-authentication
##= type=implementation
##% When enabled, the S3EC MAY release plaintext from a stream which has not been authenticated.
# slots=False because StreamingBody extends IOBase which already has __weakref__.
@define(slots=False)
class DelayedAuthCBCDecryptingStream(StreamingBody):
    """A delayed-auth stream for AES-CBC decryption.

    Extends botocore's StreamingBody so it can be used as a drop-in replacement
    for parsed["Body"], inheriting iter_chunks, iter_lines, __iter__, etc.

    CBC has no auth tag, so plaintext is released incrementally via
    cipher.update(). A 1-byte peek-ahead detects stream exhaustion so the
    PKCS7 unpadder can be finalized.
    """

    _body: object = field()
    _decryptor: object = field()
    _unpadder: object = field()
    _peek_buffer: bytes = field(init=False, default=b"")
    _finalized: bool = field(init=False, default=False)

    def __attrs_post_init__(self):  # noqa: D105
        # Initialize StreamingBody; _raw_stream is unused since plaintext is
        # produced incrementally via read().
        super().__init__(io.BytesIO(), content_length=None)

    # Inherited iter_chunks, iter_lines, __iter__, and __next__ all delegate
    # to self.read(). No override needed.

    def readable(self):  # noqa: D102
        return not self._finalized

    def read(self, amt=None):
        """Read and decrypt CBC ciphertext, releasing plaintext incrementally."""
        # Stream already fully consumed and finalized; nothing left to return.
        if self._finalized:
            return b""

        # Read the next chunk of raw ciphertext from the underlying stream.
        raw = self._body.read(amt)

        # Prepend any previously held-back peek byte to the new data.
        data = self._peek_buffer + raw
        self._peek_buffer = b""

        # No data at all; the stream is empty.
        if not data:
            return self._finalize()

        # Decrypt incrementally; plaintext is released immediately.
        plaintext = self._decryptor.update(data)
        plaintext = self._unpadder.update(plaintext)

        # Peek 1 byte ahead to detect stream exhaustion. If the stream
        # is exhausted we must finalize now to flush the unpadder.
        peek = self._body.read(1)
        if peek:
            # Stream continues; stash the peeked byte for the next read.
            self._peek_buffer = peek
        else:
            # Stream exhausted; finalize to flush any remaining padding.
            plaintext += self._finalize()

        return plaintext

    def _finalize(self):
        """Finalize CBC decryption and flush the unpadder."""
        self._finalized = True
        try:
            plaintext = self._decryptor.finalize()
            return self._unpadder.update(plaintext) + self._unpadder.finalize()
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to decrypt CBC content: {e}") from e

    def __enter__(self):  # noqa: D105
        return self

    def close(self):
        """Close the underlying stream."""
        if hasattr(self._body, "close"):
            self._body.close()


##= specification/s3-encryption/client.md#enable-delayed-authentication
##= type=implementation
##% When enabled, the S3EC MAY release plaintext from a stream which has not been authenticated.
# slots=False because StreamingBody extends IOBase which already has __weakref__.
@define(slots=False)
class DelayedAuthGCMDecryptingStream(StreamingBody):
    """A delayed-auth stream for AES-GCM decryption.

    Extends botocore's StreamingBody so it can be used as a drop-in replacement
    for parsed["Body"], inheriting iter_chunks, iter_lines, __iter__, etc.

    Plaintext is released incrementally via cipher.update(). The last
    tag_length bytes of ciphertext are the GCM auth tag, held back in a
    rolling buffer. The tag is only verified via finalize_with_tag() when
    the stream is fully consumed.
    """

    _body: object = field()
    _decryptor: object = field()
    _tag_length: int = field()
    _tag_buffer: bytes = field(init=False, default=b"")
    _finalized: bool = field(init=False, default=False)

    def __attrs_post_init__(self):  # noqa: D105
        # Initialize StreamingBody; _raw_stream is unused since plaintext is
        # produced incrementally via read().
        super().__init__(io.BytesIO(), content_length=None)

    # Inherited iter_chunks, iter_lines, __iter__, and __next__ all delegate
    # to self.read(). No override needed.

    def readable(self):  # noqa: D102
        return not self._finalized

    def read(self, amt=None):
        """Read and decrypt GCM ciphertext, holding back the trailing auth tag."""
        if amt is not None and 0 < amt < self._tag_length + 1:
            raise S3EncryptionClientError(
                f"read size {amt} is too small; must be at least {self._tag_length + 1} "
                f"to distinguish ciphertext from the GCM auth tag"
            )

        # Stream already fully consumed and finalized; nothing left to return.
        if self._finalized:
            return b""

        # Read the next chunk of raw ciphertext from the underlying stream.
        raw = self._body.read(amt)

        # No new data and no held-back bytes; the stream is empty.
        if not raw and not self._tag_buffer:
            return b""

        # Combine any previously held-back bytes with the new data.
        data = self._tag_buffer + raw

        # Not enough data to separate ciphertext from tag yet.
        if len(data) <= self._tag_length:
            if raw:
                # More data may arrive; buffer everything and wait.
                self._tag_buffer = data
                return b""
            # No more data coming; everything buffered is the tag.
            return self._finalize(tag=data)

        # Split: the last tag_length bytes are the candidate tag;
        # everything before is ciphertext safe to decrypt now.
        self._tag_buffer = data[-self._tag_length :]
        ciphertext = data[: -self._tag_length]
        plaintext = self._decryptor.update(ciphertext)

        # Peek 1 byte ahead to detect whether the underlying stream is
        # exhausted. This determines if the current tag_buffer is truly
        # the final GCM tag or just more ciphertext.
        peek = self._body.read(1)
        if peek:
            # Stream continues; the peeked byte may shift what we thought
            # was the tag back into ciphertext territory.
            self._tag_buffer = self._tag_buffer + peek
            if len(self._tag_buffer) > self._tag_length:
                # Extra bytes beyond tag_length are ciphertext; decrypt them.
                extra_ct = self._tag_buffer[: -self._tag_length]
                self._tag_buffer = self._tag_buffer[-self._tag_length :]
                plaintext += self._decryptor.update(extra_ct)
        else:
            # Stream exhausted; tag_buffer holds the final GCM auth tag.
            plaintext += self._finalize(tag=self._tag_buffer)

        return plaintext

    def _finalize(self, tag):
        """Finalize GCM decryption, verifying the auth tag."""
        self._finalized = True
        self._tag_buffer = b""
        try:
            return self._decryptor.finalize_with_tag(tag)
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to decrypt GCM content: {e}") from e

    def __enter__(self):  # noqa: D105
        return self

    def close(self):
        """Close the underlying stream."""
        if hasattr(self._body, "close"):
            self._body.close()
