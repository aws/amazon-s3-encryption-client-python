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
class GCMBufferedDecryptingStream(StreamingBody):
    """A stream that buffers all ciphertext, decrypts, then releases plaintext.

    Extends botocore's StreamingBody so it can be used as a drop-in replacement
    for parsed["Body"], inheriting iter_chunks, iter_lines, __iter__, etc.
    """

    _body: object = field()
    _decryptor: object = field()
    _tag_length: int = field()
    # _content_length intentionally collides with super's _content_length
    _content_length: int = field()
    _plaintext: object = field(init=False, default=None)

    def __attrs_post_init__(self):  # noqa: D105
        # By passing in content_length, and updating _amount_read in read(),
        # we support the super's normal progression.
        # However, we do not support the super's _verify_content_length.
        super().__init__(io.BytesIO(), content_length=self._content_length)

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
        chunk = self._plaintext.read() if amt is None else self._plaintext.read(amt)
        # super._amount_read can be used for progress tracking
        # noinspection PyUnresolvedReferences
        self._amount_read += len(chunk)
        return chunk

    def readinto(self, b):  # noqa: D102
        self._decrypt()
        return self._raw_stream.readinto(b)

    def tell(self):  # noqa: D102
        self._decrypt()
        return self._raw_stream.tell()

    def __enter__(self):  # noqa: D105
        self._decrypt()
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
class CBCDecryptingStream(StreamingBody):
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
    # _content_length intentionally collides with super's _content_length
    _content_length: int = field()
    _peek_buffer: bytes = field(init=False, default=b"")
    _finalized: bool = field(init=False, default=False)

    def __attrs_post_init__(self):  # noqa: D105
        # By passing in content_length, and updating _amount_read in read(),
        # we support the super's normal progression.
        # However, we do not support the super's _verify_content_length.
        super().__init__(io.BytesIO(), content_length=self._content_length)

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

        # super._amount_read can be used for progress tracking
        # noinspection PyUnresolvedReferences
        self._amount_read += len(plaintext)
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
class GCMDelayedAuthDecryptingStream(StreamingBody):
    """A delayed-auth stream for AES-GCM decryption.

    Extends botocore's StreamingBody so it can be used as a drop-in replacement
    for parsed["Body"], inheriting iter_chunks, iter_lines, __iter__, etc.

    Plaintext is released incrementally via cipher.update(). The content_length
    from the S3 GetObject response tells us exactly how many bytes are ciphertext
    vs. the trailing GCM auth tag. The tag is only verified via finalize_with_tag() when the ciphertext is
    fully consumed.
    """

    _body: object = field()
    _decryptor: object = field()
    _tag_length: int = field()
    # _content_length intentionally collides with super's _content_length
    _content_length: int = field()
    _ciphertext_remaining: int = field(init=False)
    _finalized: bool = field(init=False, default=False)

    def __attrs_post_init__(self):  # noqa: D105
        # By passing in content_length, and updating _amount_read in read(),
        # we support the super's normal progression.
        # However, we do not support the super's _verify_content_length.
        super().__init__(io.BytesIO(), content_length=self._content_length)
        self._ciphertext_remaining = self._content_length - self._tag_length
        if self._ciphertext_remaining < 0:
            raise S3EncryptionClientError(
                f"Malformed Input: Content Length ({self._content_length}) is less than GCM tag length ({self._tag_length})"
            )

    # Inherited iter_chunks, iter_lines, __iter__, and __next__ all delegate
    # to self.read(). No override needed.

    def readable(self):  # noqa: D102
        return not self._finalized

    def read(self, amt=None):
        """Read and decrypt GCM ciphertext, holding back the trailing auth tag."""
        # Stream already fully consumed and finalized; nothing left to return.
        if self._finalized:
            return b""

        # No ciphertext left — read the tag and finalize.
        if self._ciphertext_remaining <= 0:
            return self._finalize()

        # Read at most ciphertext_remaining bytes (never into the tag).
        to_read = (
            self._ciphertext_remaining if amt is None else min(amt, self._ciphertext_remaining)
        )
        raw = self._body.read(to_read)

        if not raw:
            return self._finalize()

        self._ciphertext_remaining -= len(raw)
        plaintext = self._decryptor.update(raw)

        # If we've consumed all ciphertext, finalize now.
        if self._ciphertext_remaining <= 0:
            plaintext += self._finalize()

        # super._amount_read can be used for progress tracking
        # noinspection PyUnresolvedReferences
        self._amount_read += len(plaintext)
        return plaintext

    def _finalize(self):
        """Read the GCM tag from the stream and verify it."""
        if self._finalized:
            return b""
        self._finalized = True
        try:
            tag = self._body.read(self._tag_length)
            return self._decryptor.finalize_with_tag(tag)
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to decrypt GCM content: {e}") from e

    def __enter__(self):  # noqa: D105
        return self

    def close(self):
        """Close the underlying stream."""
        if hasattr(self._body, "close"):
            self._body.close()
