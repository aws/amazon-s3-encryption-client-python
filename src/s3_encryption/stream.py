# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Streaming decryption support for S3 Encryption Client."""

import io

from attrs import define, field
from botocore.exceptions import IncompleteReadError
from botocore.response import StreamingBody

from .decryptor import Decryptor

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


_DEFAULT_CHUNK_SIZE = 1024


##= specification/s3-encryption/client.md#enable-delayed-authentication
##= type=implementation
##% When enabled, the S3EC MAY release plaintext from a stream which has not been authenticated.
# slots=False because StreamingBody extends IOBase which already has __weakref__.
@define(slots=False)
class DecryptingStream(StreamingBody):
    """A stream that releases plaintext incrementally before full authentication.

    Extends botocore's StreamingBody so it can be used as a drop-in replacement
    for parsed["Body"]. All StreamingBody methods are explicitly overridden.
    """

    # This stream is ALMOST cipher-agnostic — the Decryptor handles ALMOST all algorithm details.
    # Ciphertext is fed through decryptor.update() incrementally, and
    # decryptor.finalize() is called with any trailing data when the body is exhausted.
    #
    # ALMOST :: The AES-GCM tag is problematic when combined with iterators that can split
    # the tag over two reads. To accommodate this, read() has a while loop with 3 return conditions.
    # See inline comments of read for more details.

    _body: object = field()
    _decryptor: Decryptor = field()
    _content_length: int = field()
    _bytes_consumed: int = field(init=False, default=0)
    _finalized: bool = field(init=False, default=False)

    def __attrs_post_init__(self):  # noqa: D105
        super().__init__(io.BytesIO(), content_length=self._content_length)

    def readable(self):  # noqa: D102
        return not self._finalized

    def read(self, amt=None):
        """Read and decrypt ciphertext, releasing plaintext incrementally.

        Args:
            amt: Number of bytes to read. If None, reads all remaining data.

        Returns:
            bytes: Decrypted plaintext bytes.
        """
        if self._finalized:
            return b""

        # Loop until the decryptor produces non-empty plaintext.
        # The GCM decryptor's tail buffer may absorb small reads entirely
        # (returning b"" from update) while it holds back the trailing auth
        # tag. Looping prevents callers from seeing spurious empty bytes
        # mid-stream, which would break `while chunk := stream.read(amt)`.
        result = b""
        while not result:
            remaining = self._content_length - self._bytes_consumed
            if remaining <= 0:
                # All content_length bytes consumed — finalize with no extra data.
                return self._finalize(b"")

            # Never read past content_length; cap at amt if provided.
            to_read = remaining if amt is None else min(amt, remaining)
            raw = self._body.read(to_read)

            if not raw:
                # Underlying stream exhausted early — finalize with what we have.
                return self._finalize(b"")

            self._bytes_consumed += len(raw)
            remaining = self._content_length - self._bytes_consumed

            if remaining <= 0:
                # This is the last chunk — pass it to finalize so the decryptor
                # can split off the GCM tag (or flush CBC padding) and verify.
                return self._finalize(raw)

            # Feed ciphertext to the decryptor. For GCM, the tail buffer holds
            # back the last tag_length bytes, so update() may return b"" if
            # the chunk was entirely absorbed into the buffer.
            result = self._decryptor.update(raw)
        return result

    def _finalize(self, trailing_data):
        """Finalize decryption with any trailing data."""
        if self._finalized:
            return b""
        self._finalized = True
        plaintext = self._decryptor.finalize(trailing_data)
        self._verify_content_length()
        return plaintext

    def readinto(self, b):
        """Read bytes into a pre-allocated, writable bytes-like object b.

        Returns the number of bytes decrypted.
        Note: CBC Padding and GCM tag will be removed, so bytes read MAYBE greater than bytes decrypted.
        """
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def readlines(self):  # noqa: D102
        return self.read().splitlines(True)

    def __iter__(self):
        """Return an iterator to yield 1k chunks from the decryption stream."""
        return self

    def __next__(self):
        """Return the next 1k chunk from the decryption stream."""
        chunk = self.read(_DEFAULT_CHUNK_SIZE)
        if chunk:
            return chunk
        raise StopIteration()

    next = __next__

    def iter_lines(self, chunk_size=_DEFAULT_CHUNK_SIZE, keepends=False):
        """Return an iterator to yield lines from the decryption stream.

        This is achieved by reading chunk of bytes (of size chunk_size) at a
        time from the chipher-text stream, decrypting them, and then yielding lines from there.
        """
        pending = b""
        for chunk in self.iter_chunks(chunk_size):
            lines = (pending + chunk).splitlines(True)
            for line in lines[:-1]:
                yield line.splitlines(keepends)[0]
            pending = lines[-1]
        if pending:
            yield pending.splitlines(keepends)[0]

    def iter_chunks(self, chunk_size=_DEFAULT_CHUNK_SIZE):
        """Return an iterator to yield chunks of chunk_size bytes from the raw stream."""
        while True:
            chunk = self.read(chunk_size)
            if chunk == b"":
                break
            yield chunk

    def _verify_content_length(self):
        """Verify that the decryptor consumed exactly content_length bytes."""
        if self._decryptor.content_length is not None and not (
            self._decryptor.amount_read == self._content_length
        ):
            raise IncompleteReadError(
                actual_bytes=self._decryptor.amount_read,
                expected_bytes=self._decryptor.content_length,
            )

    def tell(self):  # noqa: D102
        return self._bytes_consumed

    def close(self):
        """Close the underlying cipher-text stream."""
        if hasattr(self._body, "close"):
            self._body.close()

    def __enter__(self):  # noqa: D105
        return self

    def __exit__(self, *args):  # noqa: D105
        self.close()
