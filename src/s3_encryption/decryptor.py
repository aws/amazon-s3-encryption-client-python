# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Decryptor abstractions for S3 Encryption Client."""

from abc import ABC, abstractmethod

from attrs import define, field

from .exceptions import S3EncryptionClientError


class Decryptor(ABC):
    """Abstract base class for content decryption.

    Implementations own all cipher and padding state, presenting a uniform
    streaming interface to the decrypting stream classes.
    """

    @property
    @abstractmethod
    def content_length(self) -> int:
        """Total byte length of the encrypted content (ciphertext + any trailing tag)."""

    @property
    @abstractmethod
    def amount_read(self) -> int:
        """Number of ciphertext bytes consumed so far."""

    @abstractmethod
    def update(self, data: bytes) -> bytes:
        """Process a chunk of ciphertext, returning any available plaintext."""

    @abstractmethod
    def finalize(self, data: bytes) -> bytes:
        """Process the final chunk of ciphertext and finalize decryption."""


@define
class AesCbcDecryptor(Decryptor):
    """AES-CBC decryptor that owns both the cipher and PKCS7 unpadder.

    Args:
        decryptor: A cryptography CBC cipher decryptor context.
        unpadder: A cryptography PKCS7 unpadding context.
        content_length: Total byte length of the CBC ciphertext.
    """

    _decryptor: object = field()
    _unpadder: object = field()
    _content_length: int = field()
    _amount_read: int = field(init=False, default=0)

    @property
    def content_length(self) -> int:  # noqa: D102
        return self._content_length

    @property
    def amount_read(self) -> int:  # noqa: D102
        return self._amount_read

    def update(self, data: bytes) -> bytes:
        """Decrypt a chunk and unpad incrementally."""
        self._amount_read += len(data)
        plaintext = self._decryptor.update(data)
        return self._unpadder.update(plaintext)

    def finalize(self, data: bytes) -> bytes:
        """Finalize CBC decryption and flush the unpadder."""
        try:
            self._amount_read += len(data)
            plaintext = self._decryptor.update(data) if data else b""
            plaintext += self._decryptor.finalize()
            return self._unpadder.update(plaintext) + self._unpadder.finalize()
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to decrypt CBC content: {e}") from e


@define
class AesGcmDecryptor(Decryptor):
    """AES-GCM decryptor that handles trailing auth tag verification.

    Args:
        decryptor: A cryptography GCM cipher decryptor context.
        tag_length: Length of the GCM authentication tag in bytes.
        content_length: Total byte length of the encrypted content (ciphertext + tag).
    """

    _decryptor: object = field()
    _tag_length: int = field()
    _content_length: int = field()
    _amount_read: int = field(init=False, default=0)
    _tail: bytes = field(init=False, default=b"")

    @property
    def content_length(self) -> int:  # noqa: D102
        return self._content_length

    @property
    def amount_read(self) -> int:  # noqa: D102
        return self._amount_read

    @property
    def tag_length(self) -> int:
        """Length of the GCM authentication tag in bytes."""
        return self._tag_length

    def update(self, data: bytes) -> bytes:
        """Decrypt a chunk, holding back the last tag_length bytes.

        A rolling _tail buffer always retains the last tag_length bytes
        so the GCM tag is never passed to the cipher's update().
        """
        self._amount_read += len(data)
        buf = self._tail + data
        if len(buf) <= self._tag_length:
            self._tail = buf
            return b""
        self._tail = buf[-self._tag_length :]
        return self._decryptor.update(buf[: -self._tag_length])

    def finalize(self, data: bytes) -> bytes:
        """Finalize decryption using the buffered tag."""
        try:
            self._amount_read += len(data)
            buf = self._tail + data
            if len(buf) < self._tag_length:
                raise S3EncryptionClientError(
                    f"Incomplete GCM data: expected at least {self._tag_length} "
                    f"tag bytes, got {len(buf)} total remaining bytes."
                )
            tag = buf[-self._tag_length :]
            ciphertext = buf[: -self._tag_length]
            plaintext = self._decryptor.update(ciphertext) if ciphertext else b""
            return plaintext + self._decryptor.finalize_with_tag(tag)
        except S3EncryptionClientError:
            raise
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to decrypt Object: {e}") from e
