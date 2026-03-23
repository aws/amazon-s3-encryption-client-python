# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for streaming decryption behavior."""

import os
from io import BytesIO
from unittest.mock import Mock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from s3_encryption.materials import AlgorithmSuite
from s3_encryption.stream import (
    BufferedDecryptingStream,
    DelayedAuthCBCDecryptingStream,
    DelayedAuthGCMDecryptingStream,
)


def _encrypt_gcm(plaintext: bytes):
    """Encrypt plaintext with AES-GCM, return (ciphertext_with_tag, key, nonce)."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext_with_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return ciphertext_with_tag, key, nonce


def _make_gcm_decryptor(key, nonce):
    """Create a GCM decryptor object."""
    return Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()


def _make_streaming_body(data: bytes):
    """Create a mock StreamingBody wrapping data."""
    body = Mock()
    stream = BytesIO(data)
    body.read = stream.read
    body.close = Mock()
    body._stream = stream
    return body


class TestDelayedAuthReleasesBeforeVerification:
    """Delayed auth releases plaintext before the GCM tag is verified."""

    ##= specification/s3-encryption/client.md#enable-delayed-authentication
    ##= type=test
    ##% When enabled, the S3EC MAY release plaintext from a stream which has not been authenticated.
    def test_delayed_auth_releases_plaintext_before_tag_verification(self):
        plaintext = os.urandom(4096)
        ciphertext_with_tag, key, nonce = _encrypt_gcm(plaintext)
        body = _make_streaming_body(ciphertext_with_tag)

        decryptor = _make_gcm_decryptor(key, nonce)
        stream = DelayedAuthGCMDecryptingStream(
            body,
            decryptor,
            tag_length=AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.cipher_tag_length_bytes,
        )
        # read(256) decrypts a partial chunk via cipher.update(), releasing
        # plaintext without consuming the full ciphertext stream. The GCM tag
        # at the end of the stream has not been reached yet.
        chunk = stream.read(256)

        # Plaintext was returned before the stream was fully consumed
        assert len(chunk) > 0
        # _finalized is False: the GCM tag has NOT been verified yet
        assert not stream._finalized
        # Ciphertext remains unread in the underlying stream
        assert body._stream.tell() < len(ciphertext_with_tag)

        # Finish reading the stream and verify full plaintext matches
        remaining = stream.read()
        assert chunk + remaining == plaintext


class TestBufferedWithholdsUntilVerification:
    """Buffered mode does not release plaintext until the GCM tag is verified."""

    ##= specification/s3-encryption/client.md#enable-delayed-authentication
    ##= type=test
    ##% When disabled the S3EC MUST NOT release plaintext from a stream which has not been authenticated.
    def test_buffered_verifies_tag_before_releasing_any_plaintext(self):
        plaintext = os.urandom(4096)
        ciphertext_with_tag, key, nonce = _encrypt_gcm(plaintext)
        body = _make_streaming_body(ciphertext_with_tag)

        decryptor = _make_gcm_decryptor(key, nonce)
        stream = BufferedDecryptingStream(
            body,
            decryptor,
            tag_length=AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.cipher_tag_length_bytes,
        )
        # read(1) triggers _decrypt(), which calls self._body.read() with no amt,
        # consuming the entire ciphertext and verifying the GCM tag before
        # returning even 1 byte of plaintext.
        chunk = stream.read(1)

        assert chunk == plaintext[:1]
        # _plaintext being set confirms full decrypt+verify already happened
        assert stream._plaintext is not None


def _encrypt_cbc(plaintext: bytes):
    """Encrypt plaintext with AES-CBC + PKCS7 padding, return (ciphertext, key, iv, unpadder)."""
    from cryptography.hazmat.primitives.padding import PKCS7

    key = os.urandom(32)
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return ciphertext, key, iv, unpadder


def _make_cbc_decryptor(key, iv):
    return Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()


class TestBufferedCBCDecryption:

    def test_roundtrip(self):
        plaintext = b"hello world, this is a CBC test!!"
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        stream = BufferedDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv),
            tag_length=0,
            unpadder=unpadder,
        )
        assert stream.read() == plaintext

    def test_no_trailing_padding_bytes(self):
        plaintext = b"short"
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        stream = BufferedDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv),
            tag_length=0,
            unpadder=unpadder,
        )
        assert stream.read() == plaintext


class TestDelayedAuthCBCDecryption:

    def test_roundtrip(self):
        plaintext = b"hello world, this is a CBC test!!"
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        stream = DelayedAuthCBCDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv),
            unpadder=unpadder,
        )
        assert stream.read() == plaintext

    def test_chunked_read(self):
        plaintext = b"A" * 256
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        stream = DelayedAuthCBCDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv),
            unpadder=unpadder,
        )
        result = b""
        while chunk := stream.read(64):
            result += chunk
        assert result == plaintext

    def test_finalize_called(self):
        plaintext = b"finalize me"
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        stream = DelayedAuthCBCDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv),
            unpadder=unpadder,
        )
        stream.read()
        assert stream._finalized

    def test_no_trailing_padding_bytes(self):
        plaintext = b"short"
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        stream = DelayedAuthCBCDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv),
            unpadder=unpadder,
        )
        assert stream.read() == plaintext
