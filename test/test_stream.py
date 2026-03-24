# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for streaming decryption behavior."""

import os
from io import BytesIO
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials import AlgorithmSuite
from s3_encryption.stream import (
    BufferedDecryptingGCMStream,
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
        stream = BufferedDecryptingGCMStream(
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

    def test_read_after_finalized_returns_empty(self):
        plaintext = b"done"
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        stream = DelayedAuthCBCDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv),
            unpadder=unpadder,
        )
        stream.read()
        assert stream.read() == b""

    def test_readable_false_after_finalized(self):
        plaintext = b"readable"
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        stream = DelayedAuthCBCDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv),
            unpadder=unpadder,
        )
        assert stream.readable()
        stream.read()
        assert not stream.readable()

    def test_close_delegates_to_body(self):
        plaintext = b"close me"
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        body = _make_streaming_body(ciphertext)
        stream = DelayedAuthCBCDecryptingStream(
            body, _make_cbc_decryptor(key, iv), unpadder=unpadder
        )
        stream.close()
        body.close.assert_called_once()

    def test_enter_returns_self(self):
        plaintext = b"ctx"
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        stream = DelayedAuthCBCDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv),
            unpadder=unpadder,
        )
        assert stream.__enter__() is stream

    def test_wrong_key_raises_error(self):
        from cryptography.hazmat.primitives.padding import PKCS7

        plaintext = b"wrong key test!!"
        ciphertext, _key, iv, _ = _encrypt_cbc(plaintext)
        wrong_key = os.urandom(32)
        stream = DelayedAuthCBCDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(wrong_key, iv),
            unpadder=PKCS7(128).unpadder(),
        )
        with pytest.raises(S3EncryptionClientError, match="Failed to decrypt CBC content"):
            stream.read()

    def test_empty_ciphertext(self):
        from cryptography.hazmat.primitives.padding import PKCS7

        key = os.urandom(32)
        iv = os.urandom(16)
        stream = DelayedAuthCBCDecryptingStream(
            _make_streaming_body(b""),
            _make_cbc_decryptor(key, iv),
            unpadder=PKCS7(128).unpadder(),
        )
        # Empty stream finalize will fail because CBC expects at least one block
        with pytest.raises(S3EncryptionClientError, match="Failed to decrypt CBC content"):
            stream.read()


class TestBufferedDecryptingGCMStream:

    def test_full_read(self):
        plaintext = os.urandom(1024)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = BufferedDecryptingGCMStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        assert stream.read() == plaintext

    def test_partial_reads(self):
        plaintext = os.urandom(512)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = BufferedDecryptingGCMStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        result = b""
        while chunk := stream.read(100):
            result += chunk
        assert result == plaintext

    def test_read_triggers_full_decrypt(self):
        plaintext = os.urandom(256)
        ct, key, nonce = _encrypt_gcm(plaintext)
        body = _make_streaming_body(ct)
        stream = BufferedDecryptingGCMStream(body, _make_gcm_decryptor(key, nonce), tag_length=16)
        assert stream._plaintext is None
        stream.read(1)
        assert stream._plaintext is not None
        # Entire ciphertext consumed
        assert body._stream.tell() == len(ct)

    def test_tell(self):
        plaintext = os.urandom(200)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = BufferedDecryptingGCMStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        stream.read(50)
        assert stream.tell() == 50

    def test_readable(self):
        plaintext = b"readable test"
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = BufferedDecryptingGCMStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        assert stream.readable()

    def test_readinto(self):
        """Asserts that readinto is implemented by botocore's StreamingBody"""
        plaintext = os.urandom(64)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = BufferedDecryptingGCMStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        buf = bytearray(64)
        n = stream.readinto(buf)
        assert n == 64
        assert bytes(buf) == plaintext

    def test_enter_returns_raw_stream(self):
        plaintext = b"enter"
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = BufferedDecryptingGCMStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        inner = stream.__enter__()
        assert inner.read() == plaintext

    def test_close_delegates(self):
        """Asserts that close is implemented by botocore's StreamingBody"""
        plaintext = b"close"
        ct, key, nonce = _encrypt_gcm(plaintext)
        body = _make_streaming_body(ct)
        stream = BufferedDecryptingGCMStream(body, _make_gcm_decryptor(key, nonce), tag_length=16)
        stream.close()
        body.close.assert_called_once()

    def test_close_without_close_attr(self):
        """Asserts that close is implemented by botocore's StreamingBody"""
        plaintext = b"no close"
        ct, key, nonce = _encrypt_gcm(plaintext)
        body = Mock()
        del body.close
        body.read = BytesIO(ct).read
        stream = BufferedDecryptingGCMStream(body, _make_gcm_decryptor(key, nonce), tag_length=16)
        stream.close()  # should not raise

    def test_wrong_key_raises_error(self):
        plaintext = b"wrong key"
        ct, _key, nonce = _encrypt_gcm(plaintext)
        wrong_key = os.urandom(32)
        stream = BufferedDecryptingGCMStream(
            _make_streaming_body(ct), _make_gcm_decryptor(wrong_key, nonce), tag_length=16
        )
        with pytest.raises(S3EncryptionClientError, match="Failed to decrypt object"):
            stream.read()

    def test_tampered_ciphertext_raises_error(self):
        plaintext = b"tamper test"
        ct, key, nonce = _encrypt_gcm(plaintext)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        stream = BufferedDecryptingGCMStream(
            _make_streaming_body(bytes(tampered)), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        with pytest.raises(S3EncryptionClientError, match="Failed to decrypt object"):
            stream.read()

    def test_idempotent_decrypt(self):
        plaintext = os.urandom(128)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = BufferedDecryptingGCMStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        first = stream.read(63)
        second = stream.read(65)
        assert first + second == plaintext


class TestDelayedAuthGCMDecryption:

    def test_full_read(self):
        plaintext = os.urandom(1024)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DelayedAuthGCMDecryptingStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        assert stream.read() == plaintext

    def test_chunked_read(self):
        plaintext = os.urandom(512)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DelayedAuthGCMDecryptingStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        result = b""
        while chunk := stream.read(64):
            result += chunk
        assert result == plaintext

    def test_read_after_finalized_returns_empty(self):
        plaintext = os.urandom(128)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DelayedAuthGCMDecryptingStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        actual = stream.read()
        assert stream._finalized
        assert stream.read() == b""
        assert actual == plaintext

    def test_readable_false_after_finalized(self):
        plaintext = b"readable"
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DelayedAuthGCMDecryptingStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        assert stream.readable()
        stream.read()
        assert not stream.readable()

    def test_close_delegates(self):
        plaintext = b"close"
        ct, key, nonce = _encrypt_gcm(plaintext)
        body = _make_streaming_body(ct)
        stream = DelayedAuthGCMDecryptingStream(
            body, _make_gcm_decryptor(key, nonce), tag_length=16
        )
        stream.close()
        body.close.assert_called_once()

    def test_enter_returns_self(self):
        plaintext = b"ctx"
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DelayedAuthGCMDecryptingStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        assert stream.__enter__() is stream

    def test_wrong_key_raises_error(self):
        plaintext = b"wrong key"
        ct, _key, nonce = _encrypt_gcm(plaintext)
        wrong_key = os.urandom(32)
        stream = DelayedAuthGCMDecryptingStream(
            _make_streaming_body(ct), _make_gcm_decryptor(wrong_key, nonce), tag_length=16
        )
        with pytest.raises(S3EncryptionClientError, match="Failed to decrypt GCM content"):
            stream.read()

    def test_tampered_tag_raises_error(self):
        plaintext = b"tamper tag"
        ct, key, nonce = _encrypt_gcm(plaintext)
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF  # flip last byte (part of tag)
        stream = DelayedAuthGCMDecryptingStream(
            _make_streaming_body(bytes(tampered)), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        with pytest.raises(S3EncryptionClientError, match="Failed to decrypt GCM content"):
            stream.read()

    def test_small_data_less_than_tag_length(self):
        """Data exactly equal to tag length — only tag, no ciphertext."""
        plaintext = b""
        ct, key, nonce = _encrypt_gcm(plaintext)
        # For empty plaintext, ct is just the 16-byte tag
        assert len(ct) == 16
        stream = DelayedAuthGCMDecryptingStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        assert stream.read() == b""

    def test_large_data(self):
        plaintext = os.urandom(1024 * 1024)  # 1 MB
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DelayedAuthGCMDecryptingStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        result = b""
        while chunk := stream.read(65536):
            result += chunk
        assert result == plaintext


# ---------------------------------------------------------------------------
# Parameterized edge-case plaintext lengths
# ---------------------------------------------------------------------------
# Lengths chosen around AES block size (16) and two-block (32) boundaries,
# plus zero and one byte, to exercise padding, tag-splitting, and empty-data paths.
EDGE_CASE_LENGTHS = [0, 1, 8, 15, 16, 17, 31, 32, 33, 47, 48, 49]


class TestEdgeCasePlaintextLengths:

    @pytest.mark.parametrize("length", EDGE_CASE_LENGTHS)
    def test_buffered_gcm(self, length):
        plaintext = os.urandom(length)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = BufferedDecryptingGCMStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        assert stream.read() == plaintext

    @pytest.mark.parametrize("length", EDGE_CASE_LENGTHS)
    def test_delayed_auth_gcm(self, length):
        plaintext = os.urandom(length)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DelayedAuthGCMDecryptingStream(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce), tag_length=16
        )
        result = b""
        while stream.readable():
            # odd read size to stress tag-splitting
            chunk = stream.read(7)
            result += chunk
        assert result == plaintext

    @pytest.mark.parametrize("length", [l for l in EDGE_CASE_LENGTHS if l > 0])
    def test_delayed_auth_cbc(self, length):
        plaintext = os.urandom(length)
        ciphertext, key, iv, unpadder = _encrypt_cbc(plaintext)
        stream = DelayedAuthCBCDecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv),
            unpadder=unpadder,
        )
        result = b""
        while stream.readable():
            # odd read size to stress tag-splitting/padding
            result += stream.read(7)
        assert result == plaintext
