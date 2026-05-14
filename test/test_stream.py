# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for streaming decryption behavior."""

import os
from io import BytesIO
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

from s3_encryption.buffered_decrypt import one_shot_decrypt
from s3_encryption.decryptor import AesCbcDecryptor, AesGcmDecryptor
from s3_encryption.exceptions import S3EncryptionClientSecurityError
from s3_encryption.stream import DecryptingStream


def _encrypt_gcm(plaintext: bytes):
    """Encrypt plaintext with AES-GCM, return (ciphertext_with_tag, key, nonce)."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext_with_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return ciphertext_with_tag, key, nonce


def _make_gcm_decryptor(key, nonce, content_length):
    """Create an AesGcmDecryptor."""
    cipher_decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
    return AesGcmDecryptor(cipher_decryptor, tag_length=16, content_length=content_length)


def _encrypt_cbc(plaintext: bytes):
    """Encrypt plaintext with AES-CBC + PKCS7 padding, return (ciphertext, key, iv)."""
    key = os.urandom(32)
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext, key, iv


def _make_cbc_decryptor(key, iv, content_length):
    """Create an AesCbcDecryptor."""
    cipher_decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = PKCS7(128).unpadder()
    return AesCbcDecryptor(cipher_decryptor, unpadder, content_length=content_length)


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
        ct, key, nonce = _encrypt_gcm(plaintext)
        body = _make_streaming_body(ct)

        stream = DecryptingStream(
            body,
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
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
        assert body._stream.tell() < len(ct)

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
        ct, key, nonce = _encrypt_gcm(plaintext)
        body = _make_streaming_body(ct)

        decryptor = _make_gcm_decryptor(key, nonce, len(ct))
        original_finalize = decryptor.finalize
        finalize_called = []

        def spy_finalize(data):
            result = original_finalize(data)
            finalize_called.append(True)
            return result

        decryptor.finalize = spy_finalize

        stream = one_shot_decrypt(body, decryptor)

        # one_shot_decrypt calls finalize() eagerly — tag is verified
        # before any read() call on the returned stream.
        assert finalize_called, "finalize (tag verification) must happen before read()"
        chunk = stream.read(1)
        assert chunk == plaintext[:1]


class TestDelayedAuthCBCDecryption:
    def test_roundtrip(self):
        plaintext = b"hello world, this is a CBC test!!"
        ciphertext, key, iv = _encrypt_cbc(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv, len(ciphertext)),
            content_length=len(ciphertext),
        )
        assert stream.read() == plaintext

    def test_chunked_read(self):
        plaintext = b"A" * 256
        ciphertext, key, iv = _encrypt_cbc(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv, len(ciphertext)),
            content_length=len(ciphertext),
        )
        result = b""
        while chunk := stream.read(64):
            result += chunk
        assert result == plaintext

    def test_finalize_called(self):
        plaintext = b"finalize me"
        ciphertext, key, iv = _encrypt_cbc(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv, len(ciphertext)),
            content_length=len(ciphertext),
        )
        actual = stream.read()
        assert stream._finalized
        assert actual == plaintext

    def test_no_trailing_padding_bytes(self):
        plaintext = b"short"
        ciphertext, key, iv = _encrypt_cbc(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv, len(ciphertext)),
            content_length=len(ciphertext),
        )
        assert stream.read() == plaintext

    def test_read_after_finalized_returns_empty(self):
        plaintext = b"done"
        ciphertext, key, iv = _encrypt_cbc(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv, len(ciphertext)),
            content_length=len(ciphertext),
        )
        stream.read()
        assert stream.read() == b""

    def test_readable_false_after_finalized(self):
        plaintext = b"readable"
        ciphertext, key, iv = _encrypt_cbc(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv, len(ciphertext)),
            content_length=len(ciphertext),
        )
        assert stream.readable()
        actual = stream.read()
        assert not stream.readable()
        assert actual == plaintext

    def test_close_delegates_to_body(self):
        plaintext = b"close me"
        ciphertext, key, iv = _encrypt_cbc(plaintext)
        body = _make_streaming_body(ciphertext)
        stream = DecryptingStream(
            body,
            _make_cbc_decryptor(key, iv, len(ciphertext)),
            content_length=len(ciphertext),
        )
        stream.close()
        body.close.assert_called_once()

    def test_enter_returns_self(self):
        plaintext = b"ctx"
        ciphertext, key, iv = _encrypt_cbc(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv, len(ciphertext)),
            content_length=len(ciphertext),
        )
        assert stream.__enter__() is stream

    def test_wrong_key_raises_error(self):
        plaintext = b"wrong key test!!"
        ciphertext, _key, iv = _encrypt_cbc(plaintext)
        # ~1/256 chance random garbage has valid PKCS7 padding, so retry
        for _ in range(10):
            wrong_key = os.urandom(32)
            stream = DecryptingStream(
                _make_streaming_body(ciphertext),
                _make_cbc_decryptor(wrong_key, iv, len(ciphertext)),
                content_length=len(ciphertext),
            )
            try:
                stream.read()
            except S3EncryptionClientSecurityError:
                return  # test passes
        pytest.fail("Wrong key did not produce CBC decryption error after 10 attempts")

    def test_empty_ciphertext(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        stream = DecryptingStream(
            _make_streaming_body(b""),
            _make_cbc_decryptor(key, iv, 0),
            content_length=0,
        )
        # Empty stream finalize will fail because CBC expects at least one block
        with pytest.raises(S3EncryptionClientSecurityError, match="Failed to decrypt CBC content"):
            stream.read()


class TestBufferedDecryptingStream:
    def test_full_read(self):
        plaintext = os.urandom(1024)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = one_shot_decrypt(
            _make_streaming_body(ct), _make_gcm_decryptor(key, nonce, len(ct))
        )
        assert stream.read() == plaintext

    def test_partial_reads(self):
        plaintext = os.urandom(512)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = one_shot_decrypt(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
        )
        result = b""
        while chunk := stream.read(100):
            result += chunk
        assert result == plaintext

    def test_read_triggers_full_decrypt(self):
        plaintext = os.urandom(256)
        ct, key, nonce = _encrypt_gcm(plaintext)
        body = _make_streaming_body(ct)
        decryptor = _make_gcm_decryptor(key, nonce, len(ct))
        finalize_called = []
        original_finalize = decryptor.finalize
        decryptor.finalize = lambda data: (finalize_called.append(True), original_finalize(data))[1]

        stream = one_shot_decrypt(body, decryptor)
        # one_shot_decrypt eagerly decrypts — finalize called at construction
        assert finalize_called
        # Entire ciphertext consumed from the body
        assert body._stream.tell() == len(ct)
        assert stream.read(1) == plaintext[:1]

    def test_tell(self):
        plaintext = os.urandom(200)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = one_shot_decrypt(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
        )
        stream.read(50)
        assert stream.tell() == 50

    def test_readable(self):
        plaintext = b"readable test"
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = one_shot_decrypt(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
        )
        assert stream.readable()

    def test_readinto(self):
        """Asserts that readinto is implemented."""
        plaintext = os.urandom(64)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = one_shot_decrypt(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
        )
        buf = bytearray(64)
        n = stream.readinto(buf)
        assert n == 64
        assert bytes(buf) == plaintext

    def test_enter_returns_stream(self):
        plaintext = b"enter"
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = one_shot_decrypt(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
        )
        with stream as s:
            assert s.read() == plaintext

    def test_close(self):
        """Asserts that close does not raise."""
        plaintext = b"close"
        ct, key, nonce = _encrypt_gcm(plaintext)
        body = _make_streaming_body(ct)
        stream = one_shot_decrypt(
            body,
            _make_gcm_decryptor(key, nonce, len(ct)),
        )
        stream.close()  # should not raise

    def test_close_without_close_attr(self):
        """Asserts that close handles bodies without close."""
        plaintext = b"no close"
        ct, key, nonce = _encrypt_gcm(plaintext)
        body = Mock()
        del body.close
        body.read = BytesIO(ct).read
        stream = one_shot_decrypt(
            body,
            _make_gcm_decryptor(key, nonce, len(ct)),
        )
        stream.close()  # should not raise

    def test_wrong_key_raises_error(self):
        plaintext = b"wrong key"
        ct, _key, nonce = _encrypt_gcm(plaintext)
        wrong_key = os.urandom(32)
        with pytest.raises(S3EncryptionClientSecurityError, match="Failed to decrypt"):
            one_shot_decrypt(
                _make_streaming_body(ct),
                _make_gcm_decryptor(wrong_key, nonce, len(ct)),
            )

    def test_tampered_ciphertext_raises_error(self):
        plaintext = b"tamper test"
        ct, key, nonce = _encrypt_gcm(plaintext)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(S3EncryptionClientSecurityError, match="Failed to decrypt"):
            one_shot_decrypt(
                _make_streaming_body(bytes(tampered)),
                _make_gcm_decryptor(key, nonce, len(ct)),
            )

    def test_idempotent_decrypt(self):
        plaintext = os.urandom(128)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = one_shot_decrypt(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
        )
        first = stream.read(63)
        second = stream.read(65)
        assert first + second == plaintext


class TestDelayedAuthGCMDecryption:
    def test_full_read(self):
        plaintext = os.urandom(1024)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
        )
        assert stream.read() == plaintext

    def test_chunked_read(self):
        plaintext = os.urandom(512)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
        )
        result = b""
        while chunk := stream.read(64):
            result += chunk
        assert result == plaintext

    def test_read_after_finalized_returns_empty(self):
        plaintext = os.urandom(128)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
        )
        actual = stream.read()
        assert stream._finalized
        assert stream.read() == b""
        assert actual == plaintext

    def test_readable_false_after_finalized(self):
        plaintext = b"readable"
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
        )
        assert stream.readable()
        stream.read()
        assert not stream.readable()

    def test_close_delegates(self):
        plaintext = b"close"
        ct, key, nonce = _encrypt_gcm(plaintext)
        body = _make_streaming_body(ct)
        stream = DecryptingStream(
            body,
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
        )
        stream.close()
        body.close.assert_called_once()

    def test_enter_returns_self(self):
        plaintext = b"ctx"
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
        )
        assert stream.__enter__() is stream

    def test_wrong_key_raises_error(self):
        plaintext = b"wrong key"
        ct, _key, nonce = _encrypt_gcm(plaintext)
        wrong_key = os.urandom(32)
        stream = DecryptingStream(
            _make_streaming_body(ct),
            _make_gcm_decryptor(wrong_key, nonce, len(ct)),
            content_length=len(ct),
        )
        with pytest.raises(S3EncryptionClientSecurityError, match="Failed to decrypt"):
            stream.read()

    def test_tampered_tag_raises_error(self):
        plaintext = b"tamper tag"
        ct, key, nonce = _encrypt_gcm(plaintext)
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF  # flip last byte (part of tag)
        stream = DecryptingStream(
            _make_streaming_body(bytes(tampered)),
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
        )
        with pytest.raises(S3EncryptionClientSecurityError, match="Failed to decrypt"):
            stream.read()

    def test_small_data_less_than_tag_length(self):
        """Data exactly equal to tag length — only tag, no ciphertext."""
        plaintext = b""
        ct, key, nonce = _encrypt_gcm(plaintext)
        # For empty plaintext, ct is just the 16-byte tag
        assert len(ct) == 16
        stream = DecryptingStream(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
        )
        assert stream.read() == b""

    def test_large_data(self):
        plaintext = os.urandom(1024 * 1024)  # 1 MB
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
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
EDGE_CASE_LENGTHS = [0, 1, 8, 15, 16, 17, 31, 32, 33, 47, 48, 49, 300]


class TestEdgeCasePlaintextLengths:
    @pytest.mark.parametrize("length", EDGE_CASE_LENGTHS)
    def test_buffered_gcm(self, length):
        plaintext = os.urandom(length)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = one_shot_decrypt(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
        )
        assert stream.read() == plaintext

    @pytest.mark.parametrize("length", EDGE_CASE_LENGTHS)
    def test_delayed_auth_gcm(self, length):
        plaintext = os.urandom(length)
        ct, key, nonce = _encrypt_gcm(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
        )
        result = b""
        while chunk := stream.read(7):
            result += chunk
        assert result == plaintext

    @pytest.mark.parametrize("length", EDGE_CASE_LENGTHS)
    def test_delayed_auth_cbc(self, length):
        plaintext = os.urandom(length)
        ciphertext, key, iv = _encrypt_cbc(plaintext)
        stream = DecryptingStream(
            _make_streaming_body(ciphertext),
            _make_cbc_decryptor(key, iv, len(ciphertext)),
            content_length=len(ciphertext),
        )
        result = b""
        while chunk := stream.read(7):
            result += chunk
        assert result == plaintext


class TestDecryptingStreamIterators:
    """Tests for iter_chunks, iter_lines, __iter__, __next__, readinto, and readlines."""

    def _make_gcm_stream(self, plaintext):
        ct, key, nonce = _encrypt_gcm(plaintext)
        return DecryptingStream(
            _make_streaming_body(ct),
            _make_gcm_decryptor(key, nonce, len(ct)),
            content_length=len(ct),
        )

    @pytest.mark.parametrize("chunk_size", EDGE_CASE_LENGTHS[1:])
    def test_iter_chunks(self, chunk_size):
        plaintext = os.urandom(300)
        stream = self._make_gcm_stream(plaintext)
        result = b""
        for chunk in stream.iter_chunks(chunk_size):
            assert (
                len(chunk) <= chunk_size or not result
            )  # first chunk may vary due to GCM buffering
            result += chunk
        assert result == plaintext

    def test_iter_chunks_default_size(self):
        plaintext = os.urandom(2048)
        stream = self._make_gcm_stream(plaintext)
        result = b"".join(stream.iter_chunks())
        assert result == plaintext

    def test_iter_chunks_empty(self):
        stream = self._make_gcm_stream(b"")
        assert list(stream.iter_chunks()) == []

    def test_iter(self):
        plaintext = os.urandom(2048)
        stream = self._make_gcm_stream(plaintext)
        result = b"".join(stream)
        assert result == plaintext

    def test_next(self):
        plaintext = os.urandom(100)
        stream = self._make_gcm_stream(plaintext)
        first = next(stream)
        assert len(first) > 0
        # drain the rest
        rest = b""
        for chunk in stream:
            rest += chunk
        assert first + rest == plaintext

    def test_next_raises_stop_iteration(self):
        stream = self._make_gcm_stream(b"")
        with pytest.raises(StopIteration):
            next(stream)

    def test_iter_lines(self):
        plaintext = b"line1\nline2\nline3\n"
        stream = self._make_gcm_stream(plaintext)
        lines = list(stream.iter_lines())
        assert lines == [b"line1", b"line2", b"line3"]

    def test_iter_lines_keepends(self):
        plaintext = b"line1\nline2\nline3\n"
        stream = self._make_gcm_stream(plaintext)
        lines = list(stream.iter_lines(keepends=True))
        assert lines == [b"line1\n", b"line2\n", b"line3\n"]

    def test_iter_lines_no_trailing_newline(self):
        plaintext = b"first\nsecond"
        stream = self._make_gcm_stream(plaintext)
        lines = list(stream.iter_lines())
        assert lines == [b"first", b"second"]

    def test_iter_lines_empty(self):
        stream = self._make_gcm_stream(b"")
        assert list(stream.iter_lines()) == []

    def test_readinto(self):
        plaintext = os.urandom(64)
        stream = self._make_gcm_stream(plaintext)
        buf = bytearray(64)
        n = stream.readinto(buf)
        assert bytes(buf[:n]) == plaintext[:n]

    def test_readinto_partial(self):
        plaintext = os.urandom(200)
        stream = self._make_gcm_stream(plaintext)
        buf = bytearray(50)
        result = b""
        while n := stream.readinto(buf):
            result += bytes(buf[:n])
        assert result == plaintext

    def test_readlines(self):
        plaintext = b"aaa\nbbb\nccc\n"
        stream = self._make_gcm_stream(plaintext)
        assert stream.readlines() == [b"aaa\n", b"bbb\n", b"ccc\n"]

    def test_readlines_no_trailing_newline(self):
        plaintext = b"aaa\nbbb"
        stream = self._make_gcm_stream(plaintext)
        assert stream.readlines() == [b"aaa\n", b"bbb"]
