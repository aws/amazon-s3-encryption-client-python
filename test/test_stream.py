# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for streaming decryption behavior."""

import os
from io import BytesIO
from unittest.mock import Mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from s3_encryption.stream import BufferedDecryptingStream, DelayedAuthDecryptingStream


def _encrypt(plaintext: bytes):
    """Encrypt plaintext with AES-GCM, return (ciphertext_with_tag, key, nonce)."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext_with_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return ciphertext_with_tag, key, nonce


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
        ciphertext_with_tag, key, nonce = _encrypt(plaintext)
        body = _make_streaming_body(ciphertext_with_tag)

        stream = DelayedAuthDecryptingStream(body, key, nonce)
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
        ciphertext_with_tag, key, nonce = _encrypt(plaintext)
        body = _make_streaming_body(ciphertext_with_tag)

        stream = BufferedDecryptingStream(body, key, nonce)
        # read(1) triggers _decrypt(), which calls self._body.read() with no amt,
        # consuming the entire ciphertext and verifying the GCM tag before
        # returning even 1 byte of plaintext.
        chunk = stream.read(1)

        assert chunk == plaintext[:1]
        # _plaintext being set confirms full decrypt+verify already happened
        assert stream._plaintext is not None
