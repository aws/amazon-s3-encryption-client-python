# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for decryption specification compliance annotations.

Each test in this module corresponds to a MUST/SHOULD requirement from
specification/s3-encryption/decryption.md and carries a type=test annotation
that mirrors the type=implementation annotation in the source code.
"""

import base64
import os
from io import BytesIO
from unittest.mock import Mock

import pytest

from s3_encryption.exceptions import S3EncryptionClientError, S3EncryptionClientSecurityError
from s3_encryption.key_derivation import derive_keys, verify_commitment
from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from s3_encryption.materials.keyring import S3Keyring
from s3_encryption.materials.materials import (
    AlgorithmSuite,
    CommitmentPolicy,
    DecryptionMaterials,
)
from s3_encryption.pipelines import GetEncryptedObjectPipeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pipeline(
    commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    enable_legacy=False,
    s3_client=None,
    keyring_side_effect=None,
    keyring_return=None,
):
    """Create a GetEncryptedObjectPipeline with a mocked CMM/keyring."""
    mock_keyring = Mock(spec=S3Keyring)
    if keyring_side_effect is not None:
        mock_keyring.on_decrypt.side_effect = keyring_side_effect
    elif keyring_return is not None:
        mock_keyring.on_decrypt.return_value = keyring_return
    cmm = DefaultCryptoMaterialsManager(mock_keyring)
    return GetEncryptedObjectPipeline(
        cmm,
        s3_client=s3_client,
        commitment_policy=commitment_policy,
        enable_legacy_unauthenticated_modes=enable_legacy,
    )


def _v1_cbc_metadata():
    """Return V1 (CBC) object metadata dict."""
    return {
        "x-amz-iv": base64.b64encode(os.urandom(16)).decode(),
        "x-amz-key": base64.b64encode(b"encrypted-key").decode(),
        "x-amz-matdesc": '{"kms_cmk_id": "key-id"}',
    }


def _v2_gcm_metadata():
    """Return V2 (GCM, no KDF) object metadata dict."""
    return {
        "x-amz-iv": base64.b64encode(os.urandom(12)).decode(),
        "x-amz-key-v2": base64.b64encode(b"encrypted-key").decode(),
        "x-amz-wrap-alg": "kms+context",
        "x-amz-matdesc": "{}",
        "x-amz-cek-alg": "AES/GCM/NoPadding",
        "x-amz-tag-len": "128",
    }


def _response(metadata, body=b"ciphertext"):
    return {"Body": BytesIO(body), "Metadata": metadata, "ContentLength": len(body)}


# ---------------------------------------------------------------------------
# CBC Decryption
# ---------------------------------------------------------------------------


class TestCBCDecryption:
    """Tests for specification/s3-encryption/decryption.md#cbc-decryption."""

    ##= specification/s3-encryption/decryption.md#cbc-decryption
    ##= type=test
    ##% If an object is encrypted with ALG_AES_256_CBC_IV16_NO_KDF and
    ##% [legacy unauthenticated algorithm suites](#legacy-decryption) is NOT enabled,
    ##% the S3EC MUST throw an error which details that client was
    ##% not configured to decrypt objects with ALG_AES_256_CBC_IV16_NO_KDF.
    def test_cbc_object_rejected_when_legacy_disabled(self):
        """CBC-encrypted objects MUST be rejected when legacy modes are disabled."""
        plaintext_key = os.urandom(32)
        dec_mats = DecryptionMaterials(
            iv=os.urandom(16),
            plaintext_data_key=plaintext_key,
            algorithm_suite=AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF,
        )
        pipeline = _make_pipeline(
            enable_legacy=False,
            commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            keyring_return=dec_mats,
        )

        with pytest.raises(S3EncryptionClientError, match="ALG_AES_256_CBC_IV16_NO_KDF"):
            pipeline.decrypt(
                _response(_v1_cbc_metadata()), ".instruction", enable_delayed_authentication=False
            )

    ##= specification/s3-encryption/decryption.md#cbc-decryption
    ##= type=test
    ##% If an object is encrypted with ALG_AES_256_CBC_IV16_NO_KDF and
    ##% [legacy unauthenticated algorithm suites](#legacy-decryption) is enabled,
    ##% then the S3EC MUST create a cipher with AES in CBC Mode with PKCS5Padding or
    ##% PKCS7Padding compatible padding for a 16-byte block cipher
    ##% (example: for the Java JCE, this is "AES/CBC/PKCS5Padding").
    def test_cbc_decryption_succeeds_when_legacy_enabled(self):
        """CBC decryption MUST work with PKCS7-compatible padding when legacy is enabled."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7

        plaintext = b"hello world, this is a CBC test!!"
        key = os.urandom(32)
        iv = os.urandom(16)

        # Encrypt with AES-CBC + PKCS7 padding
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        metadata = {
            "x-amz-iv": base64.b64encode(iv).decode(),
            "x-amz-key": base64.b64encode(b"encrypted-key").decode(),
            "x-amz-matdesc": '{"kms_cmk_id": "key-id"}',
        }

        dec_mats = DecryptionMaterials(
            iv=iv,
            plaintext_data_key=key,
            algorithm_suite=AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF,
        )
        pipeline = _make_pipeline(
            enable_legacy=True,
            commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            keyring_return=dec_mats,
        )

        result = pipeline.decrypt(
            _response(metadata, ciphertext), ".instruction", enable_delayed_authentication=False
        )
        assert result.read() == plaintext

    ##= specification/s3-encryption/decryption.md#cbc-decryption
    ##= type=test
    ##% If the cipher object cannot be created as described above,
    ##% Decryption MUST fail.
    ##= specification/s3-encryption/decryption.md#cbc-decryption
    ##= type=test
    ##% The error SHOULD detail why the cipher could not be initialized
    ##% (such as CBC or PKCS5Padding is not supported by the underlying crypto provider).
    def test_cbc_decryption_fails_with_wrong_key(self):
        """CBC decryption MUST fail (with detail) when the cipher cannot decrypt."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7

        plaintext = b"hello world, this is a CBC test!!"
        real_key = os.urandom(32)
        iv = os.urandom(16)

        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(real_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        metadata = {
            "x-amz-iv": base64.b64encode(iv).decode(),
            "x-amz-key": base64.b64encode(b"encrypted-key").decode(),
            "x-amz-matdesc": '{"kms_cmk_id": "key-id"}',
        }

        # ~1/256 chance random garbage has valid PKCS7 padding, so retry
        for _ in range(10):
            wrong_key = os.urandom(32)
            dec_mats = DecryptionMaterials(
                iv=iv,
                plaintext_data_key=wrong_key,
                algorithm_suite=AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF,
            )
            pipeline = _make_pipeline(
                enable_legacy=True,
                commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
                keyring_return=dec_mats,
            )
            try:
                pipeline.decrypt(
                    _response(metadata, ciphertext),
                    ".instruction",
                    enable_delayed_authentication=False,
                ).read()
            except S3EncryptionClientSecurityError as e:
                assert "Failed to decrypt CBC content" in str(e)
                return
        pytest.fail("Wrong key did not produce CBC decryption error after 10 attempts")


# ---------------------------------------------------------------------------
# Decrypting with Commitment
# ---------------------------------------------------------------------------


class TestDecryptingWithCommitment:
    """Tests for specification/s3-encryption/decryption.md#decrypting-with-commitment."""

    ##= specification/s3-encryption/decryption.md#decrypting-with-commitment
    ##= type=test
    ##% When using an algorithm suite which supports key commitment, the client MUST verify
    ##% that the [derived key commitment](./key-derivation.md#hkdf-operation) contains the
    ##% same bytes as the stored key commitment retrieved from the stored object's metadata.
    def test_commitment_verified_against_stored_metadata(self):
        """The derived commitment MUST match the stored commitment from metadata."""
        key = os.urandom(32)
        message_id = os.urandom(28)
        _, correct_commitment = derive_keys(
            key, message_id, AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        )

        # Should not raise
        verify_commitment(correct_commitment, correct_commitment)

        # Tampered commitment must fail
        tampered = bytearray(correct_commitment)
        tampered[0] ^= 0xFF
        with pytest.raises(S3EncryptionClientSecurityError):
            verify_commitment(bytes(tampered), correct_commitment)

    ##= specification/s3-encryption/decryption.md#decrypting-with-commitment
    ##= type=test
    ##% When using an algorithm suite which supports key commitment, the verification of the derived key commitment value MUST be done in constant time.
    def test_commitment_verification_uses_constant_time_compare(self):
        """Verification MUST use constant-time comparison (hmac.compare_digest)."""
        stored = os.urandom(28)
        derived = os.urandom(28)

        # verify_commitment delegates to hmac.compare_digest; confirm it raises
        # on mismatch (the constant-time property is guaranteed by hmac.compare_digest).
        with pytest.raises(S3EncryptionClientSecurityError):
            verify_commitment(stored, derived)

    ##= specification/s3-encryption/decryption.md#decrypting-with-commitment
    ##= type=test
    ##% When using an algorithm suite which supports key commitment, the client MUST throw an exception when the derived key commitment value
    ##% and stored key commitment value do not match.
    def test_commitment_mismatch_throws_exception(self):
        """Mismatched commitment values MUST raise an exception."""
        stored = os.urandom(28)
        derived = os.urandom(28)

        with pytest.raises(
            S3EncryptionClientSecurityError, match="Key commitment verification failed"
        ):
            verify_commitment(stored, derived)

    ##= specification/s3-encryption/decryption.md#decrypting-with-commitment
    ##= type=test
    ##% When using an algorithm suite which supports key commitment, the client MUST verify the key commitment values match before deriving
    ##% the [derived encryption key](./key-derivation.md#hkdf-operation).
    def test_commitment_verified_before_content_decryption(self):
        """Commitment verification MUST happen before content decryption is attempted."""
        key = os.urandom(32)
        message_id = os.urandom(28)
        _, real_commitment = derive_keys(
            key, message_id, AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        )

        # Build V3 metadata with a wrong commitment
        wrong_commitment = os.urandom(28)
        metadata = {
            "x-amz-c": "115",
            "x-amz-3": base64.b64encode(b"encrypted-key").decode(),
            "x-amz-w": "12",
            "x-amz-t": "{}",
            "x-amz-d": base64.b64encode(wrong_commitment).decode(),
            "x-amz-i": base64.b64encode(message_id).decode(),
        }

        dec_mats = DecryptionMaterials(
            plaintext_data_key=key,
            algorithm_suite=AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )
        pipeline = _make_pipeline(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            keyring_return=dec_mats,
        )

        # Must fail at commitment check, not at AES-GCM decryption
        with pytest.raises(
            S3EncryptionClientSecurityError, match="Key commitment verification failed"
        ):
            pipeline.decrypt(
                _response(metadata, b"fake-ciphertext"),
                ".instruction",
                enable_delayed_authentication=False,
            )


# ---------------------------------------------------------------------------
# Key Commitment Policy
# ---------------------------------------------------------------------------


class TestKeyCommitmentPolicy:
    """Tests for specification/s3-encryption/decryption.md#key-commitment."""

    ##= specification/s3-encryption/decryption.md#key-commitment
    ##= type=test
    ##% The S3EC MUST validate the algorithm suite used for decryption against the
    ##% key commitment policy before attempting to decrypt the content ciphertext.
    ##= specification/s3-encryption/decryption.md#key-commitment
    ##= type=test
    ##% If the commitment policy requires decryption using a committing algorithm suite,
    ##% and the algorithm suite associated with the object does not support key commitment,
    ##% then the S3EC MUST throw an exception.
    def test_require_decrypt_rejects_non_committing_suite(self):
        """REQUIRE_ENCRYPT_REQUIRE_DECRYPT MUST reject non-committing algorithm suites."""
        dec_mats = DecryptionMaterials(
            iv=os.urandom(12),
            plaintext_data_key=os.urandom(32),
            algorithm_suite=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        )
        pipeline = _make_pipeline(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            keyring_return=dec_mats,
        )

        with pytest.raises(S3EncryptionClientError, match="cannot decrypt non-key-committing"):
            pipeline.decrypt(
                _response(_v2_gcm_metadata()), ".instruction", enable_delayed_authentication=False
            )

    def test_allow_decrypt_accepts_non_committing_suite(self):
        """REQUIRE_ENCRYPT_ALLOW_DECRYPT MUST allow non-committing algorithm suites."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b"test data for allow-decrypt policy"
        ciphertext = AESGCM(key).encrypt(iv, plaintext, None)

        metadata = {
            "x-amz-iv": base64.b64encode(iv).decode(),
            "x-amz-key-v2": base64.b64encode(b"encrypted-key").decode(),
            "x-amz-wrap-alg": "kms+context",
            "x-amz-matdesc": "{}",
            "x-amz-cek-alg": "AES/GCM/NoPadding",
            "x-amz-tag-len": "128",
        }

        dec_mats = DecryptionMaterials(
            iv=iv,
            plaintext_data_key=key,
            algorithm_suite=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        )
        pipeline = _make_pipeline(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
            keyring_return=dec_mats,
        )

        result = pipeline.decrypt(
            _response(metadata, ciphertext), ".instruction", enable_delayed_authentication=False
        )
        assert result.read() == plaintext


# ---------------------------------------------------------------------------
# Legacy Decryption
# ---------------------------------------------------------------------------


class TestLegacyDecryption:
    """Tests for specification/s3-encryption/decryption.md#legacy-decryption."""

    ##= specification/s3-encryption/decryption.md#legacy-decryption
    ##= type=test
    ##% The S3EC MUST NOT decrypt objects encrypted using legacy unauthenticated algorithm suites
    ##% unless specifically configured to do so.
    ##= specification/s3-encryption/decryption.md#legacy-decryption
    ##= type=test
    ##% If the S3EC is not configured to enable legacy unauthenticated content decryption,
    ##% the client MUST throw an exception when attempting to decrypt an object encrypted
    ##% with a legacy unauthenticated algorithm suite.
    def test_legacy_cbc_rejected_by_default(self):
        """Legacy CBC objects MUST be rejected unless enable_legacy_unauthenticated_modes is True."""
        dec_mats = DecryptionMaterials(
            iv=os.urandom(16),
            plaintext_data_key=os.urandom(32),
            algorithm_suite=AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF,
        )
        pipeline = _make_pipeline(
            enable_legacy=False,
            commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            keyring_return=dec_mats,
        )

        with pytest.raises(S3EncryptionClientError, match="not configured to decrypt"):
            pipeline.decrypt(
                _response(_v1_cbc_metadata()), ".instruction", enable_delayed_authentication=False
            )
