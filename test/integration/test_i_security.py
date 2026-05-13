# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security integration tests for S3 Encryption Client.

These tests verify that the client correctly handles metadata tampering
scenarios, particularly wrapping algorithm downgrade attempts that modify
metadata to bypass encryption context validation.
"""

import base64
import json
import os
from datetime import datetime
from unittest.mock import MagicMock

import boto3
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.decryptor import AesCbcDecryptor
from s3_encryption.exceptions import S3EncryptionClientError, S3EncryptionClientSecurityError
from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from s3_encryption.materials.kms_keyring import KmsKeyring
from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy
from s3_encryption.pipelines import GetEncryptedObjectPipeline

bucket = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
region = os.environ.get("CI_AWS_REGION", "us-west-2")
kms_key_id = os.environ.get(
    "CI_KMS_KEY_ALIAS", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"
)


def _unique_key(prefix):
    return prefix + datetime.now().strftime("%Y-%m-%d-%H:%M:%S-%f")


def _make_client(algorithm_suite, commitment_policy, enable_legacy_wrapping=False):
    """Create an S3EncryptionClient with the given config."""
    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(
        kms_client, kms_key_id, enable_legacy_wrapping_algorithms=enable_legacy_wrapping
    )
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        encryption_algorithm=algorithm_suite,
        commitment_policy=commitment_policy,
    )
    return S3EncryptionClient(wrapped_client, config)


class TestWrappingAlgorithmDowngradeAttack:
    """Tests for wrapping algorithm downgrade scenarios.

    These tests verify behavior when the wrapping algorithm metadata is
    modified from kms+context to kms. In V3 format, "kms" is not a valid
    compressed wrapping algorithm code, so the client MUST reject it.
    """

    def test_v3_downgrade_wrap_alg_to_kms_rejected_without_legacy(self):
        """Tampering x-amz-w from '12' to 'kms' MUST fail when legacy wrapping is disabled.

        The default KmsKeyring does not enable legacy wrapping algorithms,
        so the 'kms' wrapping algorithm value should be rejected outright.
        """
        key = _unique_key("sec-downgrade-no-legacy-")
        data = b"sensitive data with context"
        encryption_context = {"project": "alpha"}

        # 1. Encrypt normally with kms+context (V3 format)
        s3ec = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

        # 2. Attacker tampers x-amz-w from '12' to 'kms' via S3 copy
        plain_s3 = boto3.client("s3")
        head = plain_s3.head_object(Bucket=bucket, Key=key)
        original_metadata = head["Metadata"]
        assert original_metadata.get("x-amz-w") == "12", (
            f"Expected x-amz-w='12', got {original_metadata.get('x-amz-w')}"
        )

        tampered_metadata = original_metadata.copy()
        tampered_metadata["x-amz-w"] = "kms"

        plain_s3.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            Metadata=tampered_metadata,
            MetadataDirective="REPLACE",
        )

        # 3. Decryption with mismatched context MUST fail
        with pytest.raises((S3EncryptionClientError, Exception)):
            s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext={"project": "beta"})

    def test_v3_downgrade_wrap_alg_to_kms_rejected_with_correct_context(self):
        """Tampering x-amz-w from '12' to 'kms' MUST fail even with the original context.

        The V3 wrapping algorithm validation rejects "kms" as an invalid
        compressed code regardless of what encryption context the caller
        provides. The rejection happens before any context comparison.
        """
        key = _unique_key("sec-downgrade-no-legacy-correct-ctx-")
        data = b"sensitive data with context"
        encryption_context = {"project": "alpha"}

        # 1. Encrypt normally with kms+context (V3 format)
        s3ec = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

        # 2. Tamper x-amz-w from '12' to 'kms'
        plain_s3 = boto3.client("s3")
        head = plain_s3.head_object(Bucket=bucket, Key=key)
        tampered_metadata = head["Metadata"].copy()
        tampered_metadata["x-amz-w"] = "kms"

        plain_s3.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            Metadata=tampered_metadata,
            MetadataDirective="REPLACE",
        )

        # 3. Decryption with the ORIGINAL (correct) context MUST still fail
        with pytest.raises((S3EncryptionClientError, Exception)):
            s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext=encryption_context)

    def test_v3_downgrade_wrap_alg_to_kms_rejected_with_legacy(self):
        """Tampering x-amz-w from '12' to 'kms' MUST still fail even with legacy enabled.

        Even when enable_legacy_wrapping_algorithms=True, the KmsV1 path
        passes the *stored* encryption context to KMS Decrypt. Since the
        data key was originally encrypted with the 'alpha' context, KMS
        itself will reject the Decrypt call (the ciphertext is bound to
        the original context). The mismatched 'beta' context should never
        produce a successful decryption.
        """
        key = _unique_key("sec-downgrade-legacy-")
        data = b"sensitive data with context"
        encryption_context = {"project": "alpha"}

        # 1. Encrypt with kms+context (V3)
        s3ec_encrypt = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        s3ec_encrypt.put_object(
            Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context
        )

        # 2. Attacker tampers x-amz-w from '12' to 'kms'
        plain_s3 = boto3.client("s3")
        head = plain_s3.head_object(Bucket=bucket, Key=key)
        tampered_metadata = head["Metadata"].copy()
        tampered_metadata["x-amz-w"] = "kms"

        plain_s3.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            Metadata=tampered_metadata,
            MetadataDirective="REPLACE",
        )

        # 3. Decrypt with legacy enabled but mismatched context MUST fail
        s3ec_legacy = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            enable_legacy_wrapping=True,
        )
        with pytest.raises((S3EncryptionClientError, Exception)):
            s3ec_legacy.get_object(Bucket=bucket, Key=key, EncryptionContext={"project": "beta"})

    def test_v3_downgrade_wrap_alg_correct_context_still_fails(self):
        """Tampering x-amz-w from '12' to 'kms' MUST fail even with the correct context.

        The KmsV1 path uses the *stored* encryption context (from x-amz-t)
        for the KMS Decrypt call. But the stored context for kms+context
        includes the reserved key 'aws:x-amz-cek-alg'. When the wrapping
        algorithm is changed to 'kms', the keyring may not reconstruct the
        correct KMS encryption context, causing KMS to reject the call.
        This verifies the attack fails regardless of what context the
        caller provides.
        """
        key = _unique_key("sec-downgrade-correct-ctx-")
        data = b"sensitive data with context"
        encryption_context = {"project": "alpha"}

        # 1. Encrypt with kms+context (V3)
        s3ec = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

        # 2. Attacker tampers x-amz-w
        plain_s3 = boto3.client("s3")
        head = plain_s3.head_object(Bucket=bucket, Key=key)
        tampered_metadata = head["Metadata"].copy()
        tampered_metadata["x-amz-w"] = "kms"

        plain_s3.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            Metadata=tampered_metadata,
            MetadataDirective="REPLACE",
        )

        # 3. Even with the CORRECT original context, decryption should fail
        #    because the wrapping algorithm mismatch corrupts the KMS call
        s3ec_legacy = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            enable_legacy_wrapping=True,
        )
        with pytest.raises((S3EncryptionClientError, Exception)):
            s3ec_legacy.get_object(Bucket=bucket, Key=key, EncryptionContext=encryption_context)

    def test_v3_downgrade_with_matdesc_injection(self):
        """Tampering x-amz-w to 'kms' AND copying x-amz-t into x-amz-m MUST be rejected.

        "kms" is not a valid V3 compressed wrapping algorithm code, so the
        client rejects it before the matdesc injection has any effect.
        """
        key = _unique_key("sec-v3-downgrade-matdesc-")
        data = b"sensitive data with context"
        encryption_context = {"project": "alpha"}

        # 1. Encrypt with kms+context (V3)
        s3ec = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

        # 2. Attacker tampers x-amz-w AND copies x-amz-t into x-amz-m
        plain_s3 = boto3.client("s3")
        head = plain_s3.head_object(Bucket=bucket, Key=key)
        tampered_metadata = head["Metadata"].copy()

        # Downgrade wrapping algorithm
        tampered_metadata["x-amz-w"] = "kms"
        # Copy the original bound context from x-amz-t into x-amz-m
        # so the KmsV1 path reads it as mat_desc and passes it to KMS Decrypt
        tampered_metadata["x-amz-m"] = tampered_metadata["x-amz-t"]

        plain_s3.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            Metadata=tampered_metadata,
            MetadataDirective="REPLACE",
        )

        # 3. Decrypt with legacy enabled + mismatched context MUST fail
        s3ec_legacy = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            enable_legacy_wrapping=True,
        )
        with pytest.raises((S3EncryptionClientError, Exception)):
            s3ec_legacy.get_object(Bucket=bucket, Key=key, EncryptionContext={"project": "beta"})


class TestV2WrappingAlgorithmDowngradeAttack:
    """V2 wrapping algorithm downgrade tests.

    V2 stores the wrapping algorithm in x-amz-wrap-alg. The KmsV1 ("kms")
    wrapping algorithm does not support caller-provided encryption context.
    When a caller provides encryption context on decrypt and the wrapping
    algorithm is "kms", the client MUST reject the request. This is the
    canonical behavior established by the Java AmazonS3EncryptionClientV2.
    """

    def test_v2_downgrade_wrap_alg_to_kms_correct_context(self):
        """Tampering x-amz-wrap-alg to 'kms' MUST fail even with the original correct context.

        The KmsV1 wrapping algorithm does not support encryption context.
        The client MUST reject when a caller provides any encryption context
        and the wrapping algorithm is 'kms', regardless of whether the
        context matches the stored matdesc.
        """
        key = _unique_key("sec-v2-downgrade-correct-ctx-")
        data = b"sensitive v2 data"
        encryption_context = {"project": "alpha"}

        # 1. Encrypt with V2 format (AES_GCM, kms+context wrapping)
        s3ec = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        )
        s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

        # 2. Tamper x-amz-wrap-alg from 'kms+context' to 'kms'
        plain_s3 = boto3.client("s3")
        head = plain_s3.head_object(Bucket=bucket, Key=key)
        tampered_metadata = head["Metadata"].copy()
        tampered_metadata["x-amz-wrap-alg"] = "kms"

        plain_s3.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            Metadata=tampered_metadata,
            MetadataDirective="REPLACE",
        )

        # 3. Decrypt with legacy enabled + CORRECT original context MUST still fail
        s3ec_legacy = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            enable_legacy_wrapping=True,
        )
        with pytest.raises((S3EncryptionClientError, Exception)):
            s3ec_legacy.get_object(Bucket=bucket, Key=key, EncryptionContext=encryption_context)

    def test_v2_downgrade_wrap_alg_to_kms_mismatched_context(self):
        """Tampering x-amz-wrap-alg from 'kms+context' to 'kms' with wrong context.

        The KmsV1 wrapping algorithm does not support encryption context.
        The client MUST reject when a caller provides mismatched encryption
        context and the wrapping algorithm is 'kms'.
        """
        key = _unique_key("sec-v2-downgrade-")
        data = b"sensitive v2 data"
        encryption_context = {"project": "alpha"}

        # 1. Encrypt with V2 format (AES_GCM, kms+context wrapping)
        s3ec = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        )
        s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

        # 2. Attacker tampers x-amz-wrap-alg from 'kms+context' to 'kms'
        plain_s3 = boto3.client("s3")
        head = plain_s3.head_object(Bucket=bucket, Key=key)
        original_metadata = head["Metadata"]
        assert original_metadata.get("x-amz-wrap-alg") == "kms+context", (
            f"Expected x-amz-wrap-alg='kms+context', got {original_metadata.get('x-amz-wrap-alg')}"
        )

        tampered_metadata = original_metadata.copy()
        tampered_metadata["x-amz-wrap-alg"] = "kms"

        plain_s3.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            Metadata=tampered_metadata,
            MetadataDirective="REPLACE",
        )

        # 3. Decrypt with legacy enabled + mismatched context
        s3ec_legacy = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            enable_legacy_wrapping=True,
        )
        with pytest.raises((S3EncryptionClientError, Exception)):
            s3ec_legacy.get_object(Bucket=bucket, Key=key, EncryptionContext={"project": "beta"})


class TestEncryptionContextBypassAttempts:
    """Tests verifying encryption context cannot be bypassed through other vectors."""

    def test_v3_no_context_on_decrypt_after_context_on_encrypt(self):
        """Omitting EncryptionContext on get_object MUST fail if object was encrypted with one."""
        key = _unique_key("sec-no-ctx-decrypt-")
        data = b"data requiring context"
        encryption_context = {"project": "alpha"}

        s3ec = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

        with pytest.raises(S3EncryptionClientError):
            s3ec.get_object(Bucket=bucket, Key=key)

    def test_v3_tamper_stored_context_metadata(self):
        """Tampering x-amz-t (stored encryption context) MUST cause KMS Decrypt to fail.

        The KMS ciphertext is bound to the original encryption context.
        Modifying x-amz-t changes what the client sends to KMS Decrypt,
        causing a mismatch with the ciphertext's bound context.
        """
        key = _unique_key("sec-tamper-ctx-")
        data = b"data with bound context"
        encryption_context = {"project": "alpha"}

        s3ec = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

        # Tamper the stored encryption context in x-amz-t
        plain_s3 = boto3.client("s3")
        head = plain_s3.head_object(Bucket=bucket, Key=key)
        tampered_metadata = head["Metadata"].copy()

        # Replace the stored context with attacker-controlled values
        tampered_metadata["x-amz-t"] = json.dumps({"project": "beta", "aws:x-amz-cek-alg": "115"})

        plain_s3.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            Metadata=tampered_metadata,
            MetadataDirective="REPLACE",
        )

        # Decryption with the tampered context should fail at KMS
        with pytest.raises((S3EncryptionClientError, Exception)):
            s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext={"project": "beta"})


class TestCBCErrorIndistinguishability:
    """Tests verifying that CBC decryption errors are indistinguishable.

    A padding oracle requires the caller to distinguish between padding
    errors and other decryption failures. These tests verify that all CBC
    failure modes produce the same error type and message, preventing
    an attacker from using error responses to deduce padding validity.
    """

    def _encrypt_cbc(self, key, iv, plaintext):
        """Helper to encrypt with AES-CBC + PKCS7 padding."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        return encryptor.update(padded) + encryptor.finalize()

    def _make_cbc_decryptor(self, key, iv, content_length):
        """Helper to create an AesCbcDecryptor."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        unpadder = PKCS7(128).unpadder()
        return AesCbcDecryptor(cipher.decryptor(), unpadder, content_length)

    def test_wrong_key_and_tampered_ciphertext_produce_same_error(self):
        """Wrong key and tampered ciphertext MUST produce identical error messages.

        Both cause PKCS7 unpadding to fail, but the error message and type
        MUST be the same so an attacker cannot distinguish between them.
        """
        key = os.urandom(32)
        iv = os.urandom(16)
        ciphertext = self._encrypt_cbc(key, iv, b"test data for padding oracle check")

        # Wrong key: decryption produces garbage, unpadding fails.
        # ~1/256 chance random garbage has valid PKCS7 padding, so retry.
        exc1 = None
        for _ in range(10):
            wrong_key = os.urandom(32)
            decryptor1 = self._make_cbc_decryptor(wrong_key, iv, len(ciphertext))
            try:
                decryptor1.finalize(ciphertext)
            except S3EncryptionClientSecurityError as e:
                exc1 = e
                break
        assert exc1 is not None, "Wrong key did not produce padding error after 10 attempts"

        # Tampered ciphertext: last byte flipped, unpadding fails
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])
        decryptor2 = self._make_cbc_decryptor(key, iv, len(tampered))
        with pytest.raises(S3EncryptionClientSecurityError) as exc2:
            decryptor2.finalize(tampered)

        # Both MUST produce the same error message
        assert str(exc1.value) == str(exc2.value), (
            f"Error messages differ: wrong_key={str(exc1.value)!r}, tampered={str(exc2.value)!r}"
        )

        # Neither message should contain details about the underlying failure
        assert "padding" not in str(exc1.value).lower(), (
            f"Error message leaks padding information: {str(exc1.value)!r}"
        )

    def test_truncated_ciphertext_produces_same_error(self):
        """Truncated ciphertext MUST produce the same error as padding failure.

        A non-block-aligned ciphertext causes a different exception in the
        cryptography library. The error message MUST be identical to prevent
        an attacker from distinguishing truncation from padding failure.
        """
        key = os.urandom(32)
        iv = os.urandom(16)
        ciphertext = self._encrypt_cbc(key, iv, b"test data for truncation check")

        # Padding failure (wrong key) — retry for same reason as above
        exc1 = None
        for _ in range(10):
            wrong_key = os.urandom(32)
            decryptor1 = self._make_cbc_decryptor(wrong_key, iv, len(ciphertext))
            try:
                decryptor1.finalize(ciphertext)
            except S3EncryptionClientSecurityError as e:
                exc1 = e
                break
        assert exc1 is not None, "Wrong key did not produce padding error after 10 attempts"

        # Truncated ciphertext (not block-aligned)
        truncated = ciphertext[:-3]
        decryptor2 = self._make_cbc_decryptor(key, iv, len(truncated))
        with pytest.raises(S3EncryptionClientSecurityError) as exc2:
            decryptor2.finalize(truncated)

        # Both MUST produce the same error message
        assert str(exc1) == str(exc2.value), (
            f"Error messages differ: padding_fail={str(exc1)!r}, truncated={str(exc2.value)!r}"
        )


class TestInstructionFileFormatConfusion:
    """Tests for instruction file metadata injection causing format confusion.

    When a V3 object uses instruction files, the instruction file metadata
    is merged with object metadata. If an attacker injects V2-format keys
    into the instruction file (or directly into object metadata), the merged
    metadata may contain keys from multiple format versions. The client
    detects this via has_exclusive_key_collision() and the V2+V3 content
    key coexistence check, rejecting the tampered metadata before format
    dispatch.
    """

    def test_v2_keys_injected_into_v3_metadata_rejected(self):
        """Injecting V2 keys into V3 object metadata MUST be rejected.

        Encrypt a V3 object, then tamper the S3 metadata to add V2 keys
        alongside the existing V3 content keys. The client MUST reject
        this because V2 and V3 keys should never coexist.
        """
        key = _unique_key("sec-v2-inject-v3-")
        data = b"data for format confusion test"
        encryption_context = {"project": "alpha"}

        # 1. Encrypt with V3 format
        s3ec = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

        # 2. Tamper: inject V2 keys alongside existing V3 metadata
        plain_s3 = boto3.client("s3")
        head = plain_s3.head_object(Bucket=bucket, Key=key)
        tampered_metadata = head["Metadata"].copy()

        # Add V2 keys — the V3 keys (x-amz-c, x-amz-d, x-amz-i, x-amz-3, x-amz-w) remain
        tampered_metadata["x-amz-key-v2"] = tampered_metadata.get("x-amz-3", "fake")
        tampered_metadata["x-amz-cek-alg"] = "AES/GCM/NoPadding"
        tampered_metadata["x-amz-iv"] = "AAAAAAAAAAAAAAAA"
        tampered_metadata["x-amz-wrap-alg"] = "kms+context"

        plain_s3.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            Metadata=tampered_metadata,
            MetadataDirective="REPLACE",
        )

        # 3. Decrypt MUST fail — metadata has both V2 and V3 keys
        s3ec_legacy = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
            enable_legacy_wrapping=True,
        )
        with pytest.raises((S3EncryptionClientError, Exception)):
            s3ec_legacy.get_object(Bucket=bucket, Key=key, EncryptionContext=encryption_context)

    def test_exclusive_key_collision_detected_during_decrypt(self):
        """The decrypt pipeline MUST reject metadata with exclusive key collisions.

        When merged metadata contains both V2 and V3 exclusive keys,
        the pipeline detects the collision and raises an error.
        """
        # Create a mock CMM that would return decryption materials
        mock_cmm = MagicMock(spec=DefaultCryptoMaterialsManager)

        pipeline = GetEncryptedObjectPipeline(
            cmm=mock_cmm,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
            enable_legacy_unauthenticated_modes=False,
        )

        # Build a response with merged V2+V3 metadata (simulating the
        # instruction file injection after merge)
        fake_edk = base64.b64encode(os.urandom(32)).decode()
        fake_iv = base64.b64encode(os.urandom(12)).decode()
        fake_message_id = base64.b64encode(os.urandom(28)).decode()
        fake_commitment = base64.b64encode(os.urandom(28)).decode()

        merged_metadata = {
            # V2 keys (from attacker instruction file)
            "x-amz-key-v2": fake_edk,
            "x-amz-cek-alg": "AES/GCM/NoPadding",
            "x-amz-iv": fake_iv,
            "x-amz-wrap-alg": "kms+context",
            "x-amz-matdesc": '{"aws:x-amz-cek-alg": "AES/GCM/NoPadding"}',
            # V3 keys (from object metadata)
            "x-amz-c": "115",
            "x-amz-d": fake_commitment,
            "x-amz-i": fake_message_id,
            "x-amz-w": "12",
            "x-amz-3": fake_edk,
        }

        fake_body = MagicMock()
        fake_body.read.return_value = os.urandom(48)  # fake ciphertext

        response = {
            "Body": fake_body,
            "Metadata": merged_metadata,
            "ContentLength": 48,
        }

        # This SHOULD raise an error due to exclusive key collision,
        # but currently routes to _decrypt_v2 instead
        with pytest.raises(S3EncryptionClientError):
            pipeline.decrypt(
                response,
                instruction_suffix=".instruction",
                enable_delayed_authentication=False,
                encryption_context={},
            )
