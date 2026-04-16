# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security integration tests for S3 Encryption Client.

These tests verify that the client correctly handles metadata tampering
scenarios, particularly wrapping algorithm downgrade attempts that modify
metadata to bypass encryption context validation.
"""

import json
import os
from datetime import datetime

import boto3
import pytest

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.kms_keyring import KmsKeyring
from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy

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
        assert (
            original_metadata.get("x-amz-w") == "12"
        ), f"Expected x-amz-w='12', got {original_metadata.get('x-amz-w')}"

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

    V2 stores the wrapping algorithm in x-amz-wrap-alg. When changed from
    'kms+context' to 'kms', the KmsV1 decryption path is used. Since
    x-amz-matdesc already contains the original bound context, KMS Decrypt
    succeeds and the caller-provided EncryptionContext is not validated.

    This is a known limitation of the V2 format when legacy wrapping
    algorithms are enabled.
    """

    @pytest.mark.xfail(
        reason="Known V2 format limitation: the KmsV1 path does not perform "
        "client-side encryption context comparison, and x-amz-matdesc "
        "contains the original bound context.",
        strict=True,
    )
    def test_v2_downgrade_wrap_alg_to_kms_mismatched_context(self):
        """Tampering x-amz-wrap-alg from 'kms+context' to 'kms' with wrong context.

        With legacy wrapping enabled, the KmsV1 path uses the stored matdesc
        for KMS Decrypt, which succeeds. The mismatched caller context is
        not checked.
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
        assert (
            original_metadata.get("x-amz-wrap-alg") == "kms+context"
        ), f"Expected x-amz-wrap-alg='kms+context', got {original_metadata.get('x-amz-wrap-alg')}"

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
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        return encryptor.update(padded) + encryptor.finalize()

    def _make_cbc_decryptor(self, key, iv, content_length):
        """Helper to create an AesCbcDecryptor."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7

        from s3_encryption.decryptor import AesCbcDecryptor

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        unpadder = PKCS7(128).unpadder()
        return AesCbcDecryptor(cipher.decryptor(), unpadder, content_length)

    def test_wrong_key_and_tampered_ciphertext_produce_same_error(self):
        """Wrong key and tampered ciphertext MUST produce identical error messages.

        Both cause PKCS7 unpadding to fail, but the error message and type
        MUST be the same so an attacker cannot distinguish between them.
        """
        import os

        from s3_encryption.exceptions import S3EncryptionClientSecurityError

        key = os.urandom(32)
        iv = os.urandom(16)
        ciphertext = self._encrypt_cbc(key, iv, b"test data for padding oracle check")

        # Wrong key: decryption produces garbage, unpadding fails
        wrong_key = os.urandom(32)
        decryptor1 = self._make_cbc_decryptor(wrong_key, iv, len(ciphertext))
        with pytest.raises(S3EncryptionClientSecurityError) as exc1:
            decryptor1.finalize(ciphertext)

        # Tampered ciphertext: last byte flipped, unpadding fails
        tampered = ciphertext[:-1] + bytes([(ciphertext[-1] ^ 0x01)])
        decryptor2 = self._make_cbc_decryptor(key, iv, len(tampered))
        with pytest.raises(S3EncryptionClientSecurityError) as exc2:
            decryptor2.finalize(tampered)

        # Both MUST produce the same error message
        assert str(exc1.value) == str(exc2.value), (
            f"Error messages differ: wrong_key={str(exc1.value)!r}, "
            f"tampered={str(exc2.value)!r}"
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
        import os

        from s3_encryption.exceptions import S3EncryptionClientSecurityError

        key = os.urandom(32)
        iv = os.urandom(16)
        ciphertext = self._encrypt_cbc(key, iv, b"test data for truncation check")

        # Padding failure (wrong key)
        wrong_key = os.urandom(32)
        decryptor1 = self._make_cbc_decryptor(wrong_key, iv, len(ciphertext))
        with pytest.raises(S3EncryptionClientSecurityError) as exc1:
            decryptor1.finalize(ciphertext)

        # Truncated ciphertext (not block-aligned)
        truncated = ciphertext[:-3]
        decryptor2 = self._make_cbc_decryptor(key, iv, len(truncated))
        with pytest.raises(S3EncryptionClientSecurityError) as exc2:
            decryptor2.finalize(truncated)

        # Both MUST produce the same error message
        assert str(exc1.value) == str(exc2.value), (
            f"Error messages differ: padding_fail={str(exc1.value)!r}, "
            f"truncated={str(exc2.value)!r}"
        )


class TestInstructionFileFormatConfusion:
    """Tests for instruction file metadata injection causing format confusion.

    When a V3 object uses instruction files, the instruction file metadata
    is merged with object metadata. If an attacker injects V2-format keys
    into the instruction file, the merged metadata may match is_v2_format()
    before is_v3_format(), causing the V2 decryption path to execute and
    bypassing V3 key-commitment verification.

    The has_exclusive_key_collision() method exists to detect this but is
    not called in any production code path.
    """

    def test_v2_keys_in_instruction_file_cause_format_confusion(self):
        """Injecting V2 keys into a V3 instruction file MUST be detected.

        After merging instruction file metadata (containing V2 keys) with
        object metadata (containing V3 keys), the resulting ObjectMetadata
        has V2 keys plus V3 content keys. is_v2_format() matches first
        because it does not check for V3 key absence, causing the V2
        decryption path to execute instead of V3.
        """
        from s3_encryption.metadata import ObjectMetadata

        # Simulate V3 object metadata (stored on the S3 object).
        # In V3 instruction file mode, the object metadata has content keys
        # (x-amz-c, x-amz-d, x-amz-i) but NOT the EDK (x-amz-3).
        v3_object_metadata = {
            "x-amz-c": "115",           # V3 content cipher
            "x-amz-d": "dGVzdA==",      # V3 key commitment
            "x-amz-i": "bWVzc2FnZQ==",  # V3 message ID
        }

        # Simulate attacker-crafted instruction file with V2 keys.
        # Normally the instruction file would have x-amz-3, x-amz-w, x-amz-t
        # for V3. The attacker replaces these with V2 keys.
        attacker_instruction_file = {
            "x-amz-key-v2": "YXR0YWNrZXJfa2V5",  # V2 encrypted data key
            "x-amz-cek-alg": "AES/GCM/NoPadding",  # V2 content cipher
            "x-amz-iv": "YXR0YWNrZXJfaXY=",        # V2 IV
            "x-amz-wrap-alg": "kms+context",        # V2 wrapping algorithm
            "x-amz-matdesc": '{"aws:x-amz-cek-alg": "AES/GCM/NoPadding"}',
        }

        # The forbidden-keys check only blocks V3-exclusive keys
        v3_exclusive = {"x-amz-c", "x-amz-d", "x-amz-i"}
        injected_keys = set(attacker_instruction_file.keys())
        assert not (injected_keys & v3_exclusive), (
            "Test setup error: attacker keys should not overlap with V3 exclusive keys"
        )

        # Merge: instruction_metadata.update(encryption_metadata)
        # This is the same merge order as pipelines.py line 297
        merged = attacker_instruction_file.copy()
        merged.update(v3_object_metadata)

        merged_metadata = ObjectMetadata.from_dict(merged)

        # The merged metadata has V2 keys AND V3 content keys (x-amz-c, x-amz-d, x-amz-i)
        # but NOT the V3 EDK (x-amz-3), since the attacker replaced it with V2 keys.
        # is_v2_format() matches because it only checks for V2 key presence + V1 absence
        assert merged_metadata.is_v2_format(), (
            "is_v2_format() should match when V2 keys are injected alongside V3 content keys"
        )
        # is_v3_format() does NOT match because encrypted_data_key_v3 is None
        # (the attacker didn't include x-amz-3) AND encrypted_data_key_v2 is not None
        assert not merged_metadata.is_v3_format(), (
            "is_v3_format() should NOT match when V2 EDK key is present"
        )
        # V3 content keys are present but ignored — format dispatch goes to V2
        assert merged_metadata.content_cipher_v3 is not None, (
            "V3 content cipher should still be present in merged metadata"
        )

    def test_exclusive_key_collision_detected_during_decrypt(self):
        """The decrypt pipeline MUST reject metadata with exclusive key collisions.

        When merged metadata contains both V2 and V3 exclusive keys,
        the pipeline should detect the collision and raise an error
        rather than silently routing to the V2 decryption path.
        """
        import base64
        import os
        from unittest.mock import MagicMock, patch

        from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
        from s3_encryption.materials.materials import CommitmentPolicy, DecryptionMaterials
        from s3_encryption.pipelines import GetEncryptedObjectPipeline

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
