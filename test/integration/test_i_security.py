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
