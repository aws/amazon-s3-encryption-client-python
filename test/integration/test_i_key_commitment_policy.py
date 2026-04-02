# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for key commitment policy enforcement through the front door.

These tests verify that commitment policy behavior works end-to-end through
S3EncryptionClient.put_object / get_object, not just at the pipeline level.

Objects are encrypted with one policy and decrypted with another to verify
cross-policy compatibility.
"""

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


def _make_client(algorithm_suite, commitment_policy):
    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(
        keyring,
        encryption_algorithm=algorithm_suite,
        commitment_policy=commitment_policy,
    )
    return S3EncryptionClient(wrapped_client, config)


def _unique_key(prefix):
    return prefix + datetime.now().strftime("%Y-%m-%d-%H:%M:%S-%f")


# ---------------------------------------------------------------------------
# Non-committing (V2 GCM) objects decrypted under various policies
# ---------------------------------------------------------------------------


class TestNonCommittingObjectDecryptPolicies:
    """Verify V2 (non-committing) objects can be decrypted under ALLOW policies
    and rejected under REQUIRE_REQUIRE.
    """

    PLAINTEXT = b"non-committing policy integration test"

    @pytest.fixture(autouse=True, scope="class")
    def _encrypt_v2_object(self, request):
        """Encrypt a single V2 object to be shared across all tests in this class."""
        key = _unique_key("kc-v2-policy-")
        writer = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        )
        writer.put_object(Bucket=bucket, Key=key, Body=self.PLAINTEXT)
        request.cls.s3_key = key

    def test_forbid_encrypt_allow_decrypt_decrypts_non_committing(self):
        """FORBID_ENCRYPT_ALLOW_DECRYPT MUST decrypt non-committing objects."""
        reader = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        )
        response = reader.get_object(Bucket=bucket, Key=self.s3_key)
        assert response["Body"].read() == self.PLAINTEXT

    def test_require_encrypt_allow_decrypt_decrypts_non_committing(self):
        """REQUIRE_ENCRYPT_ALLOW_DECRYPT MUST decrypt non-committing objects."""
        reader = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        )
        response = reader.get_object(Bucket=bucket, Key=self.s3_key)
        assert response["Body"].read() == self.PLAINTEXT

    def test_require_require_rejects_non_committing(self):
        """REQUIRE_ENCRYPT_REQUIRE_DECRYPT MUST reject non-committing objects."""
        reader = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        with pytest.raises(S3EncryptionClientError, match="cannot decrypt non-key-committing"):
            reader.get_object(Bucket=bucket, Key=self.s3_key)


# ---------------------------------------------------------------------------
# Committing (V3 KC-GCM) objects decrypted under various policies
# ---------------------------------------------------------------------------

# Writer policies that produce committing (V3) objects
COMMITTING_WRITER_POLICIES = [
    pytest.param(
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        id="writer=REQUIRE_REQUIRE",
    ),
    pytest.param(
        CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        id="writer=REQUIRE_ALLOW",
    ),
]


@pytest.mark.parametrize("writer_policy", COMMITTING_WRITER_POLICIES)
class TestCommittingObjectDecryptPolicies:
    """Verify V3 (committing) objects can be decrypted under all three policies,
    regardless of which REQUIRE_ENCRYPT_* policy was used to write them.
    """

    PLAINTEXT = b"committing policy integration test"

    @pytest.fixture(autouse=True)
    def _encrypt_v3_object(self, writer_policy):
        """Encrypt a V3 object with the parametrized writer policy."""
        key = _unique_key("kc-v3-policy-")
        writer = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            writer_policy,
        )
        writer.put_object(Bucket=bucket, Key=key, Body=self.PLAINTEXT)
        self.s3_key = key

    def test_require_require_decrypts_committing(self):
        """REQUIRE_ENCRYPT_REQUIRE_DECRYPT MUST decrypt committing objects."""
        reader = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        response = reader.get_object(Bucket=bucket, Key=self.s3_key)
        assert response["Body"].read() == self.PLAINTEXT

    def test_require_encrypt_allow_decrypt_decrypts_committing(self):
        """REQUIRE_ENCRYPT_ALLOW_DECRYPT MUST decrypt committing objects."""
        reader = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        )
        response = reader.get_object(Bucket=bucket, Key=self.s3_key)
        assert response["Body"].read() == self.PLAINTEXT

    def test_forbid_encrypt_allow_decrypt_decrypts_committing(self):
        """FORBID_ENCRYPT_ALLOW_DECRYPT MUST decrypt committing objects."""
        reader = _make_client(
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        )
        response = reader.get_object(Bucket=bucket, Key=self.s3_key)
        assert response["Body"].read() == self.PLAINTEXT


# ---------------------------------------------------------------------------
# Encrypt-side config rejection (no S3 needed, but verifies front-door behavior)
# ---------------------------------------------------------------------------


class TestEncryptPolicyRejection:
    """Verify that incompatible algorithm + policy combos are rejected at config time."""

    def test_require_encrypt_allow_decrypt_rejects_non_committing(self):
        """REQUIRE_ENCRYPT_ALLOW_DECRYPT MUST reject non-committing algorithm at config time."""
        kms_client = boto3.client("kms", region_name=region)
        keyring = KmsKeyring(kms_client, kms_key_id)
        with pytest.raises(S3EncryptionClientError):
            S3EncryptionClientConfig(
                keyring,
                encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
                commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
            )

    def test_require_encrypt_require_decrypt_rejects_non_committing(self):
        """REQUIRE_ENCRYPT_REQUIRE_DECRYPT MUST reject non-committing algorithm at config time."""
        kms_client = boto3.client("kms", region_name=region)
        keyring = KmsKeyring(kms_client, kms_key_id)
        with pytest.raises(S3EncryptionClientError):
            S3EncryptionClientConfig(
                keyring,
                encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
                commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            )

    def test_forbid_encrypt_allow_decrypt_rejects_committing(self):
        """FORBID_ENCRYPT_ALLOW_DECRYPT MUST reject committing algorithm at config time."""
        kms_client = boto3.client("kms", region_name=region)
        keyring = KmsKeyring(kms_client, kms_key_id)
        with pytest.raises(S3EncryptionClientError):
            S3EncryptionClientConfig(
                keyring,
                encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
                commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            )
