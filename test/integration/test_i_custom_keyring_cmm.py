# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for custom keyring and custom CMM.

These tests verify that user-implemented AbstractKeyring and
AbstractCryptoMaterialsManager subclasses work end-to-end through
S3EncryptionClient.put_object / get_object.

WARNING: The custom classes below are test-only stubs that duplicate the
built-in KmsKeyring and DefaultCryptoMaterialsManager logic. They exist
solely to prove the extension points work. Do NOT use them in production.
"""

import os
from datetime import datetime

import boto3

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.crypto_materials_manager import AbstractCryptoMaterialsManager
from s3_encryption.materials.encrypted_data_key import EncryptedDataKey
from s3_encryption.materials.keyring import S3Keyring
from s3_encryption.materials.materials import (
    AlgorithmSuite,
    CommitmentPolicy,
    DecryptionMaterials,
    EncryptionMaterials,
)

bucket = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
region = os.environ.get("CI_AWS_REGION", "us-west-2")
kms_key_id = os.environ.get(
    "CI_KMS_KEY_ALIAS", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"
)

KMS_CONTEXT_DEFAULT_KEY = "aws:x-amz-cek-alg"


# ---------------------------------------------------------------------------
# Custom keyring — test-only, do NOT use in production code.
# Duplicates KmsKeyring logic to prove the AbstractKeyring extension point.
# ---------------------------------------------------------------------------


class CustomTestKmsKeyring(S3Keyring):
    """Test-only KMS keyring. Do NOT use in production."""

    def __init__(self, kms_client, kms_key_id):
        self.kms_client = kms_client
        self.kms_key_id = kms_key_id

    def on_encrypt(self, enc_materials):
        enc_materials = super().on_encrypt(enc_materials)
        encryption_context = enc_materials.encryption_context

        if (
            enc_materials.encryption_algorithm
            == AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        ):
            encryption_context[KMS_CONTEXT_DEFAULT_KEY] = str(
                enc_materials.encryption_algorithm.suite_id
            )
        else:
            encryption_context[KMS_CONTEXT_DEFAULT_KEY] = (
                enc_materials.encryption_algorithm.cipher_name
            )

        response = self.kms_client.generate_data_key(
            KeyId=self.kms_key_id, KeySpec="AES_256", EncryptionContext=encryption_context
        )
        enc_materials.encrypted_data_key = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info="kms+context",
            encrypted_data_key=response["CiphertextBlob"],
        )
        enc_materials.plaintext_data_key = response["Plaintext"]
        return enc_materials

    def on_decrypt(self, dec_materials, encrypted_data_keys=None):
        dec_materials = super().on_decrypt(dec_materials, encrypted_data_keys)
        edks = (
            encrypted_data_keys
            if encrypted_data_keys is not None
            else dec_materials.encrypted_data_keys
        )
        edk = edks[0]

        if edk.key_provider_info == "kms+context":
            ec_from_request = dec_materials.encryption_context_from_request
            ec_stored = dec_materials.encryption_context_stored

            if KMS_CONTEXT_DEFAULT_KEY in ec_from_request:
                raise S3EncryptionClientError(f"{KMS_CONTEXT_DEFAULT_KEY} is a reserved key")

            ec_stored_copy = ec_stored.copy()
            ec_stored_copy.pop("kms_cmk_id", None)
            ec_stored_copy.pop(KMS_CONTEXT_DEFAULT_KEY, None)

            if ec_stored_copy != ec_from_request:
                raise S3EncryptionClientError("Provided encryption context does not match")
        elif edk.key_provider_info != "kms":
            raise S3EncryptionClientError(
                f"{edk.key_provider_info} is not a valid key wrapping algorithm!"
            )

        response = self.kms_client.decrypt(
            KeyId=self.kms_key_id,
            CiphertextBlob=edk.encrypted_data_key,
            EncryptionContext=dec_materials.encryption_context_stored,
        )
        dec_materials.plaintext_data_key = response["Plaintext"]
        return dec_materials


# ---------------------------------------------------------------------------
# Custom CMM — test-only, do NOT use in production code.
# Duplicates DefaultCryptoMaterialsManager logic to prove the CMM extension point.
# ---------------------------------------------------------------------------


class CustomTestCMM(AbstractCryptoMaterialsManager):
    """Test-only CMM. Do NOT use in production."""

    def __init__(self, keyring):
        self.keyring = keyring

    def get_encryption_materials(self, enc_mats_request):
        if isinstance(enc_mats_request, dict):
            materials = EncryptionMaterials(
                encryption_context=enc_mats_request.get("encryption_context", {})
            )
        else:
            materials = enc_mats_request
        return self.keyring.on_encrypt(materials)

    def decrypt_materials(self, dec_mats_request):
        if isinstance(dec_mats_request, dict):
            materials = DecryptionMaterials.from_dict(dec_mats_request)
        else:
            materials = dec_mats_request
        return self.keyring.on_decrypt(materials, materials.encrypted_data_keys)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _unique_key(prefix):
    return prefix + datetime.now().strftime("%Y-%m-%d-%H:%M:%S-%f")


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


class TestCustomKeyring:
    """Verify a user-implemented AbstractKeyring subclass works end-to-end."""

    def test_roundtrip_with_custom_keyring(self):
        """Custom keyring MUST encrypt and decrypt successfully."""
        kms_client = boto3.client("kms", region_name=region)
        keyring = CustomTestKmsKeyring(kms_client, kms_key_id)
        wrapped_client = boto3.client("s3")
        config = S3EncryptionClientConfig(keyring=keyring)
        s3ec = S3EncryptionClient(wrapped_client, config)

        key = _unique_key("custom-keyring-rt-")
        data = b"custom keyring round trip test"

        s3ec.put_object(Bucket=bucket, Key=key, Body=data)
        response = s3ec.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read() == data

    def test_roundtrip_with_custom_keyring_aes_gcm(self):
        """Custom keyring MUST work with non-committing AES-GCM suite."""
        kms_client = boto3.client("kms", region_name=region)
        keyring = CustomTestKmsKeyring(kms_client, kms_key_id)
        wrapped_client = boto3.client("s3")
        config = S3EncryptionClientConfig(
            keyring=keyring,
            encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        )
        s3ec = S3EncryptionClient(wrapped_client, config)

        key = _unique_key("custom-keyring-gcm-rt-")
        data = b"custom keyring AES-GCM round trip"

        s3ec.put_object(Bucket=bucket, Key=key, Body=data)
        response = s3ec.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read() == data


class TestCustomCMM:
    """Verify a user-implemented AbstractCryptoMaterialsManager subclass works end-to-end."""

    def test_roundtrip_with_custom_cmm(self):
        """Custom CMM MUST encrypt and decrypt successfully."""
        from s3_encryption.materials.kms_keyring import KmsKeyring

        kms_client = boto3.client("kms", region_name=region)
        keyring = KmsKeyring(kms_client, kms_key_id)
        custom_cmm = CustomTestCMM(keyring)
        wrapped_client = boto3.client("s3")
        config = S3EncryptionClientConfig(keyring=keyring, cmm=custom_cmm)
        s3ec = S3EncryptionClient(wrapped_client, config)

        key = _unique_key("custom-cmm-rt-")
        data = b"custom CMM round trip test"

        s3ec.put_object(Bucket=bucket, Key=key, Body=data)
        response = s3ec.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read() == data

    def test_roundtrip_with_custom_cmm_aes_gcm(self):
        """Custom CMM MUST work with non-committing AES-GCM suite."""
        from s3_encryption.materials.kms_keyring import KmsKeyring

        kms_client = boto3.client("kms", region_name=region)
        keyring = KmsKeyring(kms_client, kms_key_id)
        custom_cmm = CustomTestCMM(keyring)
        wrapped_client = boto3.client("s3")
        config = S3EncryptionClientConfig(
            keyring=keyring,
            cmm=custom_cmm,
            encryption_algorithm=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
            commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        )
        s3ec = S3EncryptionClient(wrapped_client, config)

        key = _unique_key("custom-cmm-gcm-rt-")
        data = b"custom CMM AES-GCM round trip"

        s3ec.put_object(Bucket=bucket, Key=key, Body=data)
        response = s3ec.get_object(Bucket=bucket, Key=key)
        assert response["Body"].read() == data
