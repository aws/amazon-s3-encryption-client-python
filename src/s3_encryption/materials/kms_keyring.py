# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""KMS keyring module for S3 Encryption Client.

This module provides a KMS-based keyring implementation that uses AWS KMS
to generate and decrypt data keys for S3 object encryption.
"""

from attrs import define, field
from botocore import client

from ..exceptions import S3EncryptionClientError
from ..materials.materials import AlgorithmSuite
from .encrypted_data_key import EncryptedDataKey
from .keyring import S3Keyring

KMS_CONTEXT_DEFAULT_KEY = "aws:x-amz-cek-alg"
KMS_V1_DEFAULT_KEY = "kms_cmk_id"


##= specification/s3-encryption/materials/s3-kms-keyring.md#interface
##= type=implication
##% The KmsKeyring MUST implement the [Keyring interface](keyrings.md#interface) and include
##% the behavior described in the [S3 Keyring](s3-keyring.md).
@define
class KmsKeyring(S3Keyring):
    """KMS implementation of the S3 keyring.

    This keyring uses AWS KMS to generate and decrypt data keys.

    Attributes:
        kms_client (client.BaseClient): The boto3 KMS client
        kms_key_id (str): The KMS key ID to use
        enable_legacy_wrapping_algorithms (bool): Whether to enable legacy wrapping algorithms
    """

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
    ##= type=implementation
    ##% On initialization, the caller MAY provide an AWS KMS SDK client instance.
    ##= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
    ##= type=implication
    ##% If the caller does not provide an AWS KMS SDK client instance or provides a null value,
    ##% the KmsKeyring MUST create a default KMS client instance.
    kms_client: client.BaseClient = field()

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
    ##= type=implementation
    ##% On initialization, the caller MUST provide an AWS KMS key identifier.
    kms_key_id: str = field()

    ##= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    ##= type=implementation
    ##% The KmsV1 mode MUST be only enabled when legacy wrapping algorithms are enabled.
    enable_legacy_wrapping_algorithms: bool = field(default=False)

    def __attrs_post_init__(self):  # noqa: D105
        from .._utils import _USER_AGENT_SUFFIX, append_user_agent

        append_user_agent(self.kms_client, _USER_AGENT_SUFFIX)

    def on_encrypt(self, enc_materials):
        """Process encryption materials using KMS.

        Args:
            enc_materials (EncryptionMaterials or dict): Encryption materials to process

        Returns:
            EncryptionMaterials: The processed encryption materials with KMS-generated keys
        """
        try:
            enc_materials = super().on_encrypt(enc_materials)

            encryption_context = enc_materials.encryption_context

            ##= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
            ##= type=implementation
            ##% The KmsKeyring MUST support encryption using Kms+Context mode.
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
            ##= type=implementation
            ##% The Kms+Context mode MUST be enabled as a fully-supported (non-legacy) wrapping
            ##% algorithm.
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
            ##= type=implication
            ##% The KmsKeyring MUST NOT support encryption using KmsV1 mode.
            # For committing algorithm suites (V3), the encryption context algorithm
            # value is the algorithm suite ID as a string ("115"), not the cipher name.
            # For non-committing suites (V2), use the cipher name ("AES/GCM/NoPadding").
            if (
                enc_materials.encryption_algorithm
                == AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            ):
                encryption_context["aws:x-amz-cek-alg"] = str(
                    enc_materials.encryption_algorithm.suite_id
                )
            else:
                encryption_context["aws:x-amz-cek-alg"] = (
                    enc_materials.encryption_algorithm.cipher_name
                )

            # Python implementation uses KMS GenerateDataKey instead of the spec's
            # EncryptDataKey pattern
            # The spec is wrong and needs to be updated.
            response = self.kms_client.generate_data_key(
                KeyId=self.kms_key_id, KeySpec="AES_256", EncryptionContext=encryption_context
            )
            # Create an EncryptedDataKey instance
            encrypted_data_key = EncryptedDataKey(
                key_provider_id=b"S3Keyring",
                key_provider_info="kms+context",
                encrypted_data_key=response["CiphertextBlob"],
            )
            enc_materials.encrypted_data_key = encrypted_data_key
            enc_materials.plaintext_data_key = response["Plaintext"]
            return enc_materials
        except Exception:
            # If KMS call fails, propagate the exception
            raise

    def on_decrypt(self, dec_materials, encrypted_data_keys=None):
        """Decrypt one of the encrypted data keys and update dec_materials.

        Args:
            dec_materials (DecryptionMaterials): A DecryptionMaterials instance containing
                decryption materials
            encrypted_data_keys (List[EncryptedDataKey], optional): A list of encrypted data
                keys to try.

        Returns:
            DecryptionMaterials: The updated dec_materials with the plaintext data key
        """
        try:
            ##= specification/s3-encryption/materials/s3-keyring.md#ondecrypt
            ##= type=implication
            ##% The OnDecrypt operation is responsible for ensuring that the DecryptionMaterials
            ##% contain valid plaintext and encrypted data keys.
            # Call parent class validation
            dec_materials = super().on_decrypt(dec_materials, encrypted_data_keys)

            # Use encrypted_data_keys from parameters if provided, otherwise use from dec_materials
            edks = (
                encrypted_data_keys
                if encrypted_data_keys is not None
                else dec_materials.encrypted_data_keys
            )

            # The parent class validation ensures there is exactly one EDK
            edk = edks[0]
            edk_bytes = edk.encrypted_data_key

            ##= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
            ##= type=implementation
            ##% The KmsKeyring MUST support decryption using Kms+Context mode.
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
            ##= type=implementation
            ##% The KmsKeyring MUST determine whether to decrypt using KmsV1 mode or
            ##% Kms+Context mode.
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
            ##= type=implementation
            ##% If the Key Provider Info of the Encrypted Data Key is "kms+context", the
            ##% KmsKeyring MUST attempt to decrypt using Kms+Context mode.
            if edk.key_provider_info == "kms+context":
                encryption_context_from_request = dec_materials.encryption_context_from_request
                encryption_context_stored = dec_materials.encryption_context_stored

                ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
                ##= type=implementation
                ##% When decrypting using Kms+Context mode, the KmsKeyring MUST validate the
                ##% provided (request) encryption context with the stored (materials) encryption
                ##% context.
                if KMS_CONTEXT_DEFAULT_KEY in encryption_context_from_request:
                    raise S3EncryptionClientError(
                        f"{KMS_CONTEXT_DEFAULT_KEY} is a reserved key for the S3 encryption client"
                    )

                ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
                ##= type=implementation
                ##% The stored encryption context with the two reserved keys removed MUST match
                ##% the provided encryption context.
                encryption_context_stored_copy = encryption_context_stored.copy()
                encryption_context_stored_copy.pop(KMS_V1_DEFAULT_KEY, None)
                encryption_context_stored_copy.pop(KMS_CONTEXT_DEFAULT_KEY, None)

                ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
                ##= type=implementation
                ##% If the stored encryption context with the two reserved keys removed does not
                ##% match the provided encryption context, the KmsKeyring MUST throw an exception.
                if encryption_context_stored_copy != encryption_context_from_request:
                    # TODO: modeled error
                    raise S3EncryptionClientError(
                        "Provided encryption context does not match information retrieved from S3"
                    )

            ##= specification/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
            ##= type=implication
            ##% If the Key Provider Info of the Encrypted Data Key is "kms", the KmsKeyring
            ##% MUST attempt to decrypt using KmsV1 mode.
            elif edk.key_provider_info == "kms":
                ##= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
                ##= type=implementation
                ##% The KmsKeyring MUST support decryption using KmsV1 mode.
                if not self.enable_legacy_wrapping_algorithms:
                    raise S3EncryptionClientError(
                        f"Enable legacy wrapping algorithms to use legacy key wrapping "
                        f"algorithm: {edk.key_provider_info}"
                    )
                # The KmsV1 wrapping algorithm does not support caller-provided
                # encryption context. If the caller provided encryption context,
                # the client MUST reject the request. This prevents a downgrade
                # from kms+context to kms from bypassing context validation.
                if dec_materials.encryption_context_from_request:
                    raise S3EncryptionClientError(
                        "Encryption context is not supported with the KmsV1 (kms) "
                        "wrapping algorithm. Use kms+context wrapping algorithm to "
                        "use encryption context."
                    )
            else:
                raise S3EncryptionClientError(
                    f"{edk.key_provider_info} is not a valid key wrapping algorithm!"
                )

            ##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            ##= type=implementation
            ##% To attempt to decrypt a particular [encrypted data key](../structures.md#
            ##% encrypted-data-key), the KmsKeyring MUST call [AWS KMS Decrypt](https://
            ##% docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the
            ##% configured AWS KMS client.
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            ##= type=implementation
            ##% - `KeyId` MUST be the configured AWS KMS key identifier.
            ##% - `CiphertextBlob` MUST be the [encrypted data key ciphertext](
            ##% ../structures.md#ciphertext).
            ##% - `EncryptionContext` MUST be the [encryption context](../structures.md#
            ##% encryption-context) included in the input [decryption materials](
            ##% ../structures.md#decryption-materials).
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
            ##= type=implementation
            ##% To attempt to decrypt a particular [encrypted data key](../structures.md#
            ##% encrypted-data-key), the KmsKeyring MUST call [AWS KMS Decrypt](https://
            ##% docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the
            ##% configured AWS KMS client.
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
            ##= type=implication
            ##% - `KeyId` MUST be the configured AWS KMS key identifier.
            ##% - `CiphertextBlob` MUST be the [encrypted data key ciphertext](
            ##% ../structures.md#ciphertext).
            ##% - `EncryptionContext` MUST be the [encryption context](../structures.md#
            ##% encryption-context) included in the input [decryption materials](
            ##% ../structures.md#decryption-materials).
            response = self.kms_client.decrypt(
                KeyId=self.kms_key_id,
                CiphertextBlob=edk_bytes,
                EncryptionContext=dec_materials.encryption_context_stored,
            )
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
            ##= type=implication
            ##% The KmsKeyring MUST immediately return the plaintext as a collection of
            ##% bytes.
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            ##= type=implication
            ##% The KmsKeyring MUST immediately return the plaintext as a collection of
            ##% bytes.
            dec_materials.plaintext_data_key = response["Plaintext"]
            return dec_materials
        except Exception:
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            ##= type=implementation
            ##% If the KmsKeyring fails to successfully decrypt the [encrypted data key](
            ##% ../structures.md#encrypted-data-key), then it MUST throw an exception.
            ##= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
            ##= type=implementation
            ##% If the KmsKeyring fails to successfully decrypt the [encrypted data key](
            ##% ../structures.md#encrypted-data-key), then it MUST throw an exception.
            raise
