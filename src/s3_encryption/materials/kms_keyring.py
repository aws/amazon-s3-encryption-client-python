# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""KMS keyring module for S3 Encryption Client.

This module provides a KMS-based keyring implementation that uses AWS KMS
to generate and decrypt data keys for S3 object encryption.
"""

from attrs import define, field

from ..exceptions import S3EncryptionClientError
from .encrypted_data_key import EncryptedDataKey
from .keyring import S3Keyring

KMS_CONTEXT_DEFAULT_KEY = "aws:x-amz-cek-alg"
KMS_V1_DEFAULT_KEY = "kms_cmk_id"


@define
class KmsKeyring(S3Keyring):
    """KMS implementation of the S3 keyring.

    This keyring uses AWS KMS to generate and decrypt data keys.

    Attributes:
        kms_client: The boto3 KMS client
        kms_key_id (str): The KMS key ID to use
        enable_legacy_wrapping_algorithms (bool): Whether to enable legacy wrapping algorithms
    """
    kms_client = field()
    kms_key_id: str = field()
    enable_legacy_wrapping_algorithms: bool = field(default=False)

    def on_encrypt(self, enc_materials):
        """Process encryption materials using KMS.

        Args:
            enc_materials (EncryptionMaterials): Encryption materials to process

        Returns:
            EncryptionMaterials: The processed encryption materials with KMS-generated keys
        """
        try:
            # Call parent class validation
            enc_materials = super().on_encrypt(enc_materials)

            # Add default encryption context
            encryption_context = enc_materials.encryption_context
            encryption_context["aws:x-amz-cek-alg"] = "AES/GCM/NoPadding"

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
            raise

    def on_decrypt(self, dec_materials, encrypted_data_keys=None):
        """Decrypt one of the encrypted data keys and update dec_materials.

        Args:
            dec_materials (DecryptionMaterials): A DecryptionMaterials instance containing
                decryption materials
            encrypted_data_keys (List[EncryptedDataKey], optional): A list of encrypted data
                keys to try.

        Returns:
            DecryptionMaterials: The updated dec_materials with the plaintext data key (PDK)
        """
        try:
            # Call parent class validation
            dec_materials = super().on_decrypt(dec_materials, encrypted_data_keys)

            # Use encrypted_data_keys from parameters if provided, otherwise use from dec_materials
            edks = (
                encrypted_data_keys
                if encrypted_data_keys is not None
                else dec_materials.encrypted_data_keys
            )

            # Try to decrypt each EDK until one succeeds
            # TODO: probably just enforce |EDKs| == 1 and remove loop
            last_exception = None
            for edk in edks:
                try:
                    edk_bytes = edk.encrypted_data_key
                    if edk.key_provider_info == "kms+context":
                        encryption_context_from_request = (
                            dec_materials.encryption_context_from_request
                        )
                        encryption_context_stored = dec_materials.encryption_context_stored

                        # Default EC MUST NOT be passed in via request
                        if KMS_CONTEXT_DEFAULT_KEY in encryption_context_from_request:
                            raise S3EncryptionClientError(
                                f"{KMS_CONTEXT_DEFAULT_KEY} is a reserved key for the "
                                f"S3 encryption client"
                            )

                        # The stored EC, minus default key/values, MUST match provided EC
                        encryption_context_stored_copy = encryption_context_stored.copy()
                        encryption_context_stored_copy.pop(KMS_V1_DEFAULT_KEY, None)
                        encryption_context_stored_copy.pop(KMS_CONTEXT_DEFAULT_KEY, None)
                        if encryption_context_stored_copy != encryption_context_from_request:
                            # TODO: modeled error
                            raise S3EncryptionClientError(
                                "Provided encryption context does not match information "
                                "retrieved from S3"
                            )

                        # Update decMaterials with the modified encryption context
                    elif edk.key_provider_info == "kms":
                        if not self.enable_legacy_wrapping_algorithms:
                            raise S3EncryptionClientError(
                                f"Enable legacy wrapping algorithms to use legacy key wrapping "
                                f"algorithm: {edk.key_provider_info}"
                            )
                    else:
                        raise S3EncryptionClientError(
                            f"{edk.key_provider_info} is not a valid key wrapping algorithm!"
                        )

                    response = self.kms_client.decrypt(
                        KeyId=self.kms_key_id,
                        CiphertextBlob=edk_bytes,
                        EncryptionContext=dec_materials.encryption_context_stored,
                    )
                    dec_materials.plaintext_data_key = response["Plaintext"]
                    return dec_materials
                except Exception as e:
                    last_exception = e
                    continue

            # If we get here, none of the EDKs could be decrypted
            if last_exception:
                raise last_exception
            raise S3EncryptionClientError("Failed to decrypt any of the encrypted data keys")
        except Exception:
            raise
