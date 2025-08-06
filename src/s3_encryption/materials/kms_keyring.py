# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from .keyring import S3Keyring
from .encrypted_data_key import EncryptedDataKey
from .materials import EncryptionMaterials
from ..exceptions import S3EncryptionClientError
from attrs import define, field

KMS_CONTEXT_DEFAULT_KEY = "aws:x-amz-cek-alg"
KMS_V1_DEFAULT_KEY = "kms_cmk_id"

@define
class KmsKeyring(S3Keyring):
    kms_client = field()
    kms_key_id: str = field()
    enable_legacy_wrapping_algorithms: bool = field(default=False)

    def onEncrypt(self, encMaterials):
        """
        Process encryption materials using KMS.
        
        Args:
            encMaterials (EncryptionMaterials): Encryption materials to process
                
        Returns:
            EncryptionMaterials: The processed encryption materials with KMS-generated keys
        """
        try:
            # Call parent class validation
            encMaterials = super().onEncrypt(encMaterials)
            
            # Add default encryption context
            encryption_context = encMaterials.encryption_context
            encryption_context["aws:x-amz-cek-alg"] = "AES/GCM/NoPadding"

            response = self.kms_client.generate_data_key(
                KeyId = self.kms_key_id,
                KeySpec = 'AES_256',
                EncryptionContext = encryption_context
            )
            # Create an EncryptedDataKey instance
            encrypted_data_key = EncryptedDataKey(
                key_provider_id=b'S3Keyring',
                key_provider_info="kms+context",
                encrypted_data_key=response['CiphertextBlob']
            )
            encMaterials.encrypted_data_key = encrypted_data_key
            encMaterials.plaintext_data_key = response['Plaintext']
            return encMaterials
        except Exception as e:
            raise

    def onDecrypt(self, decMaterials, encrypted_data_keys=None):
        """
        Decrypt one of the encrypted data keys and update decMaterials.
        
        Args:
            decMaterials (dict): A dictionary containing decryption materials
            encrypted_data_keys (List[EncryptedDataKey], optional): A list of encrypted data keys to try.
                
        Returns:
            dict: The updated decMaterials with the plaintext data key (PDK)
        """
        try:
            # Call parent class validation
            decMaterials = super().onDecrypt(decMaterials, encrypted_data_keys)
            
            # Handle both single EDK (backward compatibility) and list of EDKs
            edks = encrypted_data_keys
            
            # Try to decrypt each EDK until one succeeds
            # TODO: probably just enforce |EDKs| == 1 and remove loop
            last_exception = None
            for edk in edks:
                try:
                    edk_bytes = edk.encrypted_data_key
                    if edk.key_provider_info == "kms+context":
                        encryption_context_from_request = decMaterials.get('encryption_context_from_request', {})
                        encryption_context_stored = decMaterials.get('encryption_context_stored', {})

                        # Default EC MUST NOT be passed in via request
                        if KMS_CONTEXT_DEFAULT_KEY in encryption_context_from_request:
                            raise S3EncryptionClientError(f"{KMS_CONTEXT_DEFAULT_KEY} is a reserved key for the S3 encryption client")

                        # The stored EC, minus default key/values, MUST match provided EC
                        encryption_context_stored_copy = encryption_context_stored.copy()
                        encryption_context_stored_copy.pop(KMS_V1_DEFAULT_KEY, None)
                        encryption_context_stored_copy.pop(KMS_CONTEXT_DEFAULT_KEY, None)
                        if encryption_context_stored_copy != encryption_context_from_request:
                            # TODO: modeled error
                            raise S3EncryptionClientError("Provided encryption context does not match information retrieved from S3")

                        # Update decMaterials with the modified encryption context
                    elif edk.key_provider_info == "kms":
                        if not self.enable_legacy_wrapping_algorithms:
                            raise S3EncryptionClientError(f"Enable legacy wrapping algorithms to use legacy key wrapping algorithm: {edk.key_provider_info}")
                    else:
                        raise S3EncryptionClientError(f"{edk.key_provider_info} is not a valid key wrapping algorithm!")

                    response = self.kms_client.decrypt(
                        KeyId = self.kms_key_id,
                        CiphertextBlob = edk_bytes,
                        EncryptionContext = decMaterials['encryption_context_stored']
                    )
                    decMaterials['PDK'] = response['Plaintext']
                    return decMaterials
                except Exception as e:
                    last_exception = e
                    continue
            
            # If we get here, none of the EDKs could be decrypted
            if last_exception:
                raise last_exception
            else:
                raise S3EncryptionClientError("Failed to decrypt any of the encrypted data keys")
        except Exception as e:
            raise
