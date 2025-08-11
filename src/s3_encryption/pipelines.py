# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import base64
import os

from attrs import define, field
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .materials.crypto_materials_manager import AbstractCryptoMaterialsManager
from .materials.encrypted_data_key import EncryptedDataKey
from .materials.materials import DecryptionMaterials, EncryptionMaterials
from .metadata import ObjectMetadata


@define
class PutEncryptedObjectPipeline:
    """Pipeline for encrypting objects before they are put into S3.

    This pipeline handles only the encryption process for S3 objects.
    The actual S3 API calls are handled by the S3EncryptionClient.
    """

    cmm: AbstractCryptoMaterialsManager = field()

    def encrypt(self, plaintext, encryption_context=None):
        """Encrypt the data before it is stored in S3.

        Args:
            data (bytes or str): The data to be encrypted
            encryption_context (dict, optional): Additional context for encryption

        Returns:
            bytes: The encrypted data
            dict: Metadata about the encryption to be stored with the object
        """
        # Create encryption materials request with encryption context
        enc_mats_request = EncryptionMaterials(
            encryption_context={} if encryption_context is None else encryption_context
        )

        # Get encryption materials from the crypto materials manager
        enc_mats = self.cmm.getEncryptionMaterials(enc_mats_request)

        # Generate initialization vector
        iv = os.urandom(12)

        # Encrypt the data
        if enc_mats.plaintext_data_key is None:
            raise RuntimeError("No plaintext data key found!")

        aesgcm = AESGCM(enc_mats.plaintext_data_key)
        ciphertext = aesgcm.encrypt(nonce=iv, data=plaintext, associated_data=None)
        encrypted_data = ciphertext
        b64_iv = base64.b64encode(iv).decode("utf-8")

        # Get the encrypted data key
        if enc_mats.encrypted_data_key is None:
            raise RuntimeError("No encrypted data key found!")

        edk_bytes = enc_mats.encrypted_data_key.encrypted_data_key
        b64_edk = base64.b64encode(edk_bytes).decode("utf-8")

        # Create metadata using the ObjectMetadata class
        metadata = ObjectMetadata(
            encrypted_data_key_v2=b64_edk,
            encrypted_data_key_algorithm="kms+context",
            content_iv=b64_iv,
            content_cipher="AES/GCM/NoPadding",
            encrypted_data_key_context=enc_mats.encryption_context,
        )

        # Convert to dictionary for storage in S3 metadata
        encryption_metadata = metadata.to_dict()

        return encrypted_data, encryption_metadata


@define
class GetEncryptedObjectPipeline:
    """Pipeline for decrypting objects after they are retrieved from S3.

    This pipeline handles only the decryption process for S3 objects.
    The actual S3 API calls are handled by the S3EncryptionClient.
    """

    cmm: AbstractCryptoMaterialsManager = field()

    def decrypt(self, response, encryption_context={}):
        """Decrypt the data after it is retrieved from S3.

        Args:
            response (dict): The response from S3 containing the encrypted data and metadata
            encryption_context (dict, optional): Additional context for decryption

        Returns:
            bytes: The decrypted data
        """
        # Convert the metadata dictionary to an ObjectMetadata instance
        encrypted_data = response.get("Body").read()
        encryption_metadata = response.get("Metadata", {})
        metadata = ObjectMetadata.from_dict(encryption_metadata)

        iv_b64 = metadata.content_iv
        edk_b64 = metadata.encrypted_data_key_v2

        # TODO: probably move this to ObjectMetadata
        iv_bytes = base64.b64decode(iv_b64)

        # Create a list of encrypted data keys to try
        encrypted_data_keys = []
        # Create an instance of EncryptedDataKey
        if edk_b64:
            edk_bytes = base64.b64decode(edk_b64)
            encrypted_data_key = EncryptedDataKey(
                key_provider_id=b"S3Keyring",
                key_provider_info=metadata.encrypted_data_key_algorithm,
                encrypted_data_key=edk_bytes,
            )
            encrypted_data_keys.append(encrypted_data_key)

        # Also check for legacy encrypted data key (v1) if available
        if metadata.encrypted_data_key_v1:
            legacy_edk_bytes = base64.b64decode(metadata.encrypted_data_key_v1)
            legacy_encrypted_data_key = EncryptedDataKey(
                key_provider_id=b"S3Keyring",
                key_provider_info=metadata.encrypted_data_key_algorithm,
                encrypted_data_key=legacy_edk_bytes,
            )
            encrypted_data_keys.append(legacy_encrypted_data_key)

        # Create a DecryptionMaterials instance
        dec_materials = DecryptionMaterials(
            iv=iv_bytes,
            encrypted_data_keys=encrypted_data_keys,
            encryption_context_stored=metadata.encrypted_data_key_context or {},
            encryption_context_from_request=encryption_context or {},
        )

        # Get decryption materials from the crypto materials manager
        dec_materials = self.cmm.decryptMaterials(dec_materials)

        aesgcm = AESGCM(dec_materials.plaintext_data_key)

        plaintext = aesgcm.decrypt(nonce=iv_bytes, data=encrypted_data, associated_data=None)

        return plaintext
