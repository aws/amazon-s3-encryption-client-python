# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Encryption and decryption pipelines for S3 Encryption Client.

This module provides pipelines for encrypting objects before they are put into S3
and decrypting objects after they are retrieved from S3.
"""

import base64
import os

from attrs import define, field
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import S3EncryptionClientError
from .instruction_file import fetch_instruction_file
from .materials.crypto_materials_manager import AbstractCryptoMaterialsManager
from .materials.encrypted_data_key import EncryptedDataKey
from .materials.materials import DecryptionMaterials, EncryptionMaterials
from .metadata import ObjectMetadata
from .stream import BufferedDecryptingStream, DelayedAuthDecryptingStream


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
            plaintext (bytes or str): The data to be encrypted
            encryption_context (dict, optional): Additional context for encryption

        Returns:
            bytes: The encrypted data
            dict: Metadata about the encryption to be stored with the object
        """
        # Create encryption materials request with encryption context copy
        enc_mats_request = EncryptionMaterials(
            encryption_context={} if encryption_context is None else encryption_context.copy()
        )

        # Get encryption materials from the crypto materials manager
        enc_mats = self.cmm.get_encryption_materials(enc_mats_request)

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
    s3_client: object = field(default=None)

    def decrypt(
        self,
        response,
        encryption_context=None,
        bucket=None,
        key=None,
        instruction_suffix=None,
        enable_delayed_authentication=None,
    ):
        """Decrypt the data after it is retrieved from S3.

        Args:
            response (dict): The response from S3 containing the encrypted data and metadata
            encryption_context (dict, optional): Additional context for decryption
            bucket (str, optional): S3 bucket name (required for instruction file)
            key (str, optional): S3 object key (required for instruction file)
            instruction_suffix(str, optional): suffix for instruction file; defaults to ".instruction".
            enable_delayed_authentication (bool): If True, release plaintext before GCM tag verification.

        Returns:
            BufferedDecryptingStream: A stream that decrypts data lazily on first read.
        """
        # Convert the metadata dictionary to an ObjectMetadata instance
        streaming_body = response.get("Body")
        encryption_metadata = response.get("Metadata", {})
        metadata = ObjectMetadata.from_dict(encryption_metadata)

        # Use empty dict if encryption_context is None
        if encryption_context is None:
            encryption_context = {}

        # Check if we need to fetch instruction file
        if metadata.should_use_instruction_file():

            if self.s3_client is None:
                raise S3EncryptionClientError("s3_client required to fetch instruction file")
            if bucket is None or key is None:
                raise S3EncryptionClientError("Bucket and key required to fetch instruction file")

            instruction_key = key + instruction_suffix
            instruction_metadata = fetch_instruction_file(self.s3_client, bucket, instruction_key)
            instruction_metadata.update(encryption_metadata)
            metadata = ObjectMetadata.from_dict(instruction_metadata)
            ##= specification/s3-encryption/data-format/metadata-strategy.md#v1-v2-instruction-files
            ##= type=implementation
            ##% In the V1/V2 message format, all of the content metadata
            ##% MUST be stored in the Instruction File.
            if metadata.is_v1_format() or metadata.is_v2_format():
                object_metadata = ObjectMetadata.from_dict(encryption_metadata)
                if not (
                    object_metadata.content_cipher is None
                    and object_metadata.content_iv is None
                    and object_metadata.encrypted_data_key_algorithm is None
                ):
                    raise S3EncryptionClientError(
                        "Content metadata found in object metadata for V1 or V2 message format "
                        "BUT Instruction File is being used. This is an illegal combination. "
                        f"bucket: {bucket}\n key:{key}\n instruction_file:{instruction_key}"
                    )
        # Determine which format we're dealing with and get decryption materials
        if metadata.is_v1_format():
            dec_materials = self._decrypt_v1(metadata, encryption_context)
        elif metadata.is_v2_format():
            dec_materials = self._decrypt_v2(metadata, encryption_context)
        elif metadata.is_v3_format():
            dec_materials = self._decrypt_v3(metadata, encryption_context)
        else:
            raise S3EncryptionClientError(
                "Unable to determine S3 Encryption Client message format."
            )

        ##= specification/s3-encryption/decryption.md#cbc-decryption
        ##= type=TODO
        ##% If an object is encrypted with ALG_AES_256_CBC_IV16_NO_KDF and
        ##% [legacy unauthenticated algorithm suites](#legacy-decryption) is NOT enabled,
        ##% the S3EC MUST throw an error which details that client was
        ##% not configured to decrypt objects with ALG_AES_256_CBC_IV16_NO_KDF.

        # Return a buffered decrypting stream — no plaintext is released
        # until the entire ciphertext is read and the GCM tag is verified.
        ##= specification/s3-encryption/client.md#enable-delayed-authentication
        ##= type=implementation
        ##% When disabled the S3EC MUST NOT release plaintext from a stream which has not been authenticated.
        if enable_delayed_authentication is None:
            raise S3EncryptionClientError("enable_delayed_authentication must be explicitly set")
        if enable_delayed_authentication:
            return DelayedAuthDecryptingStream(
                streaming_body, dec_materials.plaintext_data_key, dec_materials.iv
            )
        return BufferedDecryptingStream(
            streaming_body, dec_materials.plaintext_data_key, dec_materials.iv
        )

    def _decrypt_v2(self, metadata, encryption_context) -> DecryptionMaterials:
        """Prepare V2 decryption materials."""
        iv_bytes = base64.b64decode(metadata.content_iv)
        edk_bytes = base64.b64decode(metadata.encrypted_data_key_v2)

        encrypted_data_key = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info=metadata.encrypted_data_key_algorithm,
            encrypted_data_key=edk_bytes,
        )

        dec_materials = DecryptionMaterials(
            iv=iv_bytes,
            encrypted_data_keys=[encrypted_data_key],
            encryption_context_stored=metadata.encrypted_data_key_context or {},
            encryption_context_from_request=encryption_context,
        )

        return self.cmm.decrypt_materials(dec_materials)

    def _decrypt_v1(self, metadata, encryption_context) -> DecryptionMaterials:
        """Prepare V1 decryption materials."""
        iv_bytes = base64.b64decode(metadata.content_iv)
        edk_bytes = base64.b64decode(metadata.encrypted_data_key_v1)

        encrypted_data_key = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info=metadata.encrypted_data_key_algorithm,
            encrypted_data_key=edk_bytes,
        )

        dec_materials = DecryptionMaterials(
            iv=iv_bytes,
            encrypted_data_keys=[encrypted_data_key],
            encryption_context_stored=metadata.encrypted_data_key_context or {},
            encryption_context_from_request=encryption_context,
        )

        return self.cmm.decrypt_materials(dec_materials)

    def _decrypt_v3(self, metadata, encryption_context) -> DecryptionMaterials:
        """Prepare V3 decryption materials."""
        # TODO: Implement V3 decryption
        raise NotImplementedError("V3 decryption not yet implemented")
