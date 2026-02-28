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
from .key_derivation import (
    KC_GCM_IV,
    MESSAGE_ID_LENGTH,
    SUITE_ID_BYTES,
    derive_keys,
    verify_commitment,
)
from .materials.crypto_materials_manager import AbstractCryptoMaterialsManager
from .materials.encrypted_data_key import EncryptedDataKey
from .materials.materials import AlgorithmSuite, DecryptionMaterials, EncryptionMaterials
from .metadata import ObjectMetadata


@define
class PutEncryptedObjectPipeline:
    """Pipeline for encrypting objects before they are put into S3.

    This pipeline handles only the encryption process for S3 objects.
    The actual S3 API calls are handled by the S3EncryptionClient.
    """

    cmm: AbstractCryptoMaterialsManager = field()

    def encrypt(self, plaintext, encryption_context=None, algorithm_suite=None):
        """Encrypt the data before it is stored in S3.

        Args:
            plaintext (bytes or str): The data to be encrypted
            encryption_context (dict, optional): Additional context for encryption
            algorithm_suite (AlgorithmSuite, optional): Algorithm suite to use

        Returns:
            bytes: The encrypted data
            dict: Metadata about the encryption to be stored with the object
        """
        if algorithm_suite is None:
            algorithm_suite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF

        # Create encryption materials request with encryption context copy
        enc_mats_request = EncryptionMaterials(
            algorithm_suite=algorithm_suite,
            encryption_context={} if encryption_context is None else encryption_context.copy(),
        )

        # Get encryption materials from the crypto materials manager
        enc_mats = self.cmm.get_encryption_materials(enc_mats_request)

        if enc_mats.plaintext_data_key is None:
            raise RuntimeError("No plaintext data key found!")
        if enc_mats.encrypted_data_key is None:
            raise RuntimeError("No encrypted data key found!")

        edk_bytes = enc_mats.encrypted_data_key.encrypted_data_key

        if algorithm_suite == AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY:
            return self._encrypt_kc_gcm(plaintext, enc_mats, edk_bytes)
        else:
            return self._encrypt_gcm(plaintext, enc_mats, edk_bytes)

    def _encrypt_gcm(self, plaintext, enc_mats, edk_bytes):
        """Encrypt using ALG_AES_256_GCM_IV12_TAG16_NO_KDF (V2 format)."""
        ##= specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
        ##% The client MUST initialize the cipher, or call an AES-GCM encryption API,
        ##% with the plaintext data key, the generated IV, and the tag length defined
        ##% in the Algorithm Suite when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
        ##% The client MUST NOT provide any AAD when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
        iv = os.urandom(12)
        aesgcm = AESGCM(enc_mats.plaintext_data_key)
        encrypted_data = aesgcm.encrypt(nonce=iv, data=plaintext, associated_data=None)

        b64_iv = base64.b64encode(iv).decode("utf-8")
        b64_edk = base64.b64encode(edk_bytes).decode("utf-8")

        metadata = ObjectMetadata(
            encrypted_data_key_v2=b64_edk,
            encrypted_data_key_algorithm="kms+context",
            content_iv=b64_iv,
            content_cipher="AES/GCM/NoPadding",
            encrypted_data_key_context=enc_mats.encryption_context,
        )

        return encrypted_data, metadata.to_dict()

    def _encrypt_kc_gcm(self, plaintext, enc_mats, edk_bytes):
        """Encrypt using ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY (V3 format)."""
        ##= specification/s3-encryption/encryption.md#content-encryption
        ##% The client MUST generate an IV or Message ID using the length of the IV
        ##% or Message ID defined in the algorithm suite.
        message_id = os.urandom(MESSAGE_ID_LENGTH)

        ##= specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
        ##% The client MUST use HKDF to derive the key commitment value and the derived
        ##% encrypting key as described in [Key Derivation](key-derivation.md).
        derived_encryption_key, commit_key = derive_keys(enc_mats.plaintext_data_key, message_id)

        ##= specification/s3-encryption/key-derivation.md#hkdf-operation
        ##% When encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        ##% the IV used in the AES-GCM content encryption/decryption MUST consist entirely of bytes with the value 0x01.
        ##= specification/s3-encryption/key-derivation.md#hkdf-operation
        ##% The client MUST set the AAD to the Algorithm Suite ID represented as bytes.
        aesgcm = AESGCM(derived_encryption_key)
        encrypted_data = aesgcm.encrypt(
            nonce=KC_GCM_IV, data=plaintext, associated_data=SUITE_ID_BYTES
        )

        b64_edk = base64.b64encode(edk_bytes).decode("utf-8")
        b64_message_id = base64.b64encode(message_id).decode("utf-8")
        b64_commit_key = base64.b64encode(commit_key).decode("utf-8")

        # V3 metadata format
        # x-amz-c: content cipher identifier (compressed algorithm suite)
        # x-amz-w: wrapping algorithm identifier (12 = kms+context)
        # x-amz-3: encrypted data key
        # x-amz-i: message ID
        # x-amz-d: key commitment
        # x-amz-t: encryption context (for kms+context wrapping)
        metadata = ObjectMetadata(
            content_cipher_v3="115",
            encrypted_data_key_algorithm_v3="12",
            encrypted_data_key_v3=b64_edk,
            message_id_v3=b64_message_id,
            key_commitment_v3=b64_commit_key,
            encryption_context_v3=enc_mats.encryption_context if enc_mats.encryption_context else None,
        )

        return encrypted_data, metadata.to_dict()


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
        instruction_suffix=".instruction",
    ):
        """Decrypt the data after it is retrieved from S3.

        Args:
            response (dict): The response from S3 containing the encrypted data and metadata
            encryption_context (dict, optional): Additional context for decryption
            bucket (str, optional): S3 bucket name (required for instruction file)
            key (str, optional): S3 object key (required for instruction file)
            instruction_suffix(str, optional): suffix for instruction file; defaults to ".instruction".

        Returns:
            bytes: The decrypted data
        """
        # Convert the metadata dictionary to an ObjectMetadata instance
        # TODO: Stream + Buffered Decryption
        encrypted_data = response.get("Body").read()
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
            # TODO: this is not how this works 
            dec_materials = self._decrypt_v2(metadata, encryption_context)
            dec_materials.algorithm_suite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
        elif metadata.is_v3_format():
            dec_materials = self._decrypt_v3(metadata, encryption_context)
            dec_materials.algorithm_suite = AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
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

        # Perform decryption
        # TODO: include CBC here too
        match dec_materials.algorithm_suite:
            case AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                ##= specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
                ##% The client MUST NOT provide any AAD when encrypting with
                ##% ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
                aesgcm = AESGCM(dec_materials.plaintext_data_key)
                return aesgcm.decrypt(
                    nonce=dec_materials.iv, data=encrypted_data, associated_data=None
                )
            case AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY:
                return self._decrypt_kc_gcm_content(dec_materials, encrypted_data, metadata)
            case _:
                raise S3EncryptionClientError("Unknown algorithm suite!")

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

    ##= specification/s3-encryption/data-format/content-metadata.md#v3-only
    ##% The V3 format uses compression here such that each wrapping algorithm is represented by a two digit string.
    ##= specification/s3-encryption/data-format/content-metadata.md#v3-only
    ##% - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
    ##= specification/s3-encryption/data-format/content-metadata.md#v3-only
    ##% - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
    ##= specification/s3-encryption/data-format/content-metadata.md#v3-only
    ##% - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
    _V3_WRAP_ALG_MAP = {
        "02": "AES/GCM",
        "12": "kms+context",
        "22": "RSA-OAEP-SHA1",
    }

    # Wrapping algorithms that this client currently supports for decryption
    _SUPPORTED_WRAP_ALGS = {"kms+context", "kms"}

    def _decrypt_v3(self, metadata, encryption_context) -> DecryptionMaterials:
        """Prepare V3 decryption materials."""
        edk_bytes = base64.b64decode(metadata.encrypted_data_key_v3)

        # Map V3 compressed wrapping algorithm to canonical key_provider_info
        raw_wrap_alg = metadata.encrypted_data_key_algorithm_v3 or "12"
        wrap_alg = self._V3_WRAP_ALG_MAP.get(raw_wrap_alg, raw_wrap_alg)

        if wrap_alg not in self._SUPPORTED_WRAP_ALGS:
            raise S3EncryptionClientError(
                f"Unsupported wrapping algorithm: {wrap_alg}. "
                f"The S3 Encryption Client for Python currently supports: "
                f"{', '.join(sorted(self._SUPPORTED_WRAP_ALGS))}."
            )

        encrypted_data_key = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info=wrap_alg,
            encrypted_data_key=edk_bytes,
        )

        ##= specification/s3-encryption/data-format/content-metadata.md#v3-only
        ##% The Encryption Context value MUST be used for wrapping algorithm `kms+context` or `12`.
        ##= specification/s3-encryption/data-format/content-metadata.md#v3-only
        ##% The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
        # For kms+context, the stored context comes from x-amz-t (encryption_context_v3).
        # For AES/GCM and RSA-OAEP-SHA1, it comes from x-amz-m (mat_desc_v3).
        stored_context = {}
        if wrap_alg == "kms+context":
            raw_ctx = metadata.encryption_context_v3
        else:
            raw_ctx = metadata.mat_desc_v3

        if raw_ctx is not None:
            if isinstance(raw_ctx, dict):
                stored_context = raw_ctx
            elif isinstance(raw_ctx, str):
                import json

                stored_context = json.loads(raw_ctx)

        dec_materials = DecryptionMaterials(
            encrypted_data_keys=[encrypted_data_key],
            encryption_context_stored=stored_context,
            encryption_context_from_request=encryption_context,
        )

        return self.cmm.decrypt_materials(dec_materials)

    def _decrypt_kc_gcm_content(self, dec_materials, encrypted_data, metadata):
        """Decrypt content encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.

        Performs HKDF key derivation, key commitment verification, and AES-GCM decryption.
        """
        message_id = base64.b64decode(metadata.message_id_v3)
        stored_commitment = base64.b64decode(metadata.key_commitment_v3)

        ##= specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
        ##% The client MUST use HKDF to derive the key commitment value and the derived encrypting key as described in [Key Derivation](key-derivation.md).
        derived_encryption_key, derived_commitment = derive_keys(
            dec_materials.plaintext_data_key, message_id
        )

        ##= specification/s3-encryption/decryption.md#decrypting-with-commitment
        ##% When using an algorithm suite which supports key commitment, the client MUST verify the key commitment values match before deriving
        ##% the [derived encryption key](./key-derivation.md#hkdf-operation).
        verify_commitment(stored_commitment, derived_commitment)

        ##= specification/s3-encryption/key-derivation.md#hkdf-operation
        ##% When encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        ##% the IV used in the AES-GCM content encryption/decryption MUST consist entirely of bytes with the value 0x01.
        ##= specification/s3-encryption/key-derivation.md#hkdf-operation
        ##% The client MUST set the AAD to the Algorithm Suite ID represented as bytes.
        aesgcm = AESGCM(derived_encryption_key)
        return aesgcm.decrypt(
            nonce=KC_GCM_IV, data=encrypted_data, associated_data=SUITE_ID_BYTES
        )
