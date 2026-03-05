# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Encryption and decryption pipelines for S3 Encryption Client.

This module provides pipelines for encrypting objects before they are put into S3
and decrypting objects after they are retrieved from S3.
"""

import base64
import json
import os

from attrs import define, field
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

from .exceptions import S3EncryptionClientError, S3EncryptionClientSecurityError
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
from .materials.materials import (
    AlgorithmSuite,
    CommitmentPolicy,
    DecryptionMaterials,
    EncryptionMaterials,
)
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
            encryption_context_v3=(
                enc_mats.encryption_context if enc_mats.encryption_context else None
            ),
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
    commitment_policy: CommitmentPolicy = field(
        default=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    enable_legacy_unauthenticated_modes: bool = field(default=False)

    # Map content cipher metadata values to AlgorithmSuite
    _CONTENT_CIPHER_TO_ALGORITHM_SUITE = {
        "AES/CBC/PKCS5Padding": AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF,
        "AES/GCM/NoPadding": AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        "115": AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
    }

    def _determine_algorithm_suite(self, metadata) -> AlgorithmSuite:
        """Determine the algorithm suite from object metadata.

        V1 objects are always CBC.
        V2/V3 objects check x-amz-cek-alg / x-amz-c to determine the content algorithm.
        """
        if metadata.is_v1_format():
            ##= specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            ##= type=citation
            ##% Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
            return AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF

        if metadata.is_v2_format():
            cek_alg = metadata.content_cipher
            if cek_alg is None:
                raise S3EncryptionClientError(
                    "V2 format object missing required x-amz-cek-alg metadata."
                )
            suite = self._CONTENT_CIPHER_TO_ALGORITHM_SUITE.get(cek_alg)
            if suite is None:
                raise S3EncryptionClientError(f"Unknown content encryption algorithm: {cek_alg}")
            return suite

        if metadata.is_v3_format():
            cek_alg = metadata.content_cipher_v3
            if cek_alg is None:
                raise S3EncryptionClientError("V3 format object missing required x-amz-c metadata.")
            suite = self._CONTENT_CIPHER_TO_ALGORITHM_SUITE.get(cek_alg)
            if suite is None:
                raise S3EncryptionClientError(f"Unknown content encryption algorithm: {cek_alg}")
            return suite

        raise S3EncryptionClientError("Unable to determine S3 Encryption Client message format.")

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

            ##= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            ##= type=implementation
            ##% - The V3 message format MUST NOT store the mapkey "x-amz-c" and its value in the Instruction File.
            ##= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            ##= type=implementation
            ##% - The V3 message format MUST NOT store the mapkey "x-amz-d" and its value in the Instruction File.
            ##= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            ##= type=implementation
            ##% - The V3 message format MUST NOT store the mapkey "x-amz-i" and its value in the Instruction File.
            v3_object_metadata_exclusive_keys = {
                ObjectMetadata.CONTENT_CIPHER_V3,
                ObjectMetadata.KEY_COMMITMENT_V3,
                ObjectMetadata.MESSAGE_ID_V3,
            }
            forbidden_keys_in_instruction = set(instruction_metadata.keys()) & v3_object_metadata_exclusive_keys
            if forbidden_keys_in_instruction:
                raise S3EncryptionClientError(
                    "Instruction file is tampered, instruction file contains object metadata "
                    f"exclusive mapkeys: {forbidden_keys_in_instruction}. "
                    f"bucket: {bucket}\n key:{key}\n instruction_file:{instruction_key}"
                )

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

        # Determine the algorithm suite from the metadata
        algorithm_suite = self._determine_algorithm_suite(metadata)

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

        dec_materials.algorithm_suite = algorithm_suite

        ##= specification/s3-encryption/decryption.md#cbc-decryption
        ##% If an object is encrypted with ALG_AES_256_CBC_IV16_NO_KDF and
        ##% [legacy unauthenticated algorithm suites](#legacy-decryption) is NOT enabled,
        ##% the S3EC MUST throw an error which details that client was
        ##% not configured to decrypt objects with ALG_AES_256_CBC_IV16_NO_KDF.
        if algorithm_suite == AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF:
            ##= specification/s3-encryption/decryption.md#legacy-decryption
            ##% The S3EC MUST NOT decrypt objects encrypted using legacy unauthenticated algorithm suites
            ##% unless specifically configured to do so.
            ##= specification/s3-encryption/decryption.md#legacy-decryption
            ##% If the S3EC is not configured to enable legacy unauthenticated content decryption,
            ##% the client MUST throw an exception when attempting to decrypt an object encrypted
            ##% with a legacy unauthenticated algorithm suite.
            if not self.enable_legacy_unauthenticated_modes:
                raise S3EncryptionClientError(
                    "Cannot decrypt object encrypted with ALG_AES_256_CBC_IV16_NO_KDF. "
                    "The S3 Encryption Client is not configured to decrypt objects using "
                    "legacy unauthenticated algorithm suites. "
                    "Set enable_legacy_unauthenticated_modes=True to allow decryption "
                    "of objects encrypted with CBC."
                )

        ##= specification/s3-encryption/decryption.md#key-commitment
        ##% The S3EC MUST validate the algorithm suite used for decryption against the
        ##% key commitment policy before attempting to decrypt the content ciphertext.
        ##= specification/s3-encryption/decryption.md#key-commitment
        ##% If the commitment policy requires decryption using a committing algorithm suite,
        ##% and the algorithm suite associated with the object does not support key commitment,
        ##% then the S3EC MUST throw an exception.
        if (
            self.commitment_policy == CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
            and dec_materials.algorithm_suite
            != AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
        ):
            raise S3EncryptionClientError(
                "Configuration conflict: cannot decrypt non-key-committing object "
                "when commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT. "
                "Use REQUIRE_ENCRYPT_ALLOW_DECRYPT or FORBID_ENCRYPT_ALLOW_DECRYPT "
                "to allow decryption of non-committing objects."
            )

        # Perform decryption based on algorithm suite
        match dec_materials.algorithm_suite:
            case AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF:
                return self._decrypt_cbc_content(dec_materials, encrypted_data)
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
        return self._decrypt_v1_v2(
            iv_b64=metadata.content_iv,
            edk_b64=metadata.encrypted_data_key_v2,
            wrap_alg=metadata.encrypted_data_key_algorithm,
            stored_context=metadata.encrypted_data_key_context or {},
            encryption_context=encryption_context,
        )

    def _decrypt_v1(self, metadata, encryption_context) -> DecryptionMaterials:
        """Prepare V1 decryption materials."""
        return self._decrypt_v1_v2(
            iv_b64=metadata.content_iv,
            edk_b64=metadata.encrypted_data_key_v1,
            wrap_alg=metadata.encrypted_data_key_algorithm,
            stored_context=metadata.encrypted_data_key_context or {},
            encryption_context=encryption_context,
        )

    def _decrypt_v1_v2(
        self, iv_b64, edk_b64, wrap_alg, stored_context, encryption_context
    ) -> DecryptionMaterials:
        """Shared logic for preparing V1/V2 decryption materials."""
        iv_bytes = base64.b64decode(iv_b64)
        edk_bytes = base64.b64decode(edk_b64)

        encrypted_data_key = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info=wrap_alg,
            encrypted_data_key=edk_bytes,
        )

        dec_materials = DecryptionMaterials(
            iv=iv_bytes,
            encrypted_data_keys=[encrypted_data_key],
            encryption_context_stored=stored_context,
            encryption_context_from_request=encryption_context,
        )

        return self.cmm.decrypt_materials(dec_materials)

    def _decrypt_cbc_content(self, dec_materials, encrypted_data):
        """Decrypt content encrypted with ALG_AES_256_CBC_IV16_NO_KDF.

        ##= specification/s3-encryption/decryption.md#cbc-decryption
        ##% If an object is encrypted with ALG_AES_256_CBC_IV16_NO_KDF and
        ##% [legacy unauthenticated algorithm suites](#legacy-decryption) is enabled,
        ##% then the S3EC MUST create a cipher with AES in CBC Mode with PKCS5Padding or
        ##% PKCS7Padding compatible padding for a 16-byte block cipher
        ##% (example: for the Java JCE, this is "AES/CBC/PKCS5Padding").
        """
        ##= specification/s3-encryption/decryption.md#cbc-decryption
        ##% If the cipher object cannot be created as described above,
        ##% Decryption MUST fail.
        ##= specification/s3-encryption/decryption.md#cbc-decryption
        ##% The error SHOULD detail why the cipher could not be initialized
        ##% (such as CBC or PKCS5Padding is not supported by the underlying crypto provider).
        try:
            cipher = Cipher(
                algorithms.AES(dec_materials.plaintext_data_key),
                modes.CBC(dec_materials.iv),
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

            # Remove PKCS7 padding (compatible with PKCS5Padding for 16-byte block ciphers)
            unpadder = PKCS7(128).unpadder()
            return unpadder.update(padded_plaintext) + unpadder.finalize()
        except Exception as e:
            raise S3EncryptionClientSecurityError(
                f"Failed to decrypt CBC content: {e}. "
                "Ensure the underlying crypto provider supports AES/CBC/PKCS7Padding."
            ) from e

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

    def _decrypt_v3(self, metadata, encryption_context) -> DecryptionMaterials:
        """Prepare V3 decryption materials."""
        edk_bytes = base64.b64decode(metadata.encrypted_data_key_v3)

        # Map V3 compressed wrapping algorithm to canonical key_provider_info
        raw_wrap_alg = metadata.encrypted_data_key_algorithm_v3 or "12"
        wrap_alg = self._V3_WRAP_ALG_MAP.get(raw_wrap_alg, raw_wrap_alg)

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
        return aesgcm.decrypt(nonce=KC_GCM_IV, data=encrypted_data, associated_data=SUITE_ID_BYTES)
