# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Raw AES keyring module for S3 Encryption Client.

This module provides a keyring implementation that wraps data keys using a
locally-held, caller-provided AES key ("bring your own key"), with no
dependency on a remote key management service such as AWS KMS.
"""

import os

from attrs import define, field
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..exceptions import S3EncryptionClientError
from .encrypted_data_key import EncryptedDataKey
from .keyring import S3Keyring

# Canonical wrapping-algorithm identifier for this keyring. This is the value
# stored in object metadata (x-amz-wrap-alg / V3 code "02") so that decrypt
# can recognize which keyring produced an EncryptedDataKey.
AES_WRAP_ALGORITHM = "AES/GCM"

# Reserved encryption-context key used to bind an EncryptedDataKey to the
# wrapping key that produced it, so decrypt can fail fast on a key mismatch
# instead of only failing during (or after) the AES-GCM unwrap.
RAW_AES_KEY_NAME_CONTEXT_KEY = "aws:x-amz-raw-aes-key-name"

_VALID_WRAPPING_KEY_LENGTHS = (16, 24, 32)
_NONCE_LENGTH_BYTES = 12


def _serialize_encryption_context(encryption_context: dict) -> bytes:
    """Serialize an encryption context into deterministic bytes for use as AAD.

    Args:
        encryption_context: The encryption context to serialize.

    Returns:
        bytes: A deterministic byte representation of the encryption context.
    """
    serialized = b""
    for key in sorted(encryption_context):
        value = encryption_context[key]
        serialized += key.encode("utf-8") + b"\x00" + value.encode("utf-8") + b"\x00"
    return serialized


@define
class RawAesKeyring(S3Keyring):
    """AES implementation of the S3 keyring for caller-supplied ("bring your own") keys.

    This keyring wraps and unwraps data keys locally using AES-GCM with a
    wrapping key supplied by the caller, rather than delegating to a remote
    key management service such as AWS KMS.

    Attributes:
        key_name (str): A caller-chosen identifier for the wrapping key. Stored
            in the encryption context / material description alongside the
            encrypted data key and validated on decrypt to ensure the correct
            wrapping key is used.
        wrapping_key (bytes): The raw AES wrapping key. Must be 16, 24, or 32
            bytes (AES-128, AES-192, or AES-256).
    """

    key_name: str = field()
    wrapping_key: bytes = field()

    @wrapping_key.validator
    def _check_wrapping_key(self, attribute, value):
        if (
            not isinstance(value, (bytes, bytearray))
            or len(value) not in _VALID_WRAPPING_KEY_LENGTHS
        ):
            raise S3EncryptionClientError(
                "RawAesKeyring wrapping_key must be 16, 24, or 32 bytes "
                f"(AES-128, AES-192, or AES-256), got "
                f"{len(value) if isinstance(value, (bytes, bytearray)) else type(value)}."
            )

    def on_encrypt(self, enc_materials):
        """Generate a plaintext data key and wrap it with the local AES wrapping key.

        Args:
            enc_materials (EncryptionMaterials or dict): Encryption materials to process

        Returns:
            EncryptionMaterials: The processed encryption materials with a locally
                wrapped data key
        """
        enc_materials = super().on_encrypt(enc_materials)

        encryption_context = enc_materials.encryption_context
        if RAW_AES_KEY_NAME_CONTEXT_KEY in encryption_context:
            raise S3EncryptionClientError(
                f"{RAW_AES_KEY_NAME_CONTEXT_KEY} is a reserved key for the S3 encryption client"
            )
        encryption_context[RAW_AES_KEY_NAME_CONTEXT_KEY] = self.key_name

        plaintext_data_key = os.urandom(enc_materials.encryption_algorithm.data_key_length_bytes)
        nonce = os.urandom(_NONCE_LENGTH_BYTES)
        aad = _serialize_encryption_context(encryption_context)

        aesgcm = AESGCM(self.wrapping_key)
        wrapped_key = aesgcm.encrypt(nonce, plaintext_data_key, aad)

        enc_materials.encrypted_data_key = EncryptedDataKey(
            key_provider_id=b"S3Keyring",
            key_provider_info=AES_WRAP_ALGORITHM,
            encrypted_data_key=nonce + wrapped_key,
        )
        enc_materials.plaintext_data_key = plaintext_data_key
        return enc_materials

    def on_decrypt(self, dec_materials, encrypted_data_keys=None):
        """Unwrap the encrypted data key using the local AES wrapping key.

        Args:
            dec_materials (DecryptionMaterials): A DecryptionMaterials instance containing
                decryption materials
            encrypted_data_keys (List[EncryptedDataKey], optional): A list of encrypted data
                keys to try.

        Returns:
            DecryptionMaterials: The updated dec_materials with the plaintext data key
        """
        dec_materials = super().on_decrypt(dec_materials, encrypted_data_keys)

        edks = (
            encrypted_data_keys
            if encrypted_data_keys is not None
            else dec_materials.encrypted_data_keys
        )
        edk = edks[0]

        if edk.key_provider_info != AES_WRAP_ALGORITHM:
            raise S3EncryptionClientError(
                f"{edk.key_provider_info} is not a valid key wrapping algorithm for RawAesKeyring!"
            )

        encryption_context_from_request = dec_materials.encryption_context_from_request
        encryption_context_stored = dec_materials.encryption_context_stored

        if RAW_AES_KEY_NAME_CONTEXT_KEY in encryption_context_from_request:
            raise S3EncryptionClientError(
                f"{RAW_AES_KEY_NAME_CONTEXT_KEY} is a reserved key for the S3 encryption client"
            )

        encryption_context_stored_copy = encryption_context_stored.copy()
        stored_key_name = encryption_context_stored_copy.pop(RAW_AES_KEY_NAME_CONTEXT_KEY, None)
        if stored_key_name != self.key_name:
            raise S3EncryptionClientError(
                f"Encrypted data key was wrapped with key_name={stored_key_name!r}, "
                f"but this RawAesKeyring is configured with key_name={self.key_name!r}."
            )

        if encryption_context_stored_copy != encryption_context_from_request:
            raise S3EncryptionClientError(
                "Provided encryption context does not match information retrieved from S3"
            )

        nonce = edk.encrypted_data_key[:_NONCE_LENGTH_BYTES]
        wrapped_key = edk.encrypted_data_key[_NONCE_LENGTH_BYTES:]
        aad = _serialize_encryption_context(dec_materials.encryption_context_stored)

        aesgcm = AESGCM(self.wrapping_key)
        try:
            dec_materials.plaintext_data_key = aesgcm.decrypt(nonce, wrapped_key, aad)
        except Exception as e:
            raise S3EncryptionClientError(
                f"Failed to unwrap data key with RawAesKeyring: {e}"
            ) from e

        return dec_materials
