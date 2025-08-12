# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Keyring module for S3 Encryption Client.

This module provides interfaces and implementations for keyrings, which are
responsible for encrypting and decrypting data keys used in the S3 encryption process.
"""

import abc

from attrs import define

from ..exceptions import S3EncryptionClientError
from .materials import DecryptionMaterials, EncryptionMaterials


@define
class AbstractKeyring(abc.ABC):
    """Abstract base class for keyrings.

    A keyring is responsible for encrypting and decrypting data keys.
    Concrete implementations handle specific key providers like KMS.
    """

    @abc.abstractmethod
    def on_encrypt(self, enc_materials):
        """Process encryption materials.

        Args:
            enc_materials (EncryptionMaterials or dict): Encryption materials to process

        Returns:
            EncryptionMaterials: The processed encryption materials
        """
        pass

    @abc.abstractmethod
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
        pass


@define
class S3Keyring(AbstractKeyring):
    """Base class for S3 encryption keyrings that provides common validation logic."""

    def on_encrypt(self, enc_materials):
        """Validate encryption materials before encryption.

        Args:
            enc_materials (EncryptionMaterials or dict): Encryption materials

        Returns:
            EncryptionMaterials: The validated encryption materials
        """
        # Convert dict to EncryptionMaterials if needed
        if isinstance(enc_materials, dict):
            enc_materials = EncryptionMaterials.from_dict(enc_materials)

        # Validate encryption materials
        if not isinstance(enc_materials, EncryptionMaterials):
            raise S3EncryptionClientError(
                "Encryption materials must be an EncryptionMaterials instance or a dictionary"
            )

        # Ensure encryption_context is a dictionary
        if not isinstance(enc_materials.encryption_context, dict):
            raise S3EncryptionClientError("Encryption context must be a dictionary")

        return enc_materials

    def on_decrypt(self, dec_materials, encrypted_data_keys=None):
        """Validate decryption materials before decryption.

        Args:
            dec_materials (DecryptionMaterials): A DecryptionMaterials instance containing
                decryption materials
            encrypted_data_keys (List[EncryptedDataKey], optional): A list of encrypted data
                keys to try.

        Returns:
            DecryptionMaterials: The validated decryption materials
        """
        # Validate decryption materials
        if not isinstance(dec_materials, DecryptionMaterials):
            raise S3EncryptionClientError(
                "Decryption materials must be a DecryptionMaterials instance"
            )

        # Use encrypted_data_keys from parameters if provided, otherwise use from dec_materials
        edks = (
            encrypted_data_keys
            if encrypted_data_keys is not None
            else dec_materials.encrypted_data_keys
        )

        # Validate encrypted_data_keys
        if edks is None or len(edks) == 0:
            raise S3EncryptionClientError("No encrypted data keys provided")

        # Ensure encryption contexts are dictionaries
        if not isinstance(dec_materials.encryption_context_from_request, dict):
            raise S3EncryptionClientError("Encryption context from request must be a dictionary")

        if not isinstance(dec_materials.encryption_context_stored, dict):
            raise S3EncryptionClientError("Stored encryption context must be a dictionary")

        return dec_materials
