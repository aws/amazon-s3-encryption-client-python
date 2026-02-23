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



##= specification/s3-encryption/materials/keyrings.md#interface
##= type=implication
##% The Keyring interface and its operations SHOULD adhere to the naming conventions of the implementation language.
##= specification/s3-encryption/materials/keyrings.md#supported-keyrings
##= type=implication
##% Note: A user MAY create their own custom keyring(s).
@define
class AbstractKeyring(abc.ABC):
    """Abstract base class for keyrings.

    A keyring is responsible for encrypting and decrypting data keys.
    Concrete implementations handle specific key providers like KMS.
    """

    ##= specification/s3-encryption/materials/keyrings.md#interface
    ##= type=implication
    ##% The Keyring interface MUST include the OnEncrypt operation.
    ##% The OnEncrypt operation MUST accept an instance of EncryptionMaterials as input.
    ##% The OnEncrypt operation MUST return an instance of EncryptionMaterials as output.
    @abc.abstractmethod
    def on_encrypt(self, enc_materials) -> 'EncryptionMaterials':
        """Process encryption materials.

        Args:
            enc_materials (EncryptionMaterials or dict): Encryption materials to process

        Returns:
            EncryptionMaterials: The processed encryption materials
        """
        pass

    ##= specification/s3-encryption/materials/keyrings.md#interface
    ##= type=implication
    ##% The Keyring interface MUST include the OnDecrypt operation.
    ##% The OnDecrypt operation MUST accept an instance of DecryptionMaterials and a collection of EncryptedDataKey instances as input.
    ##% The OnDecrypt operation MUST return an instance of DecryptionMaterials as output.
    @abc.abstractmethod
    def on_decrypt(self, dec_materials, encrypted_data_keys=None) -> 'DecryptionMaterials':
        """Decrypt one of the encrypted data keys and update dec_materials.

        Args:
            dec_materials (DecryptionMaterials): A DecryptionMaterials instance containing
                decryption materials
            encrypted_data_keys (List[EncryptedDataKey], optional): A list of encrypted data
                keys to try.

        Returns:
            DecryptionMaterials: The updated dec_materials with the plaintext data key
        """
        pass


##= specification/s3-encryption/materials/s3-keyring.md#overview
##= type=implication
##% The S3EC SHOULD implement an S3 Keyring to consolidate validation and other functionality common to all S3 Keyrings.
##% If implemented, the S3 Keyring MUST implement the Keyring interface.
@define
class S3Keyring(AbstractKeyring):
    """Abstract class for S3EC keyrings that provides common validation logic."""

    ##= specification/s3-encryption/materials/s3-keyring.md#overview
    ##= type=implication
    ##% If implemented, the S3 Keyring MUST NOT be able to be instantiated as a Keyring instance.
    @abc.abstractmethod
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

    ##= specification/s3-encryption/materials/s3-keyring.md#overview
    ##= type=implication
    ##% If implemented, the S3 Keyring MUST NOT be able to be instantiated as a Keyring instance.
    @abc.abstractmethod
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
        # TODO: This can probably be cleaned up, consult Java
        edks = (
            encrypted_data_keys
            if encrypted_data_keys is not None
            else dec_materials.encrypted_data_keys
        )

        if edks is None:
            raise S3EncryptionClientError("No EncryptedDataKey provided on decrypt!")

        ##= specification/s3-encryption/materials/s3-keyring.md#ondecrypt
        ##= type=implication
        ##% If the input DecryptionMaterials contains a Plaintext Data Key, the S3 Keyring MUST throw an exception.
        if dec_materials.plaintext_data_key is not None:
            raise S3EncryptionClientError("Decryption materials already contains a plaintext data key.")

        ##= specification/s3-encryption/materials/s3-keyring.md#ondecrypt
        ##= type=implication
        ##% If the input collection of EncryptedDataKey instances contains any number of EDKs other than 1, the S3 Keyring MUST throw an exception.
        if len(edks) != 1:
            raise S3EncryptionClientError(f"Only one encrypted data key is supported, found: {len(edks)}")

        # Ensure encryption contexts are dictionaries
        if not isinstance(dec_materials.encryption_context_from_request, dict):
            raise S3EncryptionClientError("Encryption context from request must be a dictionary")

        if not isinstance(dec_materials.encryption_context_stored, dict):
            raise S3EncryptionClientError("Stored encryption context must be a dictionary")

        return dec_materials
