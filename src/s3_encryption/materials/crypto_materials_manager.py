# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Crypto materials manager module for S3 Encryption Client.

This module provides interfaces and implementations for crypto materials managers,
which are responsible for coordinating the generation and use of cryptographic materials.
"""

import abc

from attrs import define

from .keyring import AbstractKeyring
from .materials import DecryptionMaterials, EncryptionMaterials


# API Stub for CMM
class AbstractCryptoMaterialsManager(abc.ABC):
    """Abstract base class for crypto materials managers.

    A crypto materials manager is responsible for generating encryption materials
    and processing decryption materials using a keyring.
    """

    @abc.abstractmethod
    def get_encryption_materials(self, enc_mats_request):
        """Get encryption materials from the keyring.

        Args:
            enc_mats_request (Dict[str, Any] or EncryptionMaterials): Request containing encryption
                parameters

        Returns:
            EncryptionMaterials: The encryption materials
        """
        pass

    @abc.abstractmethod
    def decrypt_materials(self, dec_mats_request):
        """Decrypt materials using the keyring.

        Args:
            dec_mats_request (Dict[str, Any] or DecryptionMaterials): Request containing decryption
                parameters

        Returns:
            DecryptionMaterials: The decryption materials
        """
        pass


@define
class DefaultCryptoMaterialsManager(AbstractCryptoMaterialsManager):
    """Default implementation of the crypto materials manager.

    This implementation delegates encryption and decryption operations to a single keyring.

    Attributes:
        keyring (AbstractKeyring): The keyring to use for cryptographic operations
    """

    keyring: AbstractKeyring

    def get_encryption_materials(self, enc_mats_request):
        """Get encryption materials from the keyring.

        Args:
            enc_mats_request (Dict[str, Any] or EncryptionMaterials): Request containing encryption
                parameters

        Returns:
            EncryptionMaterials: The encryption materials
        """
        # Convert dictionary to EncryptionMaterials if needed
        if isinstance(enc_mats_request, dict):
            materials = EncryptionMaterials(
                encryption_context=enc_mats_request.get("encryption_context", {})
            )
        else:
            materials = enc_mats_request

        return self.keyring.on_encrypt(materials)

    def decrypt_materials(self, dec_mats_request):
        """Decrypt materials using the keyring.

        Args:
            dec_mats_request (Dict[str, Any] or DecryptionMaterials): Request containing decryption
                parameters

        Returns:
            DecryptionMaterials: The decryption materials
        """
        # Convert dictionary to DecryptionMaterials if needed
        if isinstance(dec_mats_request, dict):
            materials = DecryptionMaterials.from_dict(dec_mats_request)
        else:
            materials = dec_mats_request

        encrypted_data_keys = materials.encrypted_data_keys
        return self.keyring.on_decrypt(materials, encrypted_data_keys)
