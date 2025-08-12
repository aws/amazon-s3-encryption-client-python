# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Materials module for S3 Encryption Client.

This module provides classes for encryption and decryption materials,
which contain the cryptographic materials needed for S3 object encryption
and decryption operations.
"""
from typing import Any

from attrs import define, field

from .encrypted_data_key import EncryptedDataKey


@define
class EncryptionMaterials:
    """Class representing encryption materials for S3 encryption.

    This class provides a structured way to handle encryption materials
    with fields corresponding to the data needed for encryption operations.

    Attributes:
        encryption_context (Dict[str, str]): Context information for encryption
        encrypted_data_key (Optional[EncryptedDataKey]): The encrypted data key
        plaintext_data_key (Optional[bytes]): The plaintext data key
    """

    encryption_context: dict[str, str] = field(factory=dict)
    encrypted_data_key: EncryptedDataKey | None = field(default=None)
    plaintext_data_key: bytes | None = field(default=None)

    @classmethod
    def from_dict(cls, materials_dict: dict[str, Any]) -> "EncryptionMaterials":
        """Create an EncryptionMaterials instance from a dictionary.

        Args:
            materials_dict (Dict[str, Any]): Dictionary containing encryption materials

        Returns:
            EncryptionMaterials: A new instance with fields populated from the dictionary
        """
        return cls(
            encryption_context=materials_dict.get("encryption_context", {}),
            encrypted_data_key=materials_dict.get("encrypted_data_key"),
            plaintext_data_key=materials_dict.get("plaintext_data_key"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert the EncryptionMaterials instance to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary containing encryption materials
        """
        result = {}

        if self.encryption_context:
            result["encryption_context"] = self.encryption_context

        if self.encrypted_data_key is not None:
            result["encrypted_data_key"] = self.encrypted_data_key

        if self.plaintext_data_key is not None:
            result["plaintext_data_key"] = self.plaintext_data_key

        return result


@define
class DecryptionMaterials:
    """Class representing decryption materials for S3 encryption.

    This class provides a structured way to handle decryption materials
    with fields corresponding to the data needed for decryption operations.

    Attributes:
        iv (Optional[bytes]): The initialization vector used for content encryption
        encrypted_data_keys (List[EncryptedDataKey]): List of encrypted data keys to try
        encryption_context_stored (Dict[str, str]): Encryption context stored with the object
        encryption_context_from_request (Dict[str, str]): Encryption context provided in the request
        plaintext_data_key (Optional[bytes]): The plaintext data key
    """

    iv: bytes | None = field(default=None)
    encrypted_data_keys: list[EncryptedDataKey] = field(factory=list)
    encryption_context_stored: dict[str, str] = field(factory=dict)
    encryption_context_from_request: dict[str, str] = field(factory=dict)
    plaintext_data_key: bytes | None = field(default=None)

    @classmethod
    def from_dict(cls, materials_dict: dict[str, Any]) -> "DecryptionMaterials":
        """Create a DecryptionMaterials instance from a dictionary.

        Args:
            materials_dict (Dict[str, Any]): Dictionary containing decryption materials

        Returns:
            DecryptionMaterials: A new instance with fields populated from the dictionary
        """
        return cls(
            iv=materials_dict.get("iv"),
            encrypted_data_keys=materials_dict.get("encrypted_data_keys", []),
            encryption_context_stored=materials_dict.get("encryption_context_stored", {}),
            encryption_context_from_request=materials_dict.get(
                "encryption_context_from_request", {}
            ),
            plaintext_data_key=materials_dict.get("plaintext_data_key"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert the DecryptionMaterials instance to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary containing decryption materials
        """
        result = {}

        if self.iv is not None:
            result["iv"] = self.iv

        if self.encrypted_data_keys:
            result["encrypted_data_keys"] = self.encrypted_data_keys

        if self.encryption_context_stored:
            result["encryption_context_stored"] = self.encryption_context_stored

        if self.encryption_context_from_request:
            result["encryption_context_from_request"] = self.encryption_context_from_request

        if self.plaintext_data_key is not None:
            result["plaintext_data_key"] = self.plaintext_data_key

        return result
