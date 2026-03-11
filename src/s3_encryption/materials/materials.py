# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Materials module for S3 Encryption Client.

This module provides classes for encryption and decryption materials,
which contain the cryptographic materials needed for S3 object encryption
and decryption operations.
"""

from enum import Enum
from typing import Any

from attrs import define, field

from .encrypted_data_key import EncryptedDataKey


class AlgorithmSuite(Enum):
    """Algorithm suites supported by the S3 Encryption Client.

    Each member consolidates all cryptographic parameters for a given suite,
    modeled after the Java reference implementation. The tuple values are:

        (id, is_legacy, data_key_algorithm, data_key_length_bits,
         cipher_name, cipher_block_size_bits, cipher_iv_length_bits,
         cipher_tag_length_bits, is_committing, commitment_length_bits,
         commitment_nonce_length_bits, kdf_hash_algorithm, suite_id_bytes)
    """

    ALG_AES_256_CBC_IV16_NO_KDF = (
        0x0070,  # id
        True,  # is_legacy
        "AES",  # data_key_algorithm
        256,  # data_key_length_bits
        "AES/CBC/PKCS5Padding",  # cipher_name
        128,  # cipher_block_size_bits
        128,  # cipher_iv_length_bits (16 bytes)
        0,  # cipher_tag_length_bits (CBC has no auth tag)
        False,  # is_committing
        0,  # commitment_length_bits
        0,  # commitment_nonce_length_bits
        None,  # kdf_hash_algorithm
        b"",  # suite_id_bytes
    )

    ALG_AES_256_GCM_IV12_TAG16_NO_KDF = (
        0x0072,  # id
        False,  # is_legacy
        "AES",  # data_key_algorithm
        256,  # data_key_length_bits
        "AES/GCM/NoPadding",  # cipher_name
        128,  # cipher_block_size_bits
        96,  # cipher_iv_length_bits (12 bytes)
        128,  # cipher_tag_length_bits (16 bytes)
        False,  # is_committing
        0,  # commitment_length_bits
        0,  # commitment_nonce_length_bits
        None,  # kdf_hash_algorithm
        b"",  # suite_id_bytes
    )

    ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY = (
        0x0073,  # id
        False,  # is_legacy
        "AES",  # data_key_algorithm
        256,  # data_key_length_bits
        "AES/GCM/HKDF/CommitKey",  # cipher_name
        128,  # cipher_block_size_bits
        96,  # cipher_iv_length_bits (12 bytes)
        128,  # cipher_tag_length_bits (16 bytes)
        True,  # is_committing
        224,  # commitment_length_bits (28 bytes)
        224,  # commitment_nonce_length_bits (28 bytes = message_id)
        "sha512",  # kdf_hash_algorithm
        b"\x00\x73",  # suite_id_bytes
    )

    def __init__(
        self,
        id: int,
        is_legacy: bool,
        data_key_algorithm: str,
        data_key_length_bits: int,
        cipher_name: str,
        cipher_block_size_bits: int,
        cipher_iv_length_bits: int,
        cipher_tag_length_bits: int,
        is_committing: bool,
        commitment_length_bits: int,
        commitment_nonce_length_bits: int,
        kdf_hash_algorithm: str | None,
        suite_id_bytes: bytes,
    ):
        self._id = id
        self._is_legacy = is_legacy
        self._data_key_algorithm = data_key_algorithm
        self._data_key_length_bits = data_key_length_bits
        self._cipher_name = cipher_name
        self._cipher_block_size_bits = cipher_block_size_bits
        self._cipher_iv_length_bits = cipher_iv_length_bits
        self._cipher_tag_length_bits = cipher_tag_length_bits
        self._is_committing = is_committing
        self._commitment_length_bits = commitment_length_bits
        self._commitment_nonce_length_bits = commitment_nonce_length_bits
        self._kdf_hash_algorithm = kdf_hash_algorithm
        self._suite_id_bytes = suite_id_bytes

    # --- Convenience properties ---

    @property
    def suite_id(self) -> int:
        return self._id

    @property
    def is_legacy(self) -> bool:
        """Return True if this algorithm suite is a legacy unauthenticated mode."""
        return self._is_legacy

    @property
    def supports_key_commitment(self) -> bool:
        """Return True if this algorithm suite supports key commitment."""
        return self._is_committing

    @property
    def data_key_length_bytes(self) -> int:
        return self._data_key_length_bits // 8

    @property
    def cipher_name(self) -> str:
        return self._cipher_name

    @property
    def cipher_iv_length_bytes(self) -> int:
        return self._cipher_iv_length_bits // 8

    @property
    def commitment_length_bytes(self) -> int:
        return self._commitment_length_bits // 8

    @property
    def commitment_nonce_length_bytes(self) -> int:
        """Length of the message ID / HKDF salt in bytes."""
        return self._commitment_nonce_length_bits // 8

    @property
    def suite_id_bytes(self) -> bytes:
        return self._suite_id_bytes

    @property
    def kdf_hash_algorithm(self) -> str | None:
        """Hash algorithm name for HKDF, usable with hmac (e.g. 'sha512')."""
        return self._kdf_hash_algorithm

    @property
    def kc_gcm_iv(self) -> bytes:
        """Fixed IV for key-committing GCM: all 0x01 bytes of cipher_iv_length."""
        if not self._is_committing:
            raise ValueError(f"{self.name} does not support key commitment")
        return b"\x01" * self.cipher_iv_length_bytes


class CommitmentPolicy(Enum):
    """Commitment policies controlling key-commitment behavior."""

    FORBID_ENCRYPT_ALLOW_DECRYPT = "ForbidEncryptAllowDecrypt"
    REQUIRE_ENCRYPT_ALLOW_DECRYPT = "RequireEncryptAllowDecrypt"
    REQUIRE_ENCRYPT_REQUIRE_DECRYPT = "RequireEncryptRequireDecrypt"


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

    algorithm_suite: AlgorithmSuite = field(
        default=AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
    )
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
    algorithm_suite: AlgorithmSuite | None = field(default=None)

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
