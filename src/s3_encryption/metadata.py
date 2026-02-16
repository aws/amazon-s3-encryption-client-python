# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Metadata handling for S3 Encryption Client.

This module provides classes and utilities for managing encryption metadata
for S3 objects, including serialization and deserialization of metadata.
"""

import json
from typing import Any

from attrs import define, field


@define
class ObjectMetadata:
    """Class representing metadata for encrypted S3 objects.

    This class provides a structured way to handle encryption metadata
    with fields corresponding to standard S3 encryption headers.

    All fields are optional and correspond to the following S3 encryption headers:
    - encrypted_data_key_v1: The encrypted data key (legacy format)
    - encrypted_data_key_v2: The encrypted data key (current format)
    - encrypted_data_key_algorithm: The algorithm used to encrypt the data key
      (e.g. AES/GCM or kms+context)
    - encrypted_data_key_context: The encryption context used for the data key
    - content_iv: The initialization vector used for content encryption
    - content_cipher: The cipher algorithm used for content encryption (e.g. AES/GCM/NoPadding)
    - content_cipher_tag_length: The length of the authentication tag
    - instruction_file: Marker for instruction files
    """

    # The encrypted data key (legacy format)
    encrypted_data_key_v1: str | None = field(default=None)
    # The encrypted data key (current format)
    encrypted_data_key_v2: str | None = field(default=None)
    # The algorithm used to encrypt the data key (e.g. AES/GCM or kms+context)
    encrypted_data_key_algorithm: str | None = field(default=None)
    # The encryption context used for the data key
    encrypted_data_key_context: dict | None = field(default=None)
    # The initialization vector used for content encryption
    content_iv: str | None = field(default=None)
    # The cipher algorithm used for content encryption (e.g. AES/GCM/NoPadding)
    content_cipher: str | None = field(default=None)
    # The length of the authentication tag
    content_cipher_tag_length: str | None = field(default="128")
    # Marker for instruction files
    instruction_file: str | None = field(default=None)
    
    # V3 format fields (compressed)
    content_cipher_v3: str | None = field(default=None)
    encrypted_data_key_v3: str | None = field(default=None)
    mat_desc_v3: str | None = field(default=None)
    encryption_context_v3: str | None = field(default=None)
    encrypted_data_key_algorithm_v3: str | None = field(default=None)
    key_commitment_v3: str | None = field(default=None)
    message_id_v3: str | None = field(default=None)

    # Constants for metadata keys
    ENCRYPTED_DATA_KEY_V1 = "x-amz-key"
    ENCRYPTED_DATA_KEY_V2 = "x-amz-key-v2"
    ENCRYPTED_DATA_KEY_ALGORITHM = "x-amz-wrap-alg"
    ENCRYPTED_DATA_KEY_CONTEXT = "x-amz-matdesc"
    CONTENT_IV = "x-amz-iv"
    CONTENT_CIPHER = "x-amz-cek-alg"
    CONTENT_CIPHER_TAG_LENGTH = "x-amz-tag-len"
    INSTRUCTION_FILE = "x-amz-crypto-instr-file"
    
    # V3 format constants (compressed)
    CONTENT_CIPHER_V3 = "x-amz-c"
    ENCRYPTED_DATA_KEY_V3 = "x-amz-3"
    MAT_DESC_V3 = "x-amz-m"
    ENCRYPTION_CONTEXT_V3 = "x-amz-t"
    ENCRYPTED_DATA_KEY_ALGORITHM_V3 = "x-amz-w"
    KEY_COMMITMENT_V3 = "x-amz-d"
    MESSAGE_ID_V3 = "x-amz-i"

    @classmethod
    def from_dict(cls, metadata_dict: dict[str, Any]) -> "ObjectMetadata":
        """Create an ObjectMetadata instance from a dictionary.

        Args:
            metadata_dict (Dict[str, Any]): Dictionary containing metadata keys and values

        Returns:
            ObjectMetadata: A new instance with fields populated from the dictionary
        """
        # Parse the encryption context if present
        encryption_context = None
        if cls.ENCRYPTED_DATA_KEY_CONTEXT in metadata_dict:
            context_str = metadata_dict.get(cls.ENCRYPTED_DATA_KEY_CONTEXT)
            if context_str is not None:
                encryption_context = json.loads(context_str)

        return cls(
            encrypted_data_key_v1=metadata_dict.get(cls.ENCRYPTED_DATA_KEY_V1),
            encrypted_data_key_v2=metadata_dict.get(cls.ENCRYPTED_DATA_KEY_V2),
            encrypted_data_key_algorithm=metadata_dict.get(cls.ENCRYPTED_DATA_KEY_ALGORITHM),
            encrypted_data_key_context=encryption_context,
            content_iv=metadata_dict.get(cls.CONTENT_IV),
            content_cipher=metadata_dict.get(cls.CONTENT_CIPHER),
            content_cipher_tag_length=metadata_dict.get(cls.CONTENT_CIPHER_TAG_LENGTH),
            instruction_file=metadata_dict.get(cls.INSTRUCTION_FILE),
            content_cipher_v3=metadata_dict.get(cls.CONTENT_CIPHER_V3),
            encrypted_data_key_v3=metadata_dict.get(cls.ENCRYPTED_DATA_KEY_V3),
            mat_desc_v3=metadata_dict.get(cls.MAT_DESC_V3),
            encryption_context_v3=metadata_dict.get(cls.ENCRYPTION_CONTEXT_V3),
            encrypted_data_key_algorithm_v3=metadata_dict.get(cls.ENCRYPTED_DATA_KEY_ALGORITHM_V3),
            key_commitment_v3=metadata_dict.get(cls.KEY_COMMITMENT_V3),
            message_id_v3=metadata_dict.get(cls.MESSAGE_ID_V3),
        )

    def to_dict(self) -> dict[str, str]:
        """Convert the ObjectMetadata instance to a dictionary.

        Returns:
            Dict[str, str]: Dictionary containing non-None metadata values
        """
        result = {}

        if self.encrypted_data_key_v1 is not None:
            result[self.ENCRYPTED_DATA_KEY_V1] = self.encrypted_data_key_v1

        if self.encrypted_data_key_v2 is not None:
            result[self.ENCRYPTED_DATA_KEY_V2] = self.encrypted_data_key_v2

        if self.encrypted_data_key_algorithm is not None:
            result[self.ENCRYPTED_DATA_KEY_ALGORITHM] = self.encrypted_data_key_algorithm

        if self.encrypted_data_key_context is not None:
            result[self.ENCRYPTED_DATA_KEY_CONTEXT] = json.dumps(self.encrypted_data_key_context)

        if self.content_iv is not None:
            result[self.CONTENT_IV] = self.content_iv

        if self.content_cipher is not None:
            result[self.CONTENT_CIPHER] = self.content_cipher

        if self.content_cipher_tag_length is not None:
            result[self.CONTENT_CIPHER_TAG_LENGTH] = self.content_cipher_tag_length

        if self.instruction_file is not None:
            result[self.INSTRUCTION_FILE] = self.instruction_file

        if self.content_cipher_v3 is not None:
            result[self.CONTENT_CIPHER_V3] = self.content_cipher_v3

        if self.encrypted_data_key_v3 is not None:
            result[self.ENCRYPTED_DATA_KEY_V3] = self.encrypted_data_key_v3

        if self.mat_desc_v3 is not None:
            result[self.MAT_DESC_V3] = self.mat_desc_v3

        if self.encryption_context_v3 is not None:
            result[self.ENCRYPTION_CONTEXT_V3] = self.encryption_context_v3

        if self.encrypted_data_key_algorithm_v3 is not None:
            result[self.ENCRYPTED_DATA_KEY_ALGORITHM_V3] = self.encrypted_data_key_algorithm_v3

        if self.key_commitment_v3 is not None:
            result[self.KEY_COMMITMENT_V3] = self.key_commitment_v3

        if self.message_id_v3 is not None:
            result[self.MESSAGE_ID_V3] = self.message_id_v3

        return result

    def is_v1_format(self) -> bool:
        """Check if metadata is in V1 format.

        Returns:
            bool: True if metadata contains V1 keys and excludes V2/V3 keys
        """
        return (
            self.content_iv is not None
            and self.encrypted_data_key_context is not None
            and self.encrypted_data_key_v1 is not None
            and self.encrypted_data_key_v2 is None
        )

    def is_v2_format(self) -> bool:
        """Check if metadata is in V2 format.

        Returns:
            bool: True if metadata contains V2 keys and excludes V1/V3 keys
        """
        return (
            self.content_cipher is not None
            and self.content_iv is not None
            and self.encrypted_data_key_algorithm is not None
            and self.encrypted_data_key_v2 is not None
            and self.encrypted_data_key_v1 is None
        )

    def is_v3_format(self) -> bool:
        """Check if metadata is in V3 format.

        Returns:
            bool: True if metadata contains V3 keys and excludes V1/V2 keys
        """
        return (
            self.content_cipher_v3 is not None
            and self.encrypted_data_key_algorithm_v3 is not None
            and self.key_commitment_v3 is not None
            and self.message_id_v3 is not None
            and self.encrypted_data_key_v3 is not None
            and self.encrypted_data_key_v2 is None
            and self.encrypted_data_key_v1 is None
        )

    def has_exclusive_key_collision(self) -> bool:
        """Check if metadata has multiple exclusive version keys.

        Returns:
            bool: True if more than one version key (V1, V2, V3) is present
        """
        has_v1_key = self.encrypted_data_key_v1 is not None
        has_v2_key = self.encrypted_data_key_v2 is not None
        has_v3_key = self.encrypted_data_key_v3 is not None
        
        exclusive_key_count = sum([has_v1_key, has_v2_key, has_v3_key])
        return exclusive_key_count > 1
