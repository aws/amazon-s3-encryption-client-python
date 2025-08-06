# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
from attrs import define, field
from typing import Optional, Dict, Any


@define
class ObjectMetadata:
    """
    Class representing metadata for encrypted S3 objects.
    
    This class provides a structured way to handle encryption metadata
    with fields corresponding to standard S3 encryption headers.
    
    All fields are optional and correspond to the following S3 encryption headers:
    - encrypted_data_key_v1: The encrypted data key (legacy format)
    - encrypted_data_key_v2: The encrypted data key (current format)
    - encrypted_data_key_algorithm: The algorithm used to encrypt the data key (e.g. AES/GCM or kms+context)
    - encrypted_data_key_context: The encryption context used for the data key
    - content_iv: The initialization vector used for content encryption
    - content_cipher: The cipher algorithm used for content encryption (e.g. AES/GCM/NoPadding)
    - content_cipher_tag_length: The length of the authentication tag
    - instruction_file: Marker for instruction files
    """
    # The encrypted data key (legacy format)
    encrypted_data_key_v1: Optional[str] = field(default=None)
    # The encrypted data key (current format)
    encrypted_data_key_v2: Optional[str] = field(default=None)
    # The algorithm used to encrypt the data key (e.g. AES/GCM or kms+context)
    encrypted_data_key_algorithm: Optional[str] = field(default=None)
    # The encryption context used for the data key
    encrypted_data_key_context: Optional[dict] = field(default=None)
    # The initialization vector used for content encryption
    content_iv: Optional[str] = field(default=None)
    # The cipher algorithm used for content encryption (e.g. AES/GCM/NoPadding)
    content_cipher: Optional[str] = field(default=None)
    # The length of the authentication tag
    content_cipher_tag_length: Optional[str] = field(default="128")
    # Marker for instruction files
    instruction_file: Optional[str] = field(default=None)

    # Constants for metadata keys
    ENCRYPTED_DATA_KEY_V1 = "x-amz-key"
    ENCRYPTED_DATA_KEY_V2 = "x-amz-key-v2"
    ENCRYPTED_DATA_KEY_ALGORITHM = "x-amz-wrap-alg"
    ENCRYPTED_DATA_KEY_CONTEXT = "x-amz-matdesc"
    CONTENT_IV = "x-amz-iv"
    CONTENT_CIPHER = "x-amz-cek-alg"
    CONTENT_CIPHER_TAG_LENGTH = "x-amz-tag-len"
    INSTRUCTION_FILE = "x-amz-crypto-instr-file"

    @classmethod
    def from_dict(cls, metadata_dict: Dict[str, Any]) -> 'ObjectMetadata':
        """
        Create an ObjectMetadata instance from a dictionary.
        
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
            instruction_file=metadata_dict.get(cls.INSTRUCTION_FILE)
        )

    def to_dict(self) -> Dict[str, str]:
        """
        Convert the ObjectMetadata instance to a dictionary.
        
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
            
        return result
