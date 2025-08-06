# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from attrs import define, field
from typing import Optional, Dict, Any
from .encrypted_data_key import EncryptedDataKey

@define
class EncryptionMaterials:
    """
    Class representing encryption materials for S3 encryption.
    
    This class provides a structured way to handle encryption materials
    with fields corresponding to the data needed for encryption operations.
    
    Attributes:
        encryption_context (Dict[str, str]): Context information for encryption
        encrypted_data_key (Optional[EncryptedDataKey]): The encrypted data key
        plaintext_data_key (Optional[bytes]): The plaintext data key (PDK)
    """
    encryption_context: Dict[str, str] = field(factory=dict)
    encrypted_data_key: Optional[EncryptedDataKey] = field(default=None)
    plaintext_data_key: Optional[bytes] = field(default=None)
    
    @classmethod
    def from_dict(cls, materials_dict: Dict[str, Any]) -> 'EncryptionMaterials':
        """
        Create an EncryptionMaterials instance from a dictionary.
        
        Args:
            materials_dict (Dict[str, Any]): Dictionary containing encryption materials
            
        Returns:
            EncryptionMaterials: A new instance with fields populated from the dictionary
        """
        return cls(
            encryption_context=materials_dict.get('encryption_context', {}),
            encrypted_data_key=materials_dict.get('encrypted_data_key'),
            plaintext_data_key=materials_dict.get('PDK')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the EncryptionMaterials instance to a dictionary.
        
        Returns:
            Dict[str, Any]: Dictionary containing encryption materials
        """
        result = {}
        
        if self.encryption_context:
            result['encryption_context'] = self.encryption_context
            
        if self.encrypted_data_key is not None:
            result['encrypted_data_key'] = self.encrypted_data_key
            
        if self.plaintext_data_key is not None:
            result['PDK'] = self.plaintext_data_key
            
        return result
