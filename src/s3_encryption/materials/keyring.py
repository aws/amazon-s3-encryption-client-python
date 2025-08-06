# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from attrs import define, field
from ..exceptions import S3EncryptionClientError
from .materials import EncryptionMaterials, DecryptionMaterials
from typing import List, Optional

@define
class AbstractKeyring():
    # Ideally, all keyrings would inherit this field.
    # However, attrs doesn't allow us to set a default here, 
    # when inheriting keyrings have optional fields.
    # Even without a default it doesn't seem to play nice with attrs.
    #enableLegacyWrappingAlgorithms: bool = field(default=False)

    def onEncrypt(self, encMaterials):
        """
        Process encryption materials.
        
        Args:
            encMaterials (EncryptionMaterials): Encryption materials to process
                
        Returns:
            EncryptionMaterials: The processed encryption materials
        """
        raise NotImplementedError

    def onDecrypt(self, decMaterials, encrypted_data_keys=None):
        """
        Decrypt one of the encrypted data keys and update decMaterials.
        
        Args:
            decMaterials (DecryptionMaterials): A DecryptionMaterials instance containing decryption materials
            encrypted_data_keys (List[EncryptedDataKey], optional): A list of encrypted data keys to try.
                
        Returns:
            DecryptionMaterials: The updated decMaterials with the plaintext data key (PDK)
        """
        raise NotImplementedError


@define
class S3Keyring(AbstractKeyring):
    """
    Base class for S3 encryption keyrings that provides common validation logic.
    """
    # Ideally this would be set, but attrs doesn't play nice 
    # enable_legacy_wrapping_algorithms: bool = field(default=False)

    def onEncrypt(self, encMaterials):
        """
        Validate encryption materials before encryption.
        
        Args:
            encMaterials (EncryptionMaterials or dict): Encryption materials
                
        Returns:
            EncryptionMaterials: The validated encryption materials
        """
        # Convert dict to EncryptionMaterials if needed
        if isinstance(encMaterials, dict):
            encMaterials = EncryptionMaterials.from_dict(encMaterials)
        
        # Validate encryption materials
        if not isinstance(encMaterials, EncryptionMaterials):
            raise S3EncryptionClientError("Encryption materials must be an EncryptionMaterials instance or a dictionary")
        
        # Ensure encryption_context is a dictionary
        if not isinstance(encMaterials.encryption_context, dict):
            raise S3EncryptionClientError("Encryption context must be a dictionary")
            
        return encMaterials

    def onDecrypt(self, decMaterials, encrypted_data_keys=None):
        """
        Validate decryption materials before decryption.
        
        Args:
            decMaterials (DecryptionMaterials): A DecryptionMaterials instance containing decryption materials
            encrypted_data_keys (List[EncryptedDataKey], optional): A list of encrypted data keys to try.
                
        Returns:
            DecryptionMaterials: The validated decryption materials
        """
        # Validate decryption materials
        if not isinstance(decMaterials, DecryptionMaterials):
            raise S3EncryptionClientError("Decryption materials must be a DecryptionMaterials instance")
        
        # Use encrypted_data_keys from parameters if provided, otherwise use from decMaterials
        edks = encrypted_data_keys if encrypted_data_keys is not None else decMaterials.encrypted_data_keys
        
        # Validate encrypted_data_keys
        if edks is None or len(edks) == 0:
            raise S3EncryptionClientError("No encrypted data keys provided")
            
        # Ensure encryption contexts are dictionaries
        if not isinstance(decMaterials.encryption_context_from_request, dict):
            raise S3EncryptionClientError("Encryption context from request must be a dictionary")
            
        if not isinstance(decMaterials.encryption_context_stored, dict):
            raise S3EncryptionClientError("Stored encryption context must be a dictionary")
            
        return decMaterials
