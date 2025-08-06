# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from attrs import define
from .keyring import AbstractKeyring
from .materials import EncryptionMaterials
from typing import List, Dict, Any

# API Stub for CMM
class AbstractCryptoMaterialsManager():
    def getEncryptionMaterials(self, encMatsRequest):
        """
        Get encryption materials from the keyring.
        
        Args:
            encMatsRequest (Dict[str, Any] or EncryptionMaterials): Request containing encryption parameters
                
        Returns:
            EncryptionMaterials: The encryption materials
        """
        raise NotImplementedError
        
    def decryptMaterials(self, decMatsRequest):
        """
        Decrypt materials using the keyring.
        
        Args:
            decMatsRequest (Dict[str, Any]): Request containing decryption parameters
                
        Returns:
            Dict[str, Any]: The decryption materials
        """
        raise NotImplementedError

@define
class DefaultCryptoMaterialsManager(AbstractCryptoMaterialsManager):
    keyring: AbstractKeyring

    def getEncryptionMaterials(self, encMatsRequest):
        """
        Get encryption materials from the keyring.
        
        Args:
            encMatsRequest (Dict[str, Any]): Request containing encryption parameters
                
        Returns:
            EncryptionMaterials: The encryption materials
        """
        # Convert dictionary to EncryptionMaterials if needed
        if isinstance(encMatsRequest, dict):
            materials = EncryptionMaterials(
                encryption_context=encMatsRequest.get('encryption_context', {})
            )
        else:
            materials = encMatsRequest
            
        return self.keyring.onEncrypt(materials)
    
    def decryptMaterials(self, decMatsRequest):
        # TODO: Fill with defaults + stuff from decMatsRequest
        materials = {**decMatsRequest}
        encrypted_data_keys = decMatsRequest.get('encrypted_data_keys')
        return self.keyring.onDecrypt(materials, encrypted_data_keys)
