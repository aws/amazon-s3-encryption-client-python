# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Materials package for S3 Encryption Client.

This package contains classes and interfaces for cryptographic materials
management, including keyrings, crypto materials managers, and encrypted data keys.
"""

from .crypto_materials_manager import AbstractCryptoMaterialsManager, DefaultCryptoMaterialsManager
from .encrypted_data_key import EncryptedDataKey
from .keyring import AbstractKeyring
from .kms_keyring import KmsKeyring
from .materials import AlgorithmSuite, CommitmentPolicy, EncryptionMaterials

__all__ = [
    "AbstractKeyring",
    "KmsKeyring",
    "AbstractCryptoMaterialsManager",
    "DefaultCryptoMaterialsManager",
    "EncryptedDataKey",
    "AlgorithmSuite",
    "CommitmentPolicy",
    "EncryptionMaterials",
]
