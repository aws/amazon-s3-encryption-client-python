# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from attrs import define, field


@define
class EncryptedDataKey:
    """
    Class representing an encrypted data key.

    An encrypted data key contains information about the key provider
    and the encrypted data key itself.

    Attributes:
        key_provider_info (str): Information about the key provider
        key_provider_id (bytes): Identifier for the key provider
        encrypted_data_key (bytes): The encrypted data key
    """

    key_provider_info: str = field()
    key_provider_id: bytes = field()
    encrypted_data_key: bytes = field()
