# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Instruction file configuration for S3 Encryption Client.

This module provides configuration for instruction file behavior
during encryption and decryption operations.
"""

from attrs import define, field


@define
class InstructionFileConfig:
    """Configuration for instruction file behavior in the S3 Encryption Client.

    Controls whether the client will interact with instruction files
    as part of GetObject, DeleteObject, and DeleteObjects operations.

    Attributes:
        disable_get_object: If True, the client will not attempt to fetch
            instruction files during GetObject (decryption) and will raise
            an error if the object's metadata implies an instruction file
            is required. Defaults to False.
        disable_delete_object: If True, the client will not attempt to
            delete the associated instruction file during DeleteObject.
            Defaults to False.
        disable_delete_objects: If True, the client will not attempt to
            delete the associated instruction files during DeleteObjects.
            Defaults to False.
    """

    disable_get_object: bool = field(default=False)
    disable_delete_object: bool = field(default=False)
    disable_delete_objects: bool = field(default=False)
