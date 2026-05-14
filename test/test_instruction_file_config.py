# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for InstructionFileConfig and its integration with S3EncryptionClientConfig."""

import base64
import json
import os
from io import BytesIO
from unittest.mock import Mock

import pytest

from s3_encryption import S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.instruction_file_config import InstructionFileConfig
from s3_encryption.materials.crypto_materials_manager import DefaultCryptoMaterialsManager
from s3_encryption.materials.keyring import S3Keyring
from s3_encryption.materials.materials import CommitmentPolicy
from s3_encryption.pipelines import GetEncryptedObjectPipeline


class TestInstructionFileConfig:
    """Tests for the InstructionFileConfig attrs class."""

    def test_defaults_all_false(self):
        """All disable flags default to False."""
        config = InstructionFileConfig()
        assert config.disable_get_object is False
        assert config.disable_delete_object is False
        assert config.disable_delete_objects is False

    def test_disable_get_object(self):
        """disable_get_object can be set to True."""
        config = InstructionFileConfig(disable_get_object=True)
        assert config.disable_get_object is True
        assert config.disable_delete_object is False
        assert config.disable_delete_objects is False

    def test_disable_delete_object(self):
        """disable_delete_object can be set independently."""
        config = InstructionFileConfig(disable_delete_object=True)
        assert config.disable_get_object is False
        assert config.disable_delete_object is True
        assert config.disable_delete_objects is False

    def test_disable_delete_objects(self):
        """disable_delete_objects can be set independently."""
        config = InstructionFileConfig(disable_delete_objects=True)
        assert config.disable_get_object is False
        assert config.disable_delete_object is False
        assert config.disable_delete_objects is True

    def test_all_disabled(self):
        """All flags can be set to True simultaneously."""
        config = InstructionFileConfig(
            disable_get_object=True,
            disable_delete_object=True,
            disable_delete_objects=True,
        )
        assert config.disable_get_object is True
        assert config.disable_delete_object is True
        assert config.disable_delete_objects is True


class TestS3EncryptionClientConfigInstructionFileConfig:
    """Tests for instruction_file_config on S3EncryptionClientConfig."""

    def test_default_instruction_file_config(self):
        """S3EncryptionClientConfig defaults to InstructionFileConfig with all enabled."""
        mock_keyring = Mock(spec=S3Keyring)
        config = S3EncryptionClientConfig(keyring=mock_keyring)
        assert isinstance(config.instruction_file_config, InstructionFileConfig)
        assert config.instruction_file_config.disable_get_object is False

    def test_custom_instruction_file_config(self):
        """S3EncryptionClientConfig accepts a custom InstructionFileConfig."""
        mock_keyring = Mock(spec=S3Keyring)
        ifc = InstructionFileConfig(disable_get_object=True)
        config = S3EncryptionClientConfig(keyring=mock_keyring, instruction_file_config=ifc)
        assert config.instruction_file_config.disable_get_object is True

    def test_instruction_file_config_does_not_affect_other_config(self):
        """Setting instruction_file_config does not change other defaults."""
        mock_keyring = Mock(spec=S3Keyring)
        ifc = InstructionFileConfig(disable_get_object=True)
        config = S3EncryptionClientConfig(keyring=mock_keyring, instruction_file_config=ifc)
        assert config.enable_delayed_authentication is False
        assert config.enable_legacy_unauthenticated_modes is False


class TestPipelineInstructionFileGetDisabled:
    """Tests for GetEncryptedObjectPipeline when instruction file get is disabled."""

    def test_decrypt_raises_when_instruction_file_disabled_and_needed(self):
        """Pipeline MUST raise when instruction file is needed but disabled."""
        object_metadata = {}

        mock_keyring = Mock(spec=S3Keyring)
        cmm = DefaultCryptoMaterialsManager(mock_keyring)
        mock_s3_client = Mock()

        pipeline = GetEncryptedObjectPipeline(
            cmm,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            s3_client=mock_s3_client,
            instruction_file_config=InstructionFileConfig(disable_get_object=True),
        )

        mock_response = {
            "Body": BytesIO(b"encrypted-data"),
            "Metadata": object_metadata,
        }

        with pytest.raises(
            S3EncryptionClientError,
            match="Exception encountered while fetching Instruction File",
        ):
            pipeline.decrypt(
                mock_response,
                instruction_suffix=".instruction",
                enable_delayed_authentication=False,
                bucket="test-bucket",
                key="test-key",
            )

        mock_s3_client.get_object.assert_not_called()

    def test_decrypt_raises_when_instruction_file_disabled_v3_partial_metadata(self):
        """Pipeline MUST raise when V3 object has partial metadata requiring instruction file."""
        object_metadata = {
            "x-amz-c": "115",
            "x-amz-d": base64.b64encode(b"key-commitment-data").decode("utf-8"),
            "x-amz-i": base64.b64encode(b"test-message-id").decode("utf-8"),
        }

        mock_keyring = Mock(spec=S3Keyring)
        cmm = DefaultCryptoMaterialsManager(mock_keyring)
        mock_s3_client = Mock()

        pipeline = GetEncryptedObjectPipeline(
            cmm,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            s3_client=mock_s3_client,
            instruction_file_config=InstructionFileConfig(disable_get_object=True),
        )

        mock_response = {
            "Body": BytesIO(b"encrypted-data"),
            "Metadata": object_metadata,
        }

        with pytest.raises(
            S3EncryptionClientError,
            match="Exception encountered while fetching Instruction File",
        ):
            pipeline.decrypt(
                mock_response,
                instruction_suffix=".instruction",
                enable_delayed_authentication=False,
                bucket="test-bucket",
                key="test-key",
            )

        mock_s3_client.get_object.assert_not_called()

    def test_decrypt_succeeds_when_instruction_file_disabled_but_not_needed(self):
        """Objects with metadata in headers decrypt fine regardless of config."""
        object_metadata = {
            "x-amz-iv": base64.b64encode(os.urandom(12)).decode("utf-8"),
            "x-amz-key-v2": base64.b64encode(b"encrypted-key-data").decode("utf-8"),
            "x-amz-wrap-alg": "kms+context",
            "x-amz-matdesc": json.dumps({"kms_cmk_id": "test-key-id"}),
            "x-amz-cek-alg": "AES/GCM/NoPadding",
            "x-amz-tag-len": "128",
        }

        mock_keyring = Mock(spec=S3Keyring)
        cmm = DefaultCryptoMaterialsManager(mock_keyring)

        pipeline = GetEncryptedObjectPipeline(
            cmm,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            s3_client=None,
            instruction_file_config=InstructionFileConfig(disable_get_object=True),
        )

        mock_response = {
            "Body": BytesIO(b"encrypted-data"),
            "Metadata": object_metadata,
            "ContentLength": 100,
        }

        mock_keyring.on_decrypt.side_effect = Exception("Keyring called — no instruction file")

        with pytest.raises(Exception, match="Keyring called"):
            pipeline.decrypt(
                mock_response,
                instruction_suffix=".instruction",
                enable_delayed_authentication=False,
                bucket="test-bucket",
                key="test-key",
            )

    def test_decrypt_fetches_instruction_file_when_not_disabled(self):
        """Pipeline fetches instruction file normally when disable_get_object is False."""
        object_metadata = {}

        instruction_file_metadata = {
            "x-amz-iv": base64.b64encode(os.urandom(12)).decode("utf-8"),
            "x-amz-key-v2": base64.b64encode(b"encrypted-key-data").decode("utf-8"),
            "x-amz-wrap-alg": "kms+context",
            "x-amz-matdesc": json.dumps({"kms_cmk_id": "test-key-id"}),
            "x-amz-cek-alg": "AES/GCM/NoPadding",
            "x-amz-tag-len": "128",
            "x-amz-crypto-instr-file": "",
        }

        mock_s3_client = Mock()
        mock_s3_client.get_object.return_value = {
            "Body": BytesIO(b""),
            "Metadata": instruction_file_metadata,
        }

        mock_keyring = Mock(spec=S3Keyring)
        cmm = DefaultCryptoMaterialsManager(mock_keyring)

        pipeline = GetEncryptedObjectPipeline(
            cmm,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            s3_client=mock_s3_client,
            instruction_file_config=InstructionFileConfig(disable_get_object=False),
        )

        mock_response = {
            "Body": BytesIO(b"encrypted-test-data"),
            "Metadata": object_metadata,
        }

        mock_keyring.on_decrypt.side_effect = Exception(
            "Keyring called - instruction file was fetched"
        )

        with pytest.raises(Exception, match="Keyring called"):
            pipeline.decrypt(
                mock_response,
                instruction_suffix=".instruction",
                enable_delayed_authentication=False,
                bucket="test-bucket",
                key="test-key",
            )

        mock_s3_client.get_object.assert_called_once_with(
            Bucket="test-bucket", Key="test-key.instruction"
        )
