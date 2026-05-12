# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for user agent string injection."""
from unittest.mock import MagicMock, patch

import boto3

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption._utils import _PACKAGE_VERSION, _USER_AGENT_SUFFIX
from s3_encryption.materials.kms_keyring import KmsKeyring


class TestUserAgent:
    def test_user_agent_suffix_format(self):
        assert _USER_AGENT_SUFFIX == f"S3ECPy/{_PACKAGE_VERSION}"

    def test_s3_client_gets_user_agent(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        kms = boto3.client("kms", region_name="us-east-1")
        keyring = KmsKeyring(kms, "arn:aws:kms:us-east-1:000000000000:key/fake")
        config = S3EncryptionClientConfig(keyring=keyring)

        S3EncryptionClient(s3, config)

        assert _USER_AGENT_SUFFIX in s3.meta.config.user_agent_extra

    def test_kms_client_gets_user_agent(self):
        kms = boto3.client("kms", region_name="us-east-1")
        KmsKeyring(kms, "arn:aws:kms:us-east-1:000000000000:key/fake")

        assert _USER_AGENT_SUFFIX in kms.meta.config.user_agent_extra

    def test_existing_user_agent_extra_preserved(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.meta.config.user_agent_extra = "existing-agent/1.0"

        kms = boto3.client("kms", region_name="us-east-1")
        keyring = KmsKeyring(kms, "arn:aws:kms:us-east-1:000000000000:key/fake")
        config = S3EncryptionClientConfig(keyring=keyring)

        S3EncryptionClient(s3, config)

        assert "existing-agent/1.0" in s3.meta.config.user_agent_extra
        assert _USER_AGENT_SUFFIX in s3.meta.config.user_agent_extra
