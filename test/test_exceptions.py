# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import pytest
from botocore.exceptions import BotoCoreError

from s3_encryption.exceptions import (
    S3EncryptionClientError,
    S3EncryptionClientSecurityError,
)


class TestS3EncryptionClientError:
    def test_default_message(self):
        error = S3EncryptionClientError()
        assert str(error) == "An unspecified S3 Encryption Client error occurred"

    def test_custom_message(self):
        error = S3EncryptionClientError("Custom error message")
        assert str(error) == "Custom error message"

    def test_empty_message(self):
        error = S3EncryptionClientError("")
        assert str(error) == ""

    def test_inherits_from_botocore_error(self):
        error = S3EncryptionClientError("test")
        assert isinstance(error, BotoCoreError)

    def test_can_be_caught_as_botocore_error(self):
        with pytest.raises(BotoCoreError):
            raise S3EncryptionClientError("test error")


class TestS3EncryptionClientSecurityError:
    def test_default_message(self):
        error = S3EncryptionClientSecurityError()
        assert str(error) == "An unspecified S3 Encryption Client Security error occurred"

    def test_custom_message(self):
        error = S3EncryptionClientSecurityError("Custom security error")
        assert str(error) == "Custom security error"

    def test_empty_message(self):
        error = S3EncryptionClientSecurityError("")
        assert str(error) == ""

    def test_inherits_from_botocore_error(self):
        error = S3EncryptionClientSecurityError("test")
        assert isinstance(error, BotoCoreError)

    def test_can_be_caught_as_botocore_error(self):
        with pytest.raises(BotoCoreError):
            raise S3EncryptionClientSecurityError("test security error")


from s3_encryption._utils import safe_get_dict


class TestSafeGetDict:
    def test_returns_value_when_present(self):
        assert safe_get_dict({"key": {"a": 1}}, "key") == {"a": 1}

    def test_returns_empty_dict_when_key_missing(self):
        assert safe_get_dict({}, "key") == {}

    def test_returns_empty_dict_when_value_is_none(self):
        assert safe_get_dict({"key": None}, "key") == {}

    def test_returns_empty_dict_for_empty_value(self):
        assert safe_get_dict({"key": {}}, "key") == {}

    def test_preserves_non_empty_dict(self):
        data = {"x": "y", "z": "w"}
        assert safe_get_dict({"meta": data}, "meta") == data
