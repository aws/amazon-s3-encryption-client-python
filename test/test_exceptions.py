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
