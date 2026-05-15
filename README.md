# Amazon S3 Encryption Client for Python

This library provides an S3 client that supports client-side encryption. For more information and detailed instructions for how to use this library, refer to the [Amazon S3 Encryption Client Developer Guide](https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/python.html).

## Getting Started

Requires Python 3.10 or greater. An AWS account is required; standard S3 and KMS charges apply.

The S3 Encryption Client wraps a standard boto3 S3 client and uses a KMS keyring to manage data key encryption. Objects are encrypted before upload and decrypted after download transparently. By default, the client uses AES-GCM with key commitment for content encryption.

```python
import boto3
from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.materials.kms_keyring import KmsKeyring

kms_client = boto3.client("kms", region_name="us-west-2")
keyring = KmsKeyring(kms_client, "arn:aws:kms:us-west-2:123456789012:alias/my-key")

s3_client = boto3.client("s3")
config = S3EncryptionClientConfig(keyring=keyring)
s3ec = S3EncryptionClient(s3_client, config)

# Encrypt and upload
s3ec.put_object(Bucket="my-bucket", Key="my-object", Body=b"secret data")

# Download and decrypt
response = s3ec.get_object(Bucket="my-bucket", Key="my-object")
plaintext = response["Body"].read()
```

## Development

### Prerequisites

- Python 3.10 or higher
- [uv](https://github.com/astral-sh/uv) for package and project management

### Setup

Install dependencies:

```bash
make install
```

### Testing

Run all tests (unit + integration + examples):

```bash
make test
```

Run unit tests only:

```bash
make test-unit
```

Run integration tests only:

```bash
make test-integration
```

### Code Quality

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting.

Check formatting:

```bash
make format-check
```

Run linter:

```bash
make lint
```

Format code and auto-fix lint issues:

```bash
make format
```

### Integration Test Resources

Integration tests require AWS credentials and the following resources. The tests use environment variables to override CI defaults:

| Variable | Description | Default |
|----------|-------------|---------|
| `CI_S3_BUCKET` | S3 bucket for read/write tests | `s3ec-python-github-test-bucket` |
| `CI_AWS_REGION` | Primary AWS region | `us-west-2` |
| `CI_KMS_KEY_ALIAS` | KMS key ARN or alias for encryption | `arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key` |
| `CI_MRK_KEY_ID_PRIMARY` | Multi-region key ARN (primary region) | `arn:aws:kms:us-west-2:370957321024:key/mrk-cea4cf67c6a046ba829f61f69db5c191` |
| `CI_MRK_KEY_ID_REPLICA` | Multi-region key ARN (replica region) | `arn:aws:kms:us-east-1:370957321024:key/mrk-cea4cf67c6a046ba829f61f69db5c191` |
| `CI_S3_STATIC_TEST_BUCKET` | Bucket with pre-existing test objects for instruction file tests | `s3ec-static-test-objects` |
| `CI_KMS_KEY_STATIC_TESTS` | KMS key used for static test objects | `arn:aws:kms:us-west-2:370957321024:key/a3889cd9-99eb-4138-a93a-aea9d52ec2ef` |

To run integration tests locally, configure AWS credentials with access to these resources (or your own equivalents) and set the environment variables accordingly.
