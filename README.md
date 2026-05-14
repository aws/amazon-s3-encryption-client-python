# Amazon S3 Encryption Client for Python

This library provides an S3 client that supports client-side encryption. For more information and detailed instructions for how to use this library, refer to the [Amazon S3 Encryption Client Developer Guide](https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/python.html).

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
