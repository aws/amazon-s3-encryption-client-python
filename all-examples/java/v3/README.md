# S3 Encryption Client Java v3 Example

This example demonstrates how to use the Amazon S3 Encryption Client v3 for Java to perform client-side encryption and decryption of objects.

## Prerequisites

1. **Java**: Requires Java 11 or later
2. **Gradle**: The project uses Gradle wrapper (included - `./gradlew`)
3. **Maven**: Required to install the S3 Encryption Client library from source
4. **AWS Credentials**: Configure your AWS credentials using one of the following methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - IAM roles (for EC2 instances)
5. **KMS Key**: You'll need a KMS key ID or ARN. You can use the default example key: `arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01`
6. **S3 Bucket**: An existing S3 bucket where you have read/write permissions

## Setup

Install dependencies and build (this automatically installs the S3 Encryption Client library from source):
```bash
make install
```

Or manually:
```bash
cd s3ec-staging && mvn clean install && cd -
./gradlew build
```

**Note**: This example uses a local library installed in Maven local repository via the symbolic link `s3ec-staging`.

## Usage

### Using Make (Recommended)

Run the example with default parameters:
```bash
make run
```

Run with custom parameters:
```bash
make run BUCKET_NAME=my-bucket OBJECT_KEY=my-key KMS_KEY_ID=my-kms-key AWS_REGION=my-region
```

### Manual Usage

Run the example with the following command:

```bash
./gradlew run --args="<bucket-name> <object-key> <kms-key-id> <region>"
```

### Example:

```bash
./gradlew run --args="my-test-bucket s3ec-java-v3-test arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2"
