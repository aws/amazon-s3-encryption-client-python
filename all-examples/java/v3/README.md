# S3 Encryption Client Java v3 Example

This example demonstrates how to use the Amazon S3 Encryption Client v3 for Java to perform client-side encryption and decryption of objects.

## Prerequisites

1. **Java**: Requires Java 11 or later
2. **Gradle**: The project uses Gradle wrapper (included)
3. **AWS Credentials**: Configure your AWS credentials using one of the following methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - IAM roles (for EC2 instances)
4. **KMS Key**: You'll need a KMS key ID or ARN. You can use the default example key: `arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01`
5. **S3 Bucket**: An existing S3 bucket where you have read/write permissions
6. **S3 Encryption Client v3 Library**: The library must be installed in your local Maven repository

## Setup

### Install S3 Encryption Client v3 Library

Before running the example, you need to install the S3 Encryption Client v3 library to your local Maven repository:

```bash
cd s3ec-staging
mvn clean install
cd -
```

### Build the Project

Build the project using the Makefile or Gradle:

```bash
make install
```

Or using Gradle directly:

```bash
./gradlew build
```

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

Run the example using Gradle:

```bash
./gradlew run --args="<bucket-name> <object-key> <kms-key-id> <region>"
```

### Example:

```bash
./gradlew run --args="my-test-bucket s3ec-java-v3-test arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2"
```

## What This Example Does

1. **Initializes the S3 Encryption Client** with KMS keyring for key management
2. **Encrypts and uploads** a test message to S3
3. **Downloads and decrypts** the object from S3
4. **Verifies** that the decrypted data matches the original data

## Key Features

- **KMS Integration**: Uses AWS Key Management Service for encryption key management
- **Client-Side Encryption**: Data is encrypted before sending to S3
- **Encryption Context**: Adds metadata to track encryption operations
- **Automatic Decryption**: Transparently decrypts data when reading from S3

## Troubleshooting

### Library Not Found

If you see errors about missing S3 Encryption Client library:
```
Could not resolve: software.amazon.encryption.s3:amazon-s3-encryption-client-java:3.4.0-TRANSITION
```

Solution: Install the library to your local Maven repository:
```bash
cd s3ec-staging && mvn install
```

### AWS Credentials

If you see AWS authentication errors, ensure your credentials are properly configured:
```bash
aws configure list
```

### KMS Access

Ensure you have permissions to use the KMS key:
- `kms:Encrypt`
- `kms:Decrypt`
- `kms:GenerateDataKey`

## Project Structure

```
all-examples/java/v3/
├── build.gradle.kts          # Gradle build configuration
├── settings.gradle.kts       # Gradle settings
├── Makefile                  # Build and run automation
├── README.md                 # This file
└── src/
    └── main/
        └── java/
            └── software/
                └── amazon/
                    └── encryption/
                        └── s3/
                            └── example/
                                └── Main.java   # Main example code
```

## Related Examples

- **Java v4**: See `../v4/` for the v4 example with key commitment
- **Other Languages**: Check `../../` for Go, .NET, Ruby, and C++ examples

## Additional Resources

- [AWS S3 Encryption Client Documentation](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/)
- [AWS SDK for Java v2](https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/)
- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)
