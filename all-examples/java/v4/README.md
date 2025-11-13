# S3 Encryption Client Java v4 Example

This example demonstrates how to use the Amazon S3 Encryption Client v4 for Java to perform client-side encryption and decryption of objects with **key commitment** enabled for enhanced security.

## Key Differences from v3

- **Key Commitment**: v4 enables key commitment by default, which provides additional security by binding the data encryption key to the encrypted data
- **Security Profile**: Uses more secure defaults (no legacy unauthenticated modes or wrapping algorithms)
- **Enhanced Protection**: Protects against key substitution attacks

## Prerequisites

1. **Java**: Requires Java 11 or later
2. **Gradle**: The project uses Gradle wrapper (included)
3. **AWS Credentials**: Configure your AWS credentials using one of the following methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - IAM roles (for EC2 instances)
4. **KMS Key**: You'll need a KMS key ID or ARN. You can use the default example key: `arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01`
5. **S3 Bucket**: An existing S3 bucket where you have read/write permissions
6. **S3 Encryption Client v4 Library**: The library must be installed in your local Maven repository

## Setup

### Install S3 Encryption Client v4 Library

Before running the example, you need to install the S3 Encryption Client v4 library to your local Maven repository:

```bash
cd s3ec-staging
mvn clean install
cd ..
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
./gradlew run --args="my-test-bucket s3ec-java-v4-test arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2"
```

## What This Example Does

1. **Initializes the S3 Encryption Client** with KMS keyring and key commitment enabled
2. **Encrypts and uploads** a test message to S3 with key commitment
3. **Downloads and decrypts** the object from S3, verifying key commitment
4. **Verifies** that the decrypted data matches the original data and key commitment is maintained

## Key Features

- **Key Commitment**: Enabled by default for enhanced security against key substitution attacks
- **KMS Integration**: Uses AWS Key Management Service for encryption key management
- **Client-Side Encryption**: Data is encrypted before sending to S3
- **Encryption Context**: Adds metadata to track encryption operations
- **Automatic Decryption**: Transparently decrypts data when reading from S3
- **Enhanced Security**: Disables legacy unauthenticated modes and wrapping algorithms

## Security Enhancements in v4

v4 provides stronger security guarantees compared to v3:

1. **Key Commitment**: Cryptographically binds the data encryption key to the encrypted data
2. **Protection Against Key Substitution**: Prevents attackers from substituting encryption keys
3. **No Legacy Modes**: Disables older, less secure encryption modes by default
4. **Stronger Defaults**: Uses only modern, well-vetted cryptographic algorithms

## Troubleshooting

### Library Not Found

If you see errors about missing S3 Encryption Client library:
```
Could not resolve: software.amazon.encryption.s3:amazon-s3-encryption-client-java:3.4.0-add-kc
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

### Key Commitment Compatibility

Objects encrypted with v4 (with key commitment) can be decrypted by v4 clients. However, v3 clients without key commitment support may not be able to decrypt v4 encrypted objects. Plan your migration strategy accordingly.

## Project Structure

```
all-examples/java/v4/
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

## Migration from v3 to v4

If you're migrating from v3 to v4:

1. **Update Dependencies**: Change library version from v3 to v4
2. **Review Security Settings**: v4 has stronger defaults (key commitment enabled)
3. **Test Compatibility**: Ensure your application can handle key commitment
4. **Update Documentation**: Document the security enhancements for your users

## Related Examples

- **Java v3**: See `../v3/` for the v3 example without key commitment
- **Other Languages**: Check `../../` for Go, .NET, Ruby, and C++ examples

## Additional Resources

- [AWS S3 Encryption Client Documentation](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/)
- [AWS SDK for Java v2](https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/)
- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)
- [Key Commitment Specification](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/changes/2020-05-13_key-commitment/key-commitment.md)
