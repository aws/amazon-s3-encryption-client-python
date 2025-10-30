# S3 Encryption Client C++ v3 Example

This example demonstrates the enhanced KMS integration pattern used by the Amazon S3 Encryption Client for C++ v3. It shows how S3EC v3 generates data keys from KMS with enhanced encryption context and security profiles, which is the foundation of client-side encryption with improved security.

**Note**: This is a demonstration example that shows the KMS workflow with v3 enhancements. For the complete S3 encryption client functionality, you need the full S3EC library from https://github.com/aws/amazon-s3-encryption-client-cpp

## Prerequisites

1. **AWS SDK for C++**: The AWS SDK for C++ must be installed on your system. You can install it via:
   - Package manager (e.g., `brew install aws-sdk-cpp` on macOS, `apt-get install libaws-cpp-sdk-dev` on Ubuntu)
   - Build from source: https://github.com/aws/aws-sdk-cpp
   - vcpkg: `vcpkg install aws-sdk-cpp[kms,s3,s3-encryption]`
2. **AWS Credentials**: Configure your AWS credentials using one of these methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - IAM roles (for EC2 instances)
3. **KMS Key**: Create a KMS key in your AWS account and note the key ID/ARN
4. **S3 Bucket**: Create an S3 bucket for testing
5. **Build Tools**: 
   - CMake 3.16 or later
   - C++17 compatible compiler (GCC, Clang, or MSVC)

## Building

Use the provided Makefile to build the example:

```bash
make build
```

This will:
1. Create a `build` directory
2. Run CMake to configure the project
3. Compile the example

## Running

### Quick Start

Run with default parameters (you'll need to update these):

```bash
make run BUCKET_NAME=avp-21638 OBJECT_KEY=s3ec-cpp-v3 KMS_KEY_ID=arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01
```

### Available Make Targets

- `make build` - Build the example
- `make run` - Build and run with parameters
- `make clean` - Remove build artifacts
- `make help` - Show help information

### Direct Execution

After building, you can also run the executable directly:

```bash
./build/s3ec-example <bucket-name> <object-key> <kms-key-id>
```

## Example Usage

```bash
make run BUCKET_NAME=my-test-bucket OBJECT_KEY=example.txt KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
```

## What the Example Does

1. **Initialize**: Sets up the AWS SDK and creates an S3 encryption client with KMS materials
2. **Encrypt & Upload**: Encrypts a test message and uploads it to S3 with encryption context
3. **Download & Decrypt**: Downloads the encrypted object and decrypts it with context validation
4. **Verify**: Compares the original and decrypted data to ensure they match

## Key Features Demonstrated

- **KMS Integration**: Uses AWS KMS for key management with enhanced security
- **Encryption Context**: Demonstrates using encryption context with stricter validation
- **Modern Security**: Uses v3's enhanced security profiles
- **Error Handling**: Shows proper error handling for S3 operations
- **Resource Management**: Proper initialization and cleanup of AWS SDK

## Security Profile

This v3 example uses the modern security profile (V2), which:
- Enforces authenticated encryption modes
- Uses stronger cryptographic standards
- Provides stricter validation of encryption context
- Focuses on security best practices

## Version Differences from v2

The v3 client provides several enhancements over v2:
- **Enhanced Security**: Stricter security profiles and validation
- **Modern Cryptography**: Focus on current cryptographic standards
- **Better Error Handling**: More detailed error messages and validation
- **Improved API**: Cleaner and more consistent API patterns

## Troubleshooting

### Common Issues

1. **Build Errors**: Ensure AWS SDK for C++ is properly configured and available
2. **Runtime Errors**: Check AWS credentials and permissions
3. **KMS Errors**: Verify the KMS key exists and you have permissions to use it
4. **S3 Errors**: Ensure the bucket exists and you have read/write permissions
5. **Security Profile Errors**: v3 may reject operations that v2 would allow for security reasons

### Required Permissions

Your AWS credentials need the following permissions:
- `s3:GetObject` and `s3:PutObject` on the target bucket
- `kms:Encrypt`, `kms:Decrypt`, and `kms:GenerateDataKey` on the KMS key

### Migration from v2

If migrating from v2:
- Review security profile settings - v3 defaults to stricter security
- Test encryption context validation - v3 may be more strict
- Update error handling for new error types
- Consider the enhanced security features

## Version Notes

This is the v3 version of the S3 Encryption Client, which provides:
- Enhanced security profiles with stricter validation
- Modern cryptographic standards
- Improved API consistency
- Better error reporting and debugging capabilities

## Security Considerations

v3 emphasizes security best practices:
- Always use encryption context for additional security
- Prefer authenticated encryption modes
- Use the latest cryptographic algorithms
- Validate all inputs and outputs
