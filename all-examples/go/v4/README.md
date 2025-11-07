# S3 Encryption Client Go v4 Example

This example demonstrates how to use the Amazon S3 Encryption Client v4 for Go to perform client-side encryption and decryption of objects stored in Amazon S3 with enhanced security features including commitment policies.

## Prerequisites

1. **Go**: Requires Go 1.24 or later
2. **AWS Credentials**: Configure your AWS credentials using one of the following methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - IAM roles (for EC2 instances)
3. **KMS Key**: You'll need a KMS key ID or ARN. You can use the default example key: `arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01`
4. **S3 Bucket**: An existing S3 bucket where you have read/write permissions

## Setup

1. Initialize submodules and download dependencies:
   ```bash
   make init
   ```
   
   Or manually:
   ```bash
   git submodule update --init --recursive
   go mod tidy
   ```

   **Note**: This example uses a local submodule for the S3EC Go v4 library via the `replace` directive in `go.mod`.

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

Build the binary:
```bash
make build
```

Run directly without building:
```bash
make run-direct
```

### Manual Usage

Run the example with the following command:

```bash
go run main.go <bucket-name> <object-key> <kms-key-id> <region>
```

### Example:

```bash
go run main.go my-test-bucket s3ec-go-v4-test arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2
```

## What This Example Does

1. **Initialize S3 Encryption Client v4**: Creates an S3 encryption client using KMS for key management with commitment policy
2. **Encrypt and Upload**: Encrypts test data and uploads it to the specified S3 bucket
3. **Download and Decrypt**: Downloads the encrypted object and decrypts it
4. **Verify Integrity**: Compares the original data with the decrypted data to ensure integrity
5. **Cleanup**: Optionally deletes the test object (commented out by default)

## Key Features Demonstrated

- **Client-side encryption** using AES-GCM
- **KMS integration** for key wrapping and management
- **Encryption context** for additional security
- **Commitment policy enforcement** for enhanced security
- **Automatic key rotation** and management
- **Secure roundtrip** data integrity verification

## Security Profile

This example uses S3 Encryption Client v4 with the following security features:
- **Key Wrap Schema**: kms_context
- **Content Encryption Schema**: aes_gcm_no_padding
- **Security Profile**: v4 (latest security enhancements)
- **Commitment Policy**: REQUIRE_ENCRYPT_ALLOW_DECRYPT (requires commitment on encryption, allows decryption of both committed and non-committed objects)

## Commitment Policy

S3 Encryption Client v4 introduces commitment policies to provide additional security guarantees:

- **REQUIRE_ENCRYPT_REQUIRE_DECRYPT**: Requires commitment on both encryption and decryption
- **REQUIRE_ENCRYPT_ALLOW_DECRYPT**: Requires commitment on encryption, allows decryption of both committed and non-committed objects (used in this example)
- **FORBID_ENCRYPT_ALLOW_DECRYPT**: Forbids commitment on encryption, allows decryption of both committed and non-committed objects

## Error Handling

The example includes comprehensive error handling for common scenarios:
- Invalid AWS credentials
- Non-existent S3 buckets
- Inaccessible KMS keys
- Legacy wrapping algorithm errors
- Network connectivity issues
- Data integrity verification failures

## Notes

- The cleanup step (deleting the test object) is commented out by default to allow you to inspect the encrypted object in S3
- Uncomment the cleanup code in Step 5 if you want the example to automatically delete the test object
- The example uses encryption context metadata for additional security
- If using a local version of S3EC Go v4, ensure the `replace` directive in `go.mod` points to the correct local path
