# S3 Encryption Client Go v3 Example

This example demonstrates how to use the Amazon S3 Encryption Client v3 for Go to perform client-side encryption and decryption of objects stored in Amazon S3.

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
go run main.go my-test-bucket s3ec-go-v3-test arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2
```

## What This Example Does

1. **Initialize S3 Encryption Client v3**: Creates an S3 encryption client using KMS for key management
2. **Encrypt and Upload**: Encrypts test data and uploads it to the specified S3 bucket
3. **Download and Decrypt**: Downloads the encrypted object and decrypts it
4. **Verify Integrity**: Compares the original data with the decrypted data to ensure integrity
5. **Cleanup**: Optionally deletes the test object (commented out by default)

## Key Features Demonstrated

- **Client-side encryption** using AES-GCM
- **KMS integration** for key wrapping and management
- **Encryption context** for additional security
- **Automatic key rotation** and management
- **Secure roundtrip** data integrity verification

## Security Profile

This example uses S3 Encryption Client v3 with the following security features:
- **Key Wrap Schema**: kms_context
- **Content Encryption Schema**: aes_gcm_no_padding
- **Security Profile**: v3 (enhanced security)

## Error Handling

The example includes comprehensive error handling for common scenarios:
- Invalid AWS credentials
- Non-existent S3 buckets
- Inaccessible KMS keys
- Network connectivity issues
- Data integrity verification failures

## Notes

- The cleanup step (deleting the test object) is commented out by default to allow you to inspect the encrypted object in S3
- Uncomment the cleanup code in Step 5 if you want the example to automatically delete the test object
- The example uses encryption context metadata for additional security
