# S3 Encryption Client Go v4 Example

This example demonstrates how to use the Amazon S3 Encryption Client v4 for Go to perform client-side encryption and decryption of objects.

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
   make install
   ```
   
   Or manually:
   ```bash
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

### Manual Usage

Run the example with the following command:

```bash
go run main.go <bucket-name> <object-key> <kms-key-id> <region>
```

### Example:

```bash
go run main.go my-test-bucket s3ec-go-v4-test arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2
```
