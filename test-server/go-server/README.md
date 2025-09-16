# Go Server for S3 Encryption Client Test Framework

This is a Go implementation of the S3 Encryption Client test server, part of the S3EC Generalized Robust Test Framework Machine (G-RTFM).

## Overview

The Go server implements the same Smithy-defined API as the Java and Python servers, providing:

- **CreateClient**: Creates and configures S3 encryption clients
- **PutObject**: Handles encrypted object uploads to S3
- **GetObject**: Handles encrypted object downloads from S3

## Architecture

The server is built using:

- **HTTP Framework**: Gorilla Mux for routing
- **AWS SDK**: AWS SDK for Go v2 for S3 and KMS operations
- **Concurrency**: Thread-safe client caching with sync.RWMutex
- **Error Handling**: Smithy-compliant error responses

## API Endpoints

### POST /client
Creates a new S3 encryption client with the provided configuration.

**Request Body:**
```json
{
  "config": {
    "enableLegacyUnauthenticatedModes": false,
    "enableDelayedAuthenticationMode": false,
    "enableLegacyWrappingAlgorithms": false,
    "setBufferSize": 1024,
    "keyMaterial": {
      "rsaKey": "...",
      "aesKey": "...",
      "kmsKeyId": "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
    }
  }
}
```

**Response:**
```json
{
  "clientId": "uuid-string"
}
```

### PUT /object/{bucket}/{key}
Uploads an encrypted object to S3 using the specified client.

**Headers:**
- `ClientID`: The client ID returned from CreateClient
- `Content-Metadata`: Encryption context metadata (optional)

**Request Body:** Raw object data

**Response:**
```json
{
  "bucket": "bucket-name",
  "key": "object-key",
  "metadata": []
}
```

### GET /object/{bucket}/{key}
Downloads and decrypts an object from S3 using the specified client.

**Headers:**
- `ClientID`: The client ID returned from CreateClient
- `Content-Metadata`: Encryption context metadata (optional)

**Response:** Raw object data with `Content-Metadata` header

## Building and Running

### Prerequisites

- Go 1.21 or later
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)

### Build

```bash
# Install dependencies
make deps

# Build the server
make build

# Or build and run
make run
```

### Development

```bash
# Format code
make fmt

# Vet code
make vet

# Run tests
make test

# Clean build artifacts
make clean
```

## Configuration

The server runs on port 8082 by default and uses the `us-west-2` AWS region. These can be modified in the source code if needed.

## Error Handling

The server implements Smithy-compliant error responses:

- **GenericServerError**: For internal server errors
- **S3EncryptionClientError**: For S3 encryption client specific errors

## Implementation Notes

- **Client Caching**: Clients are stored in memory with UUID keys for thread-safe access
- **Metadata Handling**: Follows the same metadata string format as Java/Python servers
- **AWS Integration**: Uses AWS SDK v2 for modern Go AWS operations
- **Concurrency**: Safe for concurrent requests with proper mutex usage

## Limitations

- This is a basic implementation that uses standard S3 clients rather than full S3 encryption clients
- In a production implementation, you would integrate with the actual S3 encryption client library
- Memory-based client storage (not persistent across restarts)

## Testing

The server is designed to work with the existing test framework. It should be compatible with the Java tests that validate the Smithy API contract.

## Future Enhancements

- Integration with actual S3 encryption client library
- Persistent client storage
- Enhanced logging and metrics
- Configuration file support
- Health check endpoints
