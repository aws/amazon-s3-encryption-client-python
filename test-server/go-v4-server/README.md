# S3EC Go V3 Test Server

This is the Go implementation of the S3ECTestServer framework for S3EC Go V3. It provides a server implementation for testing Go S3 Encryption Client V3 functionality.

## Overview

The S3EC Go test server implements the S3ECTestServer service defined in the shared Smithy model. It provides endpoints for:

- Creating S3 Encryption Clients
- Putting objects with encryption
- Getting and decrypting objects

## Architecture

The server is built using:

- **HTTP Framework**: Gorilla Mux for routing
- **AWS SDK**: AWS SDK for Go v2 for S3 and KMS operations
- **Concurrency**: Thread-safe client caching with sync.RWMutex
- **Error Handling**: Smithy-compliant error responses

## Usage

To run the server:

```console
go run .
```

This will start the server running on port `8082`.

The server is used as part of the testing framework to verify cross-language compatibility of the S3 Encryption Client implementations.
