# S3EC Go V3 Transition Test Server

This is the Go implementation of the S3ECTestServer framework for S3EC Go V3 Transition. It provides a server implementation for testing Go S3 Encryption Client V3 Transition functionality.

## Overview

The S3EC Go test server implements the S3ECTestServer service defined in the shared Smithy model. It provides endpoints for:

- Creating S3 Encryption Clients
- Putting objects with encryption
- Getting and decrypting objects

## Usage

To run the server:

```console
go run .
```

This will start the server running on port `8095`.

The server is used as part of the testing framework to verify cross-language compatibility of the S3 Encryption Client implementations.
