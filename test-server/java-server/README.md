# S3EC Java Test Server

This is the Java implementation of the S3ECTestServer framework. It provides a server implementation for testing S3 Encryption Client functionality.

## Overview

The S3ECJavaTestServer implements the S3ECTestServer service defined in the shared Smithy model. It provides endpoints for:

- Creating S3 Encryption Clients
- Putting objects with encryption
- Getting and decrypting objects

## Usage

To run the server:

```console
gradle run
```

This will start the server running on port `8080`.

The server is used as part of the testing framework to verify cross-language compatibility of the S3 Encryption Client implementations.
