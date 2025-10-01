# S3EC Java V4 (Improved) Test Server

This is the Java implementation of the S3ECTestServer framework for S3EC Java V4 (Improved). It provides a server implementation for testing Java S3 Encryption Client V4 (Improved) functionality.

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

This will start the server running on port `8090`.

The server is used as part of the testing framework to verify cross-language compatibility of the S3 Encryption Client implementations.
