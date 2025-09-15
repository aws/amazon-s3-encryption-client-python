# S3EC PHP V3 Test Server

This is the PHP V3 implementation of the S3ECTestServer framework. It provides a server implementation for testing S3 Encryption Client functionality.

## Overview

The S3ECPhpV3TestServer implements the S3ECTestServer service defined in the shared Smithy model. It provides endpoints for:

- Creating S3 Encryption Clients
- Putting objects with encryption
- Getting and decrypting objects

## Usage

This will start the server running on port `8093`.

The server is used as part of the testing framework to verify cross-language compatibility of the S3 Encryption Client implementations.
