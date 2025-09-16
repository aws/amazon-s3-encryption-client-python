# S3EC PHP v2 Test Server

This is the PHP V2 implementation of the S3ECTestServer framework. It provides a server implementation for testing S3 Encryption Client functionality.

## Overview

The S3ECPhpV2TestServer implements the S3ECTestServer service defined in the shared Smithy model. It provides endpoints for:

- Creating S3 Encryption Clients with session-based caching
- Putting objects with encryption
- Getting and decrypting objects

## Starting the Server

### Method 1: Using Composer (Recommended)
```bash
composer run start
```

The server will start on port `8087`.

## Available Endpoints

### Server Status
- **GET /** - Returns server status and available endpoints

### Client Management
- **POST /client** - Creates an S3EncryptionClient and caches it with session persistence
- **GET /cache** - Shows current session state and cached clients (for debugging)

### Object Operations
- **GET /object/{bucket}/{key}** - Handle GET requests using the S3EncryptionClient
- **PUT /object/{bucket}/{key}** - Handle PUT requests using the S3EncryptionClient

## Testing with curl

### Important: Session Cookie Management

To properly test the server and maintain session persistence, you **must** use cookies with curl:

#### First Request (creates session cookie):
```bash
curl -X POST http://localhost:8087/client \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -v
```

#### Subsequent Requests (reuses session cookie):
```bash
curl -X POST http://localhost:8087/client \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -c cookies.txt \
  -v
```

#### Check Cache Status:
```bash
curl http://localhost:8087/cache \
  -b cookies.txt
```

#### Helpful Notes
- **Session Storage**: Client configurations are stored in `$_SESSION['s3ecCache']`
- **Object Recreation**: AWS SDK objects are recreated from stored configuration (they cannot be serialized)
AWS SDK obbjects cannot be serialized due to internal resources and closures.
- **Helper Function**: `getCachedClient($clientId)` retrieves and recreates clients from cache
- **Debugging**: Enhanced logging and `/cache` endpoint for troubleshooting
