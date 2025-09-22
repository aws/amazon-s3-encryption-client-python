# Ruby S3 Encryption Client Test Server

This is a Ruby implementation of the S3 Encryption Client test server
that provides an invariant interface around the S3 Encryption Client v2.
It's designed to work alongside other implementations of test servers for cross-language compatibility testing.

## Overview

The server provides a REST API that wraps the AWS S3 Encryption Client v2,
allowing tests to verify that all language implementations behave consistently.

## Endpoints

- `POST /client` - Create a new S3 encryption client instance
- `PUT /object/{bucket}/{key}` - Encrypt and store an object
- `GET /object/{bucket}/{key}` - Retrieve and decrypt an object
- `GET /health` - Health check endpoint

## Configuration

The server runs on port **8086** by default.

## Setup

1. Install Ruby 3.x
2. Install dependencies:

   ```bash
   cd test-server/ruby-v2-server
   bundle install
   ```

3. Set up AWS credentials (via AWS CLI, environment variables, or IAM roles)

4. Start the server:

   ```bash
   ruby app.rb
   # or using Rack
   bundle exec rackup -p 8086
   ```

## Usage

The server is designed to be used by the Java test suite in `test-server/java-tests/`.
The tests will automatically discover and use this server for cross-language compatibility testing.

### Environment Variables

- `TEST_SERVER_KMS_KEY_ARN` - KMS key ARN for encryption (defaults to test key)
- `TEST_SERVER_S3_BUCKET` - S3 bucket for testing (defaults to test bucket)

## Architecture

- `app.rb` - Main Sinatra application
- `lib/client_manager.rb` - Manages S3 encryption client instances
- `lib/metadata_utils.rb` - Handles metadata serialization/deserialization
- `lib/error_handlers.rb` - Smithy-compliant error responses

## Error Handling

The server returns errors in the format expected by the Smithy model:

- `GenericServerError` - Internal server errors
- `S3EncryptionClientError` - Errors from the S3 Encryption Client

## Compatibility

This server is compatible with:

- S3 Encryption Client v2
- Legacy v1 clients (when `enableLegacyWrappingAlgorithms` is true)
- Cross-language testing with other implementations
