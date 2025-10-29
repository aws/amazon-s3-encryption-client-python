# Net-V2-V3-Server

A .NET test server for Amazon S3 encryption client .NET v2 and v3.

## Project Structure

```
net-v2-v3-server/
├── Controllers/         # API controllers
├── Models/              # Data models
├── Services/            # Business logic services
├── Program.cs           # Application entry point
├── NetV2V3Server.csproj # Project file
└── README.md            # This file
```

## Running the Server

For S3 Encryption Client v2 (runs on port 8083):

```bash
dotnet run -p:S3EncryptionVersion=v2
```

For S3 Encryption Client v3 (runs on port 8084):

```bash
dotnet run -p:S3EncryptionVersion=v3
```

## API Endpoints

### Client Management

- `POST /Client` - Create a new S3 encryption client

### Object Operations

- `PUT /{bucket}/{key}` - Upload an encrypted object to S3
- `GET /{bucket}/{key}` - Download and decrypt an object from S3

All object operations require a `clientId` header to specify which client to use.

## Example Usage

### Create a Client

```bash
curl -i -X POST \
 -H "Content-Type: application/json" \
 -H "User-Agent: smithy-java/0.0.3 ua/2.1 os/macos#15.5 lang/java#23.0.2" \
 -d '{"config":{"keyMaterial":{"kmsKeyId":"arn:aws:kms:us-west-2:370957321024:alias/S3EC-Test-Server-Github-KMS-Key"}, "encryptionContext": {"abc": "b"}, "CommitmentPolicy":"FORBID_ENCRYPT_ALLOW_DECRYPT"}}' \
    http://localhost:8090/client
```

### Upload an Object

```bash
curl -X PUT \
  -H "clientid: 7978763a-a02b-4dea-a5d4-78ef11d13d12" \
  -H "content-type: application/octet-stream" \
  -d "simple-test-input-net" \
  http://localhost:8083/object/s3ec-test-server-github-bucket/cross-lang-test-key-kms-ec-dotnet
```

### Download an Object

```bash
curl -X GET \
  -H "clientid: 7978763a-a02b-4dea-a5d4-78ef11d13d12" \
  http://localhost:8083/object/s3ec-test-server-github-bucket/cross-lang-test-key-kms-ec-dotnet
```
