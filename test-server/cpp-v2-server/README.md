# C++ S3 Encryption Test Server

Minimal C++ implementation of the S3 Encryption test server.

## Dependencies

- libmicrohttpd
- AWS SDK for C++
- nlohmann/json
- uuid

On MacOS you can
```bash
brew install libmicrohttpd nlohmann-json ossp-uuid
```

## Build

```bash
mkdir build && cd build
cmake ..
make
```

## Run

```bash
./s3ec-server
```

Server runs on localhost:8081

## API Endpoints

- `POST /client` - Create S3 encryption client
- `GET /object/{bucket}/{key}` - Get encrypted object  
- `PUT /object/{bucket}/{key}` - Put encrypted object