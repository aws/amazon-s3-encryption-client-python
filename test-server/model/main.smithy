$version: "2"

namespace software.amazon.encryption.s3

use aws.protocols#restJson1

@title("S3 Encryption Client Test Service")
@restJson1
service S3ECTestServer {
    version: "2024-08-23"
    operations: [
        CreateClient
    ]
    resources: [
        Object
    ]
    errors: [GenericServerError, S3EncryptionClientError]
}

/// Used for "internal" errors, e.g. problems with the test server itself
/// Tests MUST NOT expect this error in negative tests.
@error("server")
structure GenericServerError {
    @required
    message: String
}

/// Used for modeled errors, e.g. errors thrown by the S3EC
/// Tests SHOULD expect this error in negative tests.
@error("server")
structure S3EncryptionClientError {
    @required
    message: String
}
