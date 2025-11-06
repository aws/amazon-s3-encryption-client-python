$version: "2.0"

namespace software.amazon.encryption.s3

/// Represents an S3-like bucket
///resource Bucket {
///    identifiers: {
///        bucketName: String
///    }
///}

/// Represents an S3-like object
resource Object {
    identifiers: {
        bucket: String
        key: String
    }
    properties: {
        body: StreamingBlob
        metadata: ObjectMetadata
    }
    read: GetObject
    put: PutObject
}

@idempotent
@http(method: "PUT", uri: "/object/{bucket}/{key}")
operation PutObject {
    input := for Object {
        @httpLabel
        @required
        $bucket

        @httpLabel
        @required
        $key

        @httpHeader("Content-Metadata")
        $metadata

        @required
        @httpPayload
        $body

        @httpHeader("ClientID")
        @required
        @notProperty
        clientID: String
    }

    output := for Object {
        @required
        $bucket

        @required
        $key

        @required
        $metadata
    }
}

@readonly
@http(method: "GET", uri: "/object/{bucket}/{key}")
operation GetObject {
    input := for Object {
        @httpLabel
        @required
        $bucket

        @httpLabel
        @required
        $key
        
        /// Should probably be renamed to be EC specific
        @httpHeader("Content-Metadata")
        $metadata

        @httpHeader("ClientID")
        @required
        @notProperty
        clientID: String
    } 

    output := for Object {
        @httpHeader("Content-Metadata")
        @required
        $metadata

        @required
        @httpPayload
        $body
    }
}

@readonly
@http(method: "GET", uri: "/object/{bucket}/{key}")
operation ReEncrypt {
    input := for Object {
        @httpLabel
        @required
        $bucket

        @httpLabel
        @required
        $key
        
        /// Should probably be renamed to be EC specific
        @httpHeader("Content-Metadata")
        $metadata

        @httpHeader("ClientID")
        @required
        @notProperty
        clientID: String

        /// Custom instruction file suffix
        @httpHeader("InstructionFileSuffix")
        @notProperty
        instructionFileSuffix: String
    } 

    output := for Object {
        @httpHeader("Content-Metadata")
        @required
        $metadata

        @required
        @httpPayload
        $body
    }
}

/// Smithy does not know how to serialize a map 
list ObjectMetadata {
    member: String
}

/// Seems like Streaming is broken in Java.
///@streaming
blob StreamingBlob
