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
    operations: [ReEncrypt]
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

        /// Encryption context/materials description to use for this operation.
        /// For most SDKs (Java, .NET, etc.), materials description is embedded in the keyring/materials
        /// during client creation and this parameter is typically empty/unused.
        /// 
        /// For C++ SDK: Materials description MUST be passed per-operation via this parameter
        /// because the C++ SDK's EncryptionMaterials constructor does not accept materials description.
        /// Instead, GetObject/PutObject operations accept a contextMap parameter that becomes the
        /// materials description.
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
        
        /// Encryption context/materials description to use for this operation.
        /// For most SDKs (Java, .NET, etc.), materials description is embedded in the keyring/materials
        /// during client creation and this parameter is typically empty/unused.
        /// 
        /// For C++ SDK: Materials description MUST be passed per-operation via this parameter
        /// because the C++ SDK's EncryptionMaterials constructor does not accept materials description.
        /// Instead, GetObject/PutObject operations accept a contextMap parameter that becomes the
        /// materials description.
        @httpHeader("Content-Metadata")
        $metadata

        @httpHeader("ClientID")
        @required
        @notProperty
        clientID: String

        @httpHeader("Range")
        @notProperty
        range: String

        /// Custom instruction file suffix to use when reading instruction files
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

@http(method: "POST", uri: "/object/{bucket}/{key}/reencrypt")
operation ReEncrypt {
    input := for Object {
        @httpLabel
        @required
        $bucket

        @httpLabel
        @required
        $key

        @httpHeader("ClientID")
        @required
        @notProperty
        clientID: String

        /// New key material to use for re-encryption
        @httpPayload
        @required
        @notProperty
        newKeyMaterial: KeyMaterial

        /// Custom instruction file suffix for RSA keyring re-encryption
        @httpHeader("InstructionFileSuffix")
        @notProperty
        instructionFileSuffix: String

        /// Whether to enforce rotation by verifying the key has changed
        @httpHeader("EnforceRotation")
        @notProperty
        enforceRotation: Boolean
    }

    output := {
        @required
        bucket: String

        @required
        key: String

        @notProperty
        instructionFileSuffix: String
        
        @notProperty
        enforceRotation: Boolean
    }
}

/// Smithy does not know how to serialize a map 
list ObjectMetadata {
    member: String
}

/// Seems like Streaming is broken in Java.
///@streaming
blob StreamingBlob
