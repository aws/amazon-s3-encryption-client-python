$version: "2.0"

namespace software.amazon.encryption.s3

/// Client Creation/Configuration
@http(method: "POST", uri: "/client")
operation CreateClient {
    input: CreateClientInput,
    output: CreateClientOutput,
}

@input
structure CreateClientInput {
    config: S3ECConfig,
}

@output
structure CreateClientOutput {
    clientId: String,
}

/// Since it's possible to pass this directly, include it separately
/// Probably also need a Keyring structure to signal when to create Keyrings directly
/// Or maybe KeyringConfig
structure KeyMaterial {
    rsaKey: Blob,
    aesKey: Blob,
    kmsKeyId: String
}

structure S3ECConfig {
    enableLegacyUnauthenticatedModes: Boolean = false,
    enableDelayedAuthenticationMode: Boolean = false,
    enableLegacyWrappingAlgorithms: Boolean = false,
    setBufferSize: Long,
    keyMaterial: KeyMaterial
}
