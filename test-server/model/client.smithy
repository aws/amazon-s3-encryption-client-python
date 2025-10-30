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

enum CommitmentPolicy {
    REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    REQUIRE_ENCRYPT_ALLOW_DECRYPT
    FORBID_ENCRYPT_ALLOW_DECRYPT
}

enum EncryptionAlgorithm {
    ALG_AES_256_CBC_IV16_NO_KDF
    ALG_AES_256_GCM_IV12_TAG16_NO_KDF
    ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
}

structure InstructionFileConfig {
    clientId: String,
    enableInstructionFilePutObject: Boolean = false,
    disableInstructionFile: Boolean = false
}

structure S3ECConfig {
    enableLegacyUnauthenticatedModes: Boolean = false,
    enableDelayedAuthenticationMode: Boolean = false,
    enableLegacyWrappingAlgorithms: Boolean = false,
    setBufferSize: Long,
    keyMaterial: KeyMaterial,
    commitmentPolicy: CommitmentPolicy,
    encryptionAlgorithm: EncryptionAlgorithm,
    instructionFileConfig: InstructionFileConfig,
}
