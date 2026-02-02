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
    kmsKeyId: String,
    /// Optional materials description for keyring differentiation
    /// Used to distinguish between different key materials for rotation enforcement
    materialsDescription: MaterialsDescriptionMap
}

/// Map of materials description key-value pairs
map MaterialsDescriptionMap {
    key: String,
    value: String
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
    /// This allows specifying a (non-encrypted) client for languages which
    /// support this for instruction files.
    /// In general, languages do not require specifying a client;
    /// they use the usual wrapped client for instruction file operations,
    /// so it is fine to leave it null for now.
    /// This also requires a way to create non-encrypted clients which we don't have yet.
    /// Some languages (Java) do allow a client to be passed specifically for instruction files,
    /// so this should be implemented eventually for full coverage,
    /// especially if other languages add this feature. Until then,
    /// the Java integ tests are sufficient.
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
