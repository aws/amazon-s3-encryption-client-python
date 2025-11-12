using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace NetV4Server.Models;

public class ClientRequest
{
    [Required]
    public ClientConfig Config { get; set; } = new();
}

public class ClientConfig
{
    public bool? EnableLegacyUnauthenticatedModes { get; set; }
    public bool? EnableLegacyWrappingAlgorithms { get; set; } 
    public bool? EnableDelayedAuthenticationMode { get; set; }
    public long? SetBufferSize { get; set; }
    [Required]
    public KeyMaterial KeyMaterial { get; set; } = new();
    [JsonPropertyName("commitmentPolicy")]
    public CommitmentPolicy? CommitmentPolicy { get; set; }
    [JsonPropertyName("encryptionAlgorithm")]
    public EncryptionAlgorithm? EncryptionAlgorithm { get; set; }
}

public class KeyMaterial
{
    public byte[]? RsaKey { get; set; }
    public byte[]? AesKey { get; set; }
    public string? KmsKeyId { get; set; }
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CommitmentPolicy
{
    REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    REQUIRE_ENCRYPT_ALLOW_DECRYPT,
    FORBID_ENCRYPT_ALLOW_DECRYPT
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EncryptionAlgorithm
{
    ALG_AES_256_CBC_IV16_NO_KDF,
    ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
    ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
}