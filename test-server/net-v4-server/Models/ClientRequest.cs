using System.ComponentModel.DataAnnotations;

namespace NetV4Server.Models;

public class ClientRequest
{
    [Required]
    public ClientConfig Config { get; set; } = new();
}

public class ClientConfig
{
    public bool EnableLegacyUnauthenticatedModes { get; set; } = false;
    public bool EnableLegacyWrappingAlgorithms { get; set; } = false;
    public bool EnableDelayedAuthenticationMode { get; set; } = false;
    public long? SetBufferSize { get; set; }
    [Required]
    public KeyMaterial KeyMaterial { get; set; } = new();
}

public class KeyMaterial
{
    public byte[]? RsaKey { get; set; }
    public byte[]? AesKey { get; set; }

    [Required]
    public string KmsKeyId { get; set; } = string.Empty;
}