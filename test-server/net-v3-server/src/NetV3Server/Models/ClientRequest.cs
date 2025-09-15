namespace NetV3Server.Models;

public class ClientRequest
{
    public ClientConfig Config { get; set; } = new();
}

public class ClientConfig
{
    public bool EnableLegacyUnauthenticatedModes { get; set; }
    public bool EnableDelayedAuthenticationMode { get; set; }
    public bool EnableLegacyWrappingAlgorithms { get; set; }
    public KeyMaterial KeyMaterial { get; set; } = new();
}

public class KeyMaterial
{
    public string KmsKeyId { get; set; } = string.Empty;
}
