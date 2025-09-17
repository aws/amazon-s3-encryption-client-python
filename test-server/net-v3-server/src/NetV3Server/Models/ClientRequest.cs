namespace NetV3Server.Models;

public class ClientRequest
{
    public ClientConfig Config { get; set; } = new();
}

public class ClientConfig
{
    public Dictionary<string, string> EncryptionContext { get; set; } = new();
    public bool EnableLegacyMode { get; set; }
    public KeyMaterial KeyMaterial { get; set; } = new();
}

public class KeyMaterial
{
    public string KmsKeyId { get; set; } = string.Empty;
}