namespace NetV2V3Server.Models;

public class GenericServerError
{
    [JsonPropertyName("__type")]
    public string Type { get; set; } = "software.amazon.encryption.s3#GenericServerError";
    public string Message { get; set; } = string.Empty;
}

public class S3EncryptionClientError
{
    [JsonPropertyName("__type")]
    public string Type { get; set; } = "software.amazon.encryption.s3#S3EncryptionClientError";
    public string Message { get; set; } = string.Empty;
}
