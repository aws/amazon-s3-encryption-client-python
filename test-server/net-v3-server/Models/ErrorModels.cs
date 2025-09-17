namespace NetV3Server.Models;

public class GenericServerError
{
    public string __type { get; set; } = "software.amazon.encryption.s3#GenericServerError";
    public string Message { get; set; } = string.Empty;
}

public class S3EncryptionClientError
{
    public string __type { get; set; } = "software.amazon.encryption.s3#S3EncryptionClientError";
    public string Message { get; set; } = string.Empty;
}
