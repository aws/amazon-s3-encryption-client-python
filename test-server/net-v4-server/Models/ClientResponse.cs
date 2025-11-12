using System.Text.Json.Serialization;

namespace NetV4Server.Models;

public class ClientResponse
{
    [JsonPropertyName("clientId")] public string ClientId { get; set; } = string.Empty;
}