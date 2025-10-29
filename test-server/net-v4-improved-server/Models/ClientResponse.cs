using System.Text.Json.Serialization;

namespace NetV4ImprovedServer.Models;

public class ClientResponse
{
    [JsonPropertyName("clientId")] public string ClientId { get; set; } = string.Empty;
}