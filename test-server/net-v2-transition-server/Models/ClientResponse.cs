using System.Text.Json.Serialization;

namespace NetV2TransitionServer.Models;

public class ClientResponse
{
    [JsonPropertyName("clientId")] public string ClientId { get; set; } = string.Empty;
}