using Amazon.Extensions.S3.Encryption;
using System.Collections.Concurrent;

namespace NetV4ImprovedServer.Services;

public interface IClientCacheService
{
    string AddClient(AmazonS3EncryptionClientV4 client);
    AmazonS3EncryptionClientV4? GetClient(string clientId);
}

public class ClientCacheService : IClientCacheService
{
    private readonly ConcurrentDictionary<string, AmazonS3EncryptionClientV4> _clients = new();

    public string AddClient(AmazonS3EncryptionClientV4 client)
    {
        var clientId = Guid.NewGuid().ToString();
        _clients[clientId] = client;
        return clientId;
    }

    public AmazonS3EncryptionClientV4? GetClient(string clientId)
    {
        _clients.TryGetValue(clientId, out var client);
        return client;
    }
}
