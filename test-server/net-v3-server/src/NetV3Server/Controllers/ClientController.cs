using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Microsoft.AspNetCore.Mvc;
using NetV3Server.Models;
using NetV3Server.Services;

namespace NetV3Server.Controllers;

[ApiController]
[Route("[controller]")]
public class ClientController : ControllerBase
{
    private readonly IClientCacheService _clientCacheService;

    public ClientController(IClientCacheService clientCacheService)
    {
        _clientCacheService = clientCacheService;
    }

    [HttpPost]
    public async Task<IActionResult> CreateClient([FromBody] ClientRequest request)
    {
        try
        {
            var kmsKeyId = request.Config.KeyMaterial.KmsKeyId;
            var enableLegacyMode = request.Config.EnableLegacyMode;
            var encryptionContext = new Dictionary<string, string>();
            var encryptionMaterial = new EncryptionMaterialsV2(kmsKeyId, KmsType.KmsContext, encryptionContext);
            // SecurityProfile V2AndLegacy can decrypt from legacy S3EC while V2 cannot
            var securityProfile = enableLegacyMode ? SecurityProfile.V2AndLegacy : SecurityProfile.V2;
            var configuration = new AmazonS3CryptoConfigurationV2(securityProfile);
            // Create S3 encryption client
            var encryptionClient = new AmazonS3EncryptionClientV2(configuration, encryptionMaterial);
            // Add to cache and return client ID
            var clientId = _clientCacheService.AddClient(encryptionClient);
            return Ok(new ClientResponse { ClientId = clientId });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new S3EncryptionClientError
            {
                Message = $"Failed to create client: {ex.Message}"
            });
        }
    }
}