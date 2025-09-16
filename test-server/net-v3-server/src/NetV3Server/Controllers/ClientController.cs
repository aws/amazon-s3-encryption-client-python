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
            var enableLegacyWrappingAlgorithms = request.Config.EnableLegacyUnauthenticatedModes;


            var encryptionContext = new Dictionary<string, string>();

            // Create encryption materials
            var encryptionMaterial = new EncryptionMaterialsV2(kmsKeyId, KmsType.KmsContext, encryptionContext);

            // Create S3 encryption client
            var configuration = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
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