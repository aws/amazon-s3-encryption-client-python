using System.Text.Json;
using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Microsoft.AspNetCore.Mvc;
using NetV3Server.Models;
using NetV3Server.Services;

namespace NetV3Server.Controllers;

[ApiController]
[Route("[controller]")]
public class ClientController(IClientCacheService clientCacheService, ILogger<ClientController> logger) : ControllerBase
{
    [HttpPost]
    public IActionResult CreateClient([FromBody] ClientRequest request)
    {
        try
        {
            var kmsKeyId = request.Config.KeyMaterial.KmsKeyId;
            var enableLegacyUnauthenticatedModes = request.Config.EnableLegacyUnauthenticatedModes;
            var enableLegacyWrappingAlgorithms = request.Config.EnableLegacyWrappingAlgorithms;
            var encryptionContext = request.Config.EncryptionContext;
            var encryptionMaterial = new EncryptionMaterialsV2(kmsKeyId, KmsType.KmsContext, encryptionContext);
            logger.LogInformation(
                "Created EncryptionMaterialsV2: KMS={KmsKeyId}, Encryption Context={EncryptionContext}", 
                kmsKeyId, encryptionContext);
            // SecurityProfile V2AndLegacy can decrypt from legacy S3EC but V2 cannot
            var enableLegacyMode = enableLegacyUnauthenticatedModes || enableLegacyWrappingAlgorithms;
            var securityProfile = enableLegacyMode ? SecurityProfile.V2AndLegacy : SecurityProfile.V2;
            
            logger.LogInformation("Created securityProfile= {securityProfile}", securityProfile.ToString()); 
            
            var configuration = new AmazonS3CryptoConfigurationV2(securityProfile);
            // Create S3 encryption client
            var encryptionClient = new AmazonS3EncryptionClientV2(configuration, encryptionMaterial);
            // Add to cache and return client ID
            var clientId = clientCacheService.AddClient(encryptionClient);
            var response = new ClientResponse { ClientId = clientId };
            
            logger.LogInformation("Created S3EC client with ID: {clientId}", clientId);
            
            return new ContentResult
            {
                Content = JsonSerializer.Serialize(response),
                ContentType = "application/json",
                StatusCode = 200
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to create S3EC client");
            return StatusCode(500, new S3EncryptionClientError
            {
                Message = $"Failed to create client: {ex.Message}"
            });
        }
    }
}