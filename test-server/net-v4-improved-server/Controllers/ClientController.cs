using System.Text.Json;
using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Microsoft.AspNetCore.Mvc;
using NetV2V3Server.Models;
using NetV2V3Server.Services;

namespace NetV2V3Server.Controllers;

[ApiController]
[Route("[controller]")]
public class ClientController(IClientCacheService clientCacheService, ILogger<ClientController> logger) : ControllerBase
{
    [HttpPost]
    public IActionResult CreateClient([FromBody] ClientRequest request)
    {
        // Return 501 for not implemented features by the server
        if (request.Config.EnableDelayedAuthenticationMode)
            return StatusCode(501, new GenericServerError { Message = "EnableDelayedAuthenticationMode not supported" });
        if (request.Config.SetBufferSize.HasValue)
            return StatusCode(501, new GenericServerError { Message = "SetBufferSize not supported" });
        if (request.Config.KeyMaterial.RsaKey != null)
            return StatusCode(501, new GenericServerError { Message = "RsaKey not supported" });
        if (request.Config.KeyMaterial.AesKey != null)
            return StatusCode(501, new GenericServerError { Message = "AesKey not supported" });

        var kmsKeyId = request.Config.KeyMaterial.KmsKeyId;
        var enableLegacyUnauthenticatedModes = request.Config.EnableLegacyUnauthenticatedModes;
        var enableLegacyWrappingAlgorithms = request.Config.EnableLegacyWrappingAlgorithms;
        
        try
        {
            // Parse CommitmentPolicy enum
            CommitmentPolicy? commitmentPolicy = null;
            if (!string.IsNullOrEmpty(request.Config.CommitmentPolicy))
            {
                commitmentPolicy = request.Config.CommitmentPolicy switch
                {
                    "FORBID_ENCRYPT_ALLOW_DECRYPT" => CommitmentPolicy.ForbidEncryptAllowDecrypt,
                    "REQUIRE_ENCRYPT_ALLOW_DECRYPT" => CommitmentPolicy.RequireEncryptAllowDecrypt,
                    "REQUIRE_ENCRYPT_REQUIRE_DECRYPT" => CommitmentPolicy.RequireEncryptRequireDecrypt,
                    _ => throw new ArgumentException($"Unsupported CommitmentPolicy: {request.Config.CommitmentPolicy}")
                };
            }

            // Parse EncryptionAlgorithm enum
            ContentEncryptionAlgorithm? encryptionAlgorithm = null;
            if (!string.IsNullOrEmpty(request.Config.EncryptionAlgorithm))
            {
                encryptionAlgorithm = request.Config.EncryptionAlgorithm switch
                {
                    "AES_GCM" => ContentEncryptionAlgorithm.AesGcm,
                    "AES_GCM_WITH_COMMITMENT" => ContentEncryptionAlgorithm.AesGcmWithCommitment,
                    _ => throw new ArgumentException($"Unsupported EncryptionAlgorithm: {request.Config.EncryptionAlgorithm}")
                };
            }

            // The POST request does not contain encryption context. 
            // However, encryption context is a required field when using KMS.
            // So, we are passing empty dictionary.
            var encryptionContext = new Dictionary<string, string>();
            var encryptionMaterial = new EncryptionMaterialsV2(kmsKeyId, KmsType.KmsContext, encryptionContext);
            logger.LogInformation(
                "Created EncryptionMaterialsV2: KMS={KmsKeyId}",
                kmsKeyId);
            // SecurityProfile V2AndLegacy can decrypt from legacy S3EC but V2 cannot
            var enableLegacyMode = enableLegacyUnauthenticatedModes || enableLegacyWrappingAlgorithms;
            var securityProfile = enableLegacyMode ? SecurityProfile.V4AndLegacy : SecurityProfile.V4;

            logger.LogInformation("Created AmazonS3CryptoConfigurationV4 with security profile: {securityProfile}," + 
                "commitmentPolicy: {commitmentPolicy}, encryptionAlgorithm: {encryptionAlgorithm}", securityProfile.ToString(), commitmentPolicy.Value, encryptionAlgorithm.Value);

            var configuration = new AmazonS3CryptoConfigurationV4(securityProfile, commitmentPolicy.Value, encryptionAlgorithm.Value);

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