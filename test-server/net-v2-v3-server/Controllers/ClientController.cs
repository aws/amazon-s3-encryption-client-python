using System.Net;
using System.Security.Cryptography;
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
            return StatusCode(501, new GenericServerError { Message = "[NET-current] EnableDelayedAuthenticationMode not supported" });
        if (request.Config.SetBufferSize.HasValue)
            return StatusCode(501, new GenericServerError { Message = "[NET-current] SetBufferSize not supported" });

        try
        {
            EncryptionMaterialsV2 encryptionMaterial;
            if (request.Config.KeyMaterial.KmsKeyId != null)
            {
                // The POST request does not contain encryption context. 
                // However, encryption context is a required field when using KMS.
                // So, we are passing empty dictionary.
                var encryptionContext = new Dictionary<string, string>();
                var kmsKeyId = request.Config.KeyMaterial.KmsKeyId;
                encryptionMaterial = new EncryptionMaterialsV2(kmsKeyId, KmsType.KmsContext, encryptionContext);
                logger.LogInformation(
                    "[NET-current] Created EncryptionMaterialsV2: KMS={KmsKeyId}",
                kmsKeyId);
            }
            else if (request.Config.KeyMaterial.RsaKey != null)
            {
                var rsaKeyBytes = request.Config.KeyMaterial.RsaKey;
                var rsaKey = RSA.Create();
                rsaKey.ImportPkcs8PrivateKey(new ReadOnlySpan<byte>(rsaKeyBytes), out _);
                encryptionMaterial = new EncryptionMaterialsV2(rsaKey, AsymmetricAlgorithmType.RsaOaepSha1);
                logger.LogInformation(
                    "Created EncryptionMaterialsV2: RSA");
            }
            else if (request.Config.KeyMaterial.AesKey != null)
            {
                var aesKeyBytes = request.Config.KeyMaterial.AesKey;
                var aes = Aes.Create();
                aes.Key = aesKeyBytes;
                encryptionMaterial = new EncryptionMaterialsV2(aes, SymmetricAlgorithmType.AesGcm);
                logger.LogInformation(
                    "[NET-current] Created EncryptionMaterialsV2: AES");
            } else
            {
                return StatusCode(501, new GenericServerError { Message = "[NET-current] Unknown or missing key material!" });
            }

            var enableLegacyUnauthenticatedModes = request.Config.EnableLegacyUnauthenticatedModes;
            var enableLegacyWrappingAlgorithms = request.Config.EnableLegacyWrappingAlgorithms;

            // SecurityProfile V2AndLegacy can decrypt from legacy S3EC but V2 cannot
            var enableLegacyMode = enableLegacyUnauthenticatedModes || enableLegacyWrappingAlgorithms;
            var securityProfile = enableLegacyMode ? SecurityProfile.V2AndLegacy : SecurityProfile.V2;

            logger.LogInformation("[NET-current] Created securityProfile= {securityProfile}", securityProfile.ToString());

            var configuration = new AmazonS3CryptoConfigurationV2(securityProfile);
            if (request.Config.InstructionFileConfig?.EnableInstructionFilePutObject == true)
            // Add retry configuration for throttling
            configuration.RetryMode = Amazon.Runtime.RequestRetryMode.Adaptive;
            configuration.MaxErrorRetry = 5;

            {
                configuration.StorageMode = CryptoStorageMode.InstructionFile;
                logger.LogInformation("[NET-current] Created StorageMode= InstructionFile");
            }
            // Create S3 encryption client
            var encryptionClient = new AmazonS3EncryptionClientV2(configuration, encryptionMaterial);
            // Add to cache and return client ID
            var clientId = clientCacheService.AddClient(encryptionClient);
            var response = new ClientResponse { ClientId = clientId };

            logger.LogInformation("[NET-current] Created S3EC client with ID: {clientId}", clientId);

            return new ContentResult
            {
                Content = JsonSerializer.Serialize(response),
                ContentType = "application/json",
                StatusCode = 200
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[NET-current] Failed to create S3EC client");
            return StatusCode(500, new S3EncryptionClientError
            {
                Message = $"[NET-current] Failed to create client: {ex.Message}"
            });
        }
    }
}
