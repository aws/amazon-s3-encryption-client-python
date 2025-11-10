using System.Text.Json;
using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Microsoft.AspNetCore.Mvc;
using NetV3TransitionServer.Models;
using NetV3TransitionServer.Services;

namespace NetV3TransitionServer.Controllers;

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
        if (request.Config.KeyMaterial.AesKey != null)
            return StatusCode(501, new GenericServerError { Message = "AesKey not supported" });
        
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
                    "[NET-V3-Transitional] Created EncryptionMaterialsV2: KMS={KmsKeyId}",
                    kmsKeyId);
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
            } else
            {
                return StatusCode(501, new GenericServerError { Message = "Unknown or missing key material!" });
            }

            var enableLegacyUnauthenticatedModes = request.Config.EnableLegacyUnauthenticatedModes;
            var enableLegacyWrappingAlgorithms = request.Config.EnableLegacyWrappingAlgorithms;
            var commitmentPolicy = MapCommitmentPolicy(request.Config.CommitmentPolicy);
            
            // SecurityProfile V2AndLegacy can decrypt from legacy S3EC but V2 cannot
            var enableLegacyMode = enableLegacyUnauthenticatedModes || enableLegacyWrappingAlgorithms;
            var securityProfile = enableLegacyMode ? SecurityProfile.V2AndLegacy : SecurityProfile.V2;
            logger.LogInformation("[NET-V3-Transitional] Created securityProfile= {securityProfile}", securityProfile.ToString());

            var encryptionAlgorithm = MapEncryptionAlgorithm(request.Config.EncryptionAlgorithm);
            // var encryptionAlgorithm = commitmentPolicy == Amazon.Extensions.S3.Encryption.CommitmentPolicy.ForbidEncryptAllowDecrypt ? ContentEncryptionAlgorithm.AesGcm : ContentEncryptionAlgorithm.AesGcmWithCommitment;
            logger.LogInformation("[NET-V3-Transitional] Created commitmentPolicy= {commitmentPolicy}", commitmentPolicy);
            logger.LogInformation("[NET-V3-Transitional] Created encryptionAlgorithm= {encryptionAlgorithm}", encryptionAlgorithm);

            var configuration = new AmazonS3CryptoConfigurationV2(securityProfile, commitmentPolicy, encryptionAlgorithm);
            // Create S3 encryption client
            var encryptionClient = new AmazonS3EncryptionClientV2(configuration, encryptionMaterial);
            // Add to cache and return client ID
            var clientId = clientCacheService.AddClient(encryptionClient);
            var response = new ClientResponse { ClientId = clientId };

            logger.LogInformation("[NET-V3-Transitional] Created S3EC client with ID: {clientId}", clientId);

            return new ContentResult
            {
                Content = JsonSerializer.Serialize(response),
                ContentType = "application/json",
                StatusCode = 200
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[NET-V3-Transitional] Failed to create S3EC client");
            return StatusCode(500, new S3EncryptionClientError
            {
                Message = $"Failed to create client: {ex.Message}"
            });
        }
    }

    private static Amazon.Extensions.S3.Encryption.CommitmentPolicy MapCommitmentPolicy(Models.CommitmentPolicy? policy)
    {
        return policy switch
        {
            Models.CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT => Amazon.Extensions.S3.Encryption.CommitmentPolicy.RequireEncryptRequireDecrypt,
            Models.CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT => Amazon.Extensions.S3.Encryption.CommitmentPolicy.RequireEncryptAllowDecrypt,
            Models.CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT => Amazon.Extensions.S3.Encryption.CommitmentPolicy.ForbidEncryptAllowDecrypt,
            _ => Amazon.Extensions.S3.Encryption.CommitmentPolicy.ForbidEncryptAllowDecrypt
        };
    }

    // This is redundant but useful when tests starts sending EncryptionAlgorithm
    private static ContentEncryptionAlgorithm MapEncryptionAlgorithm(Models.EncryptionAlgorithm? algorithm)
    {
        return algorithm switch
        {
            Models.EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF => ContentEncryptionAlgorithm.AesGcm,
            Models.EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY => ContentEncryptionAlgorithm.AesGcmWithCommitment,
            _ => ContentEncryptionAlgorithm.AesGcm
        };
    }
}