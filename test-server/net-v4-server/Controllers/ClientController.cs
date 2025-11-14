using System.Security.Cryptography;
using System.Text.Json;
using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Microsoft.AspNetCore.Mvc;
using NetV4Server.Models;
using NetV4Server.Services;

namespace NetV4Server.Controllers;

[ApiController]
[Route("[controller]")]
public class ClientController(IClientCacheService clientCacheService, ILogger<ClientController> logger) : ControllerBase
{
    [HttpPost]
    public IActionResult CreateClient([FromBody] ClientRequest request)
    {
        // Return 501 for not implemented features by the server
        if (request.Config.EnableDelayedAuthenticationMode ?? false)
            return StatusCode(501, new GenericServerError { Message = "[NET-V4] EnableDelayedAuthenticationMode not supported" });
        if (request.Config.SetBufferSize.HasValue)
            return StatusCode(501, new GenericServerError { Message = "[NET-V4] SetBufferSize not supported" });
        if (request.Config.KeyMaterial.AesKey != null)
            return StatusCode(501, new GenericServerError { Message = "[NET-V4] AesKey not supported" });
        
        try
        {
            EncryptionMaterialsV4 encryptionMaterial;
            if (request.Config.KeyMaterial.KmsKeyId != null)
            {
                // The POST request does not contain encryption context.
                // However, encryption context is a required field when using KMS.
                // So, we are passing empty dictionary.
                var encryptionContext = new Dictionary<string, string>();
                var kmsKeyId = request.Config.KeyMaterial.KmsKeyId;
                encryptionMaterial = new EncryptionMaterialsV4(kmsKeyId, KmsType.KmsContext, encryptionContext);
                logger.LogInformation(
                    "[NET-V4] Created EncryptionMaterialsV4: KMS={KmsKeyId}",
                    kmsKeyId);
            }
            else if (request.Config.KeyMaterial.RsaKey != null)
            {
                var rsaKeyBytes = request.Config.KeyMaterial.RsaKey;
                var rsaKey = RSA.Create();
                rsaKey.ImportPkcs8PrivateKey(new ReadOnlySpan<byte>(rsaKeyBytes), out _);
                encryptionMaterial = new EncryptionMaterialsV4(rsaKey, AsymmetricAlgorithmType.RsaOaepSha1);
                logger.LogInformation(
                    "[NET-V4] Created EncryptionMaterialsV4: RSA");
            } else
            {
                return StatusCode(501, new GenericServerError { Message = "[NET-V4] Unknown or missing key material!" });
            }
            var enableLegacyUnauthenticatedModes = request.Config.EnableLegacyUnauthenticatedModes ?? false;
            var enableLegacyWrappingAlgorithms = request.Config.EnableLegacyWrappingAlgorithms ?? false;
            var commitmentPolicy = MapCommitmentPolicy(request.Config.CommitmentPolicy);
            var isSecurityProfileProvided = request.Config.EnableLegacyUnauthenticatedModes.HasValue || request.Config.EnableLegacyWrappingAlgorithms.HasValue;
            var isCommitmentPolicyProvided = request.Config.CommitmentPolicy.HasValue;
            var useDefaultConf = !isCommitmentPolicyProvided;

            logger.LogInformation("[NET-V4] isSecurityProfileProvided: {isSecurityProfileProvided}, isCommitmentPolicyProvided: {isCommitmentPolicyProvided}, useDefaultConf: {useDefaultConf}", isSecurityProfileProvided, isCommitmentPolicyProvided, useDefaultConf);
            
            // SecurityProfile V4AndLegacy can decrypt from legacy S3EC but V4 cannot
            var enableLegacyMode = enableLegacyUnauthenticatedModes || enableLegacyWrappingAlgorithms;
            var securityProfile = enableLegacyMode ? SecurityProfile.V4AndLegacy : SecurityProfile.V4;

            var encryptionAlgorithm = MapEncryptionAlgorithm(request.Config.EncryptionAlgorithm);
            
            if (!useDefaultConf)
            {
                logger.LogInformation("[NET-V4] Created securityProfile= {securityProfile}", securityProfile.ToString());
                logger.LogInformation("[NET-V4] Created commitmentPolicy= {commitmentPolicy}", commitmentPolicy);
                logger.LogInformation("[NET-V4] Created encryptionAlgorithm= {encryptionAlgorithm}", encryptionAlgorithm);
            } else
            {
                logger.LogInformation("[NET-V4] Using default configuration for securityProfile, commitmentPolicy and encryptionAlgorithm");
            }

            var configuration = useDefaultConf
                ? new AmazonS3CryptoConfigurationV4() 
                : new AmazonS3CryptoConfigurationV4(securityProfile, commitmentPolicy, encryptionAlgorithm);
            
            if (request.Config.InstructionFileConfig?.EnableInstructionFilePutObject == true)
            {
                configuration.StorageMode = CryptoStorageMode.InstructionFile;
                logger.LogInformation("[NET-V3-Transitional] Created StorageMode= InstructionFile");
            }
            
            // Create S3 encryption client
            var encryptionClient = new AmazonS3EncryptionClientV4(configuration, encryptionMaterial);
            // Add to cache and return client ID
            var clientId = clientCacheService.AddClient(encryptionClient);
            var response = new ClientResponse { ClientId = clientId };

            logger.LogInformation("[NET-V4] Created S3EC client with ID: {clientId}", clientId);

            return new ContentResult
            {
                Content = JsonSerializer.Serialize(response),
                ContentType = "application/json",
                StatusCode = 200
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[NET-V4] Failed to create S3EC client");
            return StatusCode(500, new S3EncryptionClientError
            {
                Message = $"[NET-V4] Failed to create client: {ex.Message}"
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
            _ => Amazon.Extensions.S3.Encryption.CommitmentPolicy.RequireEncryptRequireDecrypt
        };
    }

    private static ContentEncryptionAlgorithm MapEncryptionAlgorithm(Models.EncryptionAlgorithm? algorithm)
    {
        return algorithm switch
        {
            Models.EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF => ContentEncryptionAlgorithm.AesGcm,
            Models.EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY => ContentEncryptionAlgorithm.AesGcmWithCommitment,
            _ => ContentEncryptionAlgorithm.AesGcmWithCommitment
        };
    }
}