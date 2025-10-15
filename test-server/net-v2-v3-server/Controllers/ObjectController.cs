using System.Text.Json;
#if S3EC_V3
using Amazon.Extensions.S3.Encryption.Extensions;
#endif
using Amazon.S3.Model;
using Microsoft.AspNetCore.Mvc;
using NetV2V3Server.Models;
using NetV2V3Server.Services;

namespace NetV2V3Server.Controllers;

[ApiController]
[Route("[controller]")]
public class ObjectController(IClientCacheService clientCacheService, ILogger<ObjectController> logger) : ControllerBase
{
    [HttpPut("{bucket}/{key}")]
    public async Task<IActionResult> PutObject(string bucket, string key)
    {
        logger.LogInformation("Starting PutObject");
        var clientId = Request.Headers["clientId"].FirstOrDefault();
        if (string.IsNullOrEmpty(clientId))
            return BadRequest(new GenericServerError { Message = "ClientID header is required" });

        var client = clientCacheService.GetClient(clientId);
        if (client == null)
            return NotFound(new GenericServerError { Message = $"No client found for ClientID: {clientId}" });
        
        var contentMetadataString = Request.Headers["content-metadata"].FirstOrDefault();
        var ec = ParseEncryptionContext(contentMetadataString);
        
        try
        {
            // Read raw body data
            using var memoryStream = new MemoryStream();
            // Request is the HTTP request this method is currently handling 
            await Request.Body.CopyToAsync(memoryStream);
            var bodyBytes = memoryStream.ToArray();

            // Create put request
            var putRequest = new PutObjectRequest
            {
                BucketName = bucket,
                Key = key,
                InputStream = new MemoryStream(bodyBytes)
            };
#if S3EC_V3
            putRequest.SetEncryptionContext(ec);
#endif
            await client.PutObjectAsync(putRequest);

            var response = new { bucket, key };

            logger.LogInformation(
                "Put object succeeded for bucket={bucket}, key={key} and clientId = {clientId}",
                bucket, key, clientId);
            return new ContentResult
            {
                Content = JsonSerializer.Serialize(response),
                ContentType = "application/json",
                StatusCode = 200
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to put object from S3 for bucket={bucket}, key={key}", bucket, key);
            return StatusCode(500, new S3EncryptionClientError { Message = $"Failed to put object: {ex.Message}" });
        }
    }

    [HttpGet("{bucket}/{key}")]
    public async Task<IActionResult> GetObject(string bucket, string key)
    {
        logger.LogInformation("Starting GetObject");
        var clientId = Request.Headers["clientId"].FirstOrDefault();
        if (string.IsNullOrEmpty(clientId))
            return BadRequest(new GenericServerError { Message = "ClientID header is required" });
            
        var contentMetadataString = Request.Headers["content-metadata"].FirstOrDefault();
        var ec = ParseEncryptionContext(contentMetadataString);

        var client = clientCacheService.GetClient(clientId);
        if (client == null)
            return NotFound(new GenericServerError { Message = $"No client found for ClientID: {clientId}" });

        try
        {
            var getRequest = new GetObjectRequest
            {
                BucketName = bucket,
                Key = key
            };
#if S3EC_V3
           getRequest.SetEncryptionContext(ec);
#endif
            var response = await client.GetObjectAsync(getRequest);
            logger.LogInformation("Got object from S3 for bucket={bucket}, key={key}", bucket, key);
            // Read response body
            using var memoryStream = new MemoryStream();
            await response.ResponseStream.CopyToAsync(memoryStream);
            var bodyBytes = memoryStream.ToArray();

            // Convert metadata to content-metadata header format
            var metadataList = response.Metadata.Keys
                .Select(metaDataKey => $"{metaDataKey}={response.Metadata[metaDataKey]}")
                .ToList();
            var metadataStr = string.Join(",", metadataList);

            // Set response headers
            Response.Headers["Content-Metadata"] = metadataStr;

            return File(bodyBytes, "application/octet-stream");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to get object from S3 for bucket={bucket}, key={key}", bucket, key);
            return StatusCode(500, new S3EncryptionClientError { Message = ex.Message });
        }
    }
    
    private static Dictionary<string, string> ParseEncryptionContext(string encryptionContextStr)
    {
        if (string.IsNullOrEmpty(encryptionContextStr))
            return null;
        
        var result = new Dictionary<string, string>();
        var pairs = encryptionContextStr.Split(',');
        foreach (var pair in pairs)
        {
            var parts = pair.Split(':', 2);
            if (parts.Length == 2)
            {
                var key = parts[0].Trim('[', ']');
                var value = parts[1].Trim('[', ']');
                result.Add(key, value);
            }
        }

        return result;
    }
}