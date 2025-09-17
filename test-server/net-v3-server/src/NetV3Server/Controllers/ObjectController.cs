using System.Text.Json;
using Amazon.S3.Model;
using Microsoft.AspNetCore.Mvc;
using NetV3Server.Models;
using NetV3Server.Services;

namespace NetV3Server.Controllers;

[ApiController]
[Route("[controller]")]
public class ObjectController(IClientCacheService clientCacheService) : ControllerBase
{
    [HttpPut("{bucket}/{key}")]
    public async Task<IActionResult> PutObject(string bucket, string key)
    {
        var clientId = Request.Headers["clientId"].FirstOrDefault();
        if (string.IsNullOrEmpty(clientId))
            return BadRequest(new GenericServerError { Message = "ClientID header is required" });

        var client = clientCacheService.GetClient(clientId);
        if (client == null)
            return NotFound(new GenericServerError { Message = $"No client found for ClientID: {clientId}" });

        try
        {
            // Read raw body data
            using var memoryStream = new MemoryStream();
            await Request.Body.CopyToAsync(memoryStream);
            var bodyBytes = memoryStream.ToArray();

            // Create put request
            var putRequest = new PutObjectRequest
            {
                BucketName = bucket,
                Key = key,
                InputStream = new MemoryStream(bodyBytes)
            };

            await client.PutObjectAsync(putRequest);

            var response = new { bucket, key };

            return new ContentResult
            {
                Content = JsonSerializer.Serialize(response),
                ContentType = "application/json",
                StatusCode = 200
            };
        }
        catch (Exception ex)
        {
            return StatusCode(500, new S3EncryptionClientError { Message = $"Failed to put object: {ex.Message}" });
        }
    }

    [HttpGet("{bucket}/{key}")]
    public async Task<IActionResult> GetObject(string bucket, string key)
    {
        var clientId = Request.Headers["clientId"].FirstOrDefault();
        if (string.IsNullOrEmpty(clientId))
            return BadRequest(new GenericServerError { Message = "ClientID header is required" });

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
            var response = await client.GetObjectAsync(getRequest);
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
            return StatusCode(500, new S3EncryptionClientError { Message = ex.Message });
        }
    }
}