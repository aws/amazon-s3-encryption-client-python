using Amazon.S3.Model;
using Microsoft.AspNetCore.Mvc;
using NetV3Server.Models;
using NetV3Server.Services;

namespace NetV3Server.Controllers;

[ApiController]
[Route("[controller]")]
public class ObjectController : ControllerBase
{
    private readonly IClientCacheService _clientCacheService;

    public ObjectController(IClientCacheService clientCacheService)
    {
        _clientCacheService = clientCacheService;
    }

    [HttpPut("{bucket}/{key}")]
    public async Task<IActionResult> PutObject(string bucket, string key)
    {
        var clientId = Request.Headers["ClientID"].FirstOrDefault();
        if (string.IsNullOrEmpty(clientId))
            return BadRequest(new GenericServerError { Message = "ClientID header is required" });

        var client = _clientCacheService.GetClient(clientId);
        if (client == null)
            return NotFound(new GenericServerError { Message = $"No client found for ClientID: {clientId}" });

        try
        {
            // Read raw body data
            using var memoryStream = new MemoryStream();
            await Request.Body.CopyToAsync(memoryStream);
            var bodyBytes = memoryStream.ToArray();

            // Parse encryption context from content-metadata header
            var contentMetadata = Request.Headers["Content-Metadata"].FirstOrDefault() ?? "";
            var encryptionContext = ParseMetadataString(contentMetadata);

            // Create put request
            var putRequest = new PutObjectRequest
            {
                BucketName = bucket,
                Key = key,
                InputStream = new MemoryStream(bodyBytes)
            };

            // Add encryption context to metadata
            foreach (var kvp in encryptionContext) putRequest.Metadata.Add(kvp.Key, kvp.Value);

            await client.PutObjectAsync(putRequest);

            return Ok(new { bucket, key, metadata = new string[0] });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new S3EncryptionClientError { Message = $"Failed to put object: {ex.Message}" });
        }
    }

    [HttpGet("{bucket}/{key}")]
    public async Task<IActionResult> GetObject(string bucket, string key)
    {
        var clientId = Request.Headers["ClientID"].FirstOrDefault();
        if (string.IsNullOrEmpty(clientId))
            return BadRequest(new GenericServerError { Message = "ClientID header is required" });

        var client = _clientCacheService.GetClient(clientId);
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
                .Select(key => $"{key}={response.Metadata[key]}")
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

    private Dictionary<string, string> ParseMetadataString(string metadataString)
    {
        if (string.IsNullOrEmpty(metadataString))
            return new Dictionary<string, string>();

        return metadataString
            .Split(',') // split into each key-value pair
            .Select(entry =>
            {
                // transforms each string entry into a string array by splitting on the delimiter "]:["
                var parts = entry.Split("]:[");
                if (parts.Length != 2)
                    throw new ArgumentException($"Invalid metadata entry: {entry}");
                return parts;
            })
            .ToDictionary(
                parts => parts[0].TrimStart('['),
                parts => parts[1].TrimEnd(']')
            );
    }
}