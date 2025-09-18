<?php

function handleGetObject($params)
{
    // Get ClientID from HTTP header
    $clientId = $_SERVER['HTTP_X_CLIENT_ID'] ?? $_SERVER['HTTP_CLIENTID'] ?? null;

    if (empty($clientId)) {
        http_response_code(400);
        return json_encode(['error' => 'ClientID header is required']);
    }

    # Get the S3EncryptionClient from the client_cache
    $s3ecClientTuple = getCachedClient($clientId);
    if ($s3ecClientTuple == null) {
        error_log("No cached client found :( " . $clientId);
        error_log("Creating a default client now.");
        $s3ecClientTuple = createDefaultClientTuple();
    } else {
        error_log("Cached Client found: " . $clientId);
    }

    $metadata = $_SERVER['HTTP_CONTENT_METADATA'] ?? '';
    $encryptionContext = metadataStringToMap($metadata);

    // Extract bucket and key from URL parameters
    $bucket = $params['bucket'] ?? null;
    $key = $params['key'] ?? null;

    $s3ec = $s3ecClientTuple["encryptionClient"];
    $materialProvider = $s3ecClientTuple["materialsProvider"];

    try {
        $result = $s3ec->getObject([
            '@SecurityProfile' => 'V2',
            '@MaterialsProvider' => $materialProvider,
            '@KmsEncryptionContext' => $encryptionContext,
            'Bucket' => $bucket,
            'Key' => $key,
        ]);

        $body = $result['Body']->getContents();
        $formattedMetadata = formatMetadataForResponse($result["Metadata"]);
        header("Content-Metadata: " . $formattedMetadata);
        header("Content-Type: application/octet-stream");
        header("Content-Length: " . strlen($body));
        return $body;
    } catch (InvalidArgumentException $e) {
        http_response_code(400);
        return json_encode(['error' => 'Invalid argument: ' . $e->getMessage()]);
    } catch (Exception $e) {
        http_response_code(500);
        return json_encode(['error' => 'Server error: ' . $e->getMessage()]);
    }
}
