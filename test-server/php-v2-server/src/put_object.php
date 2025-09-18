<?php

function handlePutObject($params)
{
    // Get the raw request body
    $rawBody = file_get_contents('php://input');
    // Get ClientID from HTTP header
    $clientId = $_SERVER['HTTP_X_CLIENT_ID'] ?? $_SERVER['HTTP_CLIENTID'] ?? null;

    if (empty($clientId)) {
        http_response_code(400);
        return json_encode(['error' => 'ClientID header is required']);
    }

    # Get the S3EncryptionClient from the client_cache
    $s3ecClientTuple = getCachedClient($clientId);
    if ($s3ecClientTuple === null) {
        error_log("No cached client found :( " . $clientId);
        error_log("Creating a default client now.");
        $s3ecClientTuple = createDefaultClientTuple();
    } else {
        error_log("Cached Client found: " . $clientId);
    }

    // Capture all Content-Metadata headers
    $metadata = $_SERVER['HTTP_CONTENT_METADATA'] ?? '';
    $encryptionContext = metadataStringToMap($metadata);

    // Extract bucket and key from URL parameters
    $bucket = $params['bucket'] ?? null;
    $key = $params['key'] ?? null;

    $s3ec = $s3ecClientTuple["encryptionClient"];
    $materialProvider = $s3ecClientTuple["materialsProvider"];
    $cipherOptions = [
        'Cipher' => 'gcm',
        'KeySize' => 256,
    ];
    $legacyConfig = $s3ecClientTuple["legacy"] ?? false;
    $legacy = null;
    if ($legacyConfig === false) {
        $legacy = "V2";
    } else {
        $legacy = "V2_AND_LEGACY";
    }

    try {
        $result = $s3ec->putObject([
            '@SecurityProfile' => $legacy,
            '@MaterialsProvider' => $materialProvider,
            '@KmsEncryptionContext' => $encryptionContext,
            '@CipherOptions' => $cipherOptions,
            'Bucket' => $bucket,
            'Key' => $key,
            'Body' => $rawBody,
        ]);

        header("Content-Type: application/json");
        return json_encode([
            "bucket" => $bucket,
            "key" => $key,
            // "metadata" => $encryptionContext
        ]);

    } catch (InvalidArgumentException $e) {
        http_response_code(400);
        return json_encode(['error' => 'Invalid argument: ' . $e->getMessage()]);
    } catch (Exception $e) {
        http_response_code(500);
        return json_encode(['error' => 'Server error: ' . $e->getMessage()]);
    }
}
