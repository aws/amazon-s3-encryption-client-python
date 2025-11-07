<?php

use Aws\S3\Crypto\InstructionFileMetadataStrategy;

require_once __DIR__ . '/errors.php';

function handlePutObject($params)
{
    // Get the raw request body
    $rawBody = file_get_contents('php://input');
    // Get ClientID from HTTP header
    $clientId = $_SERVER['HTTP_X_CLIENT_ID'] ?? $_SERVER['HTTP_CLIENTID'] ?? null;

    if (empty($clientId)) {
        return GenericServerError("ClientID header is required", 400);
    }

    # Get the S3EncryptionClient from the client_cache
    $s3ecClientTuple = getCachedClient($clientId);
    if (is_null($s3ecClientTuple)) {
        return GenericServerError("No client found for ClientID: " . $clientId, 404);
    }

    // Capture all Content-Metadata headers
    $metadata = $_SERVER['HTTP_CONTENT_METADATA'] ?? '';
    $encryptionContext = metadataStringToMap($metadata);

    // Extract bucket and key from URL parameters
    $bucket = $params['bucket'] ?? null;
    $key = $params['key'] ?? null;

    if (is_null($bucket) || is_null($key)) {
        return GenericServerError("Invalidb bucket or key parameters", 400);
    }

    $s3Client = $s3ecClientTuple["s3Client"];
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
    $instructionFileConfig = $s3ecClientTuple["config"]["instFilePut"] ?? false;
    $result = null;
    try {
        if (!$instructionFileConfig) {
            $result = $s3ec->putObject([
                '@SecurityProfile' => $legacy,
                '@MaterialsProvider' => $materialProvider,
                '@KmsEncryptionContext' => $encryptionContext,
                '@CipherOptions' => $cipherOptions,
                'Bucket' => $bucket,
                'Key' => $key,
                'Body' => $rawBody,
            ]);
        } else {
            $strategy = new InstructionFileMetadataStrategy($s3Client);
            $result = $s3ec->putObject([
                '@SecurityProfile' => $legacy,
                '@MaterialsProvider' => $materialProvider,
                '@KmsEncryptionContext' => $encryptionContext,
                '@MetadataStrategy' => $strategy,
                '@CipherOptions' => $cipherOptions,
                'Bucket' => $bucket,
                'Key' => $key,
                'Body' => $rawBody,
            ]);
        }

        header("Content-Type: application/json");
        return json_encode([
            "bucket" => $bucket,
            "key" => $key,
            // php for some reason blows java's heap if we pass the metadata
            // "metadata" => $encryptionContext
        ]);

    } catch (InvalidArgumentException $e) {
        return S3EncryptionClientError("Invalid arguement: " . $e->getMessage());
    } catch (Exception $e) {
        return GenericServerError("Server error: " . $e->getMessage());
    }
}
