<?php

require_once __DIR__ . '/errors.php';

function handleGetObject($params)
{
    // Get ClientID from HTTP header
    $clientId = $_SERVER['HTTP_X_CLIENT_ID'] ?? $_SERVER['HTTP_CLIENTID'] ?? null;

    if (empty($clientId)) {
        return GenericServerError("ClientID header is required", 400);
    }

    # Get the S3EncryptionClient from the client_cache
    $s3ecClientTuple = getCachedClient($clientId);
    if ($s3ecClientTuple == null) {
        return GenericServerError("No client found for ClientID: " . $clientId, 404);
    }

    $metadata = $_SERVER['HTTP_CONTENT_METADATA'] ?? '';
    $encryptionContext = metadataStringToMap($metadata);

    // Extract bucket and key from URL parameters
    $bucket = $params['bucket'] ?? null;
    $key = $params['key'] ?? null;

    if (is_null($bucket) || is_null($key)) {
        return GenericServerError("Invalid bucket or key parameters", 400);
    }

    $s3ec = $s3ecClientTuple["encryptionClient"];
    $materialProvider = $s3ecClientTuple["materialsProvider"];
    $clientConfig = $s3ecClientTuple["config"];
    $legacyConfig = $clientConfig["legacy"] ?? false;
    $legacy = null;
    if ($legacyConfig === false) {
        $legacy = "V2";
    } else {
        $legacy = "V2_AND_LEGACY";
    }

    try {
        // Start output buffering before the AWS call to capture any unwanted output
        ob_start();

        $result = $s3ec->getObject([
            '@SecurityProfile' => $legacy,
            '@MaterialsProvider' => $materialProvider,
            '@KmsEncryptionContext' => $encryptionContext,
            'Bucket' => $bucket,
            'Key' => $key,
        ]);

        // Capture and discard any unwanted output from AWS SDK
        $unwantedOutput = ob_get_clean();
        if (!empty($unwantedOutput)) {
            error_log("AWS SDK produced unexpected output: " . strlen($unwantedOutput) . " bytes");
        }

        $body = $result['Body']->getContents();
        $formattedMetadata = formatMetadataForResponse($result["Metadata"]);

        // Now set headers safely
        header("Content-Metadata: " . $formattedMetadata);
        header("Content-Type: application/octet-stream");
        header("Content-Length: " . strlen($body));
        return $body;
    } catch (InvalidArgumentException $e) {
        // Clean up output buffer if still active
        if (ob_get_level()) {
            ob_end_clean();
        }
        return GenericServerError("Invalid argument: " . $e->getMessage(), 400);
    } catch (Exception $e) {
        // Clean up output buffer if still active
        if (ob_get_level()) {
            ob_end_clean();
        }
        if (strpos($e->getMessage(), "@SecurityProfile=V2") !== false) {
            return S3EncryptionClientError($e->getMessage() . " " . "Enable legacy wrapping algorithms to use legacy key wrapping algorithm: kms");
        } else {
            return GenericServerError("Server error: " . $e->getMessage(), 500);
        }
    }
}
