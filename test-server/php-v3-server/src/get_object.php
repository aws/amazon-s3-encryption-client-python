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
    if (is_null($s3ecClientTuple)) {
        return GenericServerError("No client found for ClientID: " . $clientId, 404);
    }

    $metadata = $_SERVER['HTTP_CONTENT_METADATA'] ?? '';
    $encryptionContext = metadataStringToMap($metadata);

    // Extract bucket and key from URL parameters
    $bucket = $params['bucket'] ?? null;
    $key = $params['key'] ?? null;

    if (is_null($bucket) || is_null($key)) {
        return GenericServerError("Invalidb bucket or key parameters", 400);
    }

    $s3ec = $s3ecClientTuple["encryptionClient"];
    $materialProvider = $s3ecClientTuple["materialsProvider"];
    $clientConfig = $s3ecClientTuple["config"];
    $legacyConfig = $clientConfig["legacy"] ?? false;
    $legacy = null;
    if ($legacyConfig === false) {
        $legacy = "V3";
    } else {
        $legacy = "V3_AND_LEGACY";
    }
    $commitmentPolicy = $s3ecClientTuple['config']['commitmentPolicy'];

    try {
        // Start output buffering before the AWS call to capture any unwanted output
        ob_start();

        $result = $s3ec->getObject([
            '@SecurityProfile' => $legacy,
            '@MaterialsProvider' => $materialProvider,
            '@KmsEncryptionContext' => $encryptionContext,
            '@CommitmentPolicy' => $commitmentPolicy,
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
    } catch (CryptoException $e) {
        return S3EncryptionClientError("Crypto error: " . $e->getMessage());
    } catch (Exception $e) {
        // Clean up output buffer if still active
        if (ob_get_level()) {
            ob_end_clean();
        }
        if (strpos($e->getMessage(), "@SecurityProfile=V3") !== false) {
            return S3EncryptionClientError($e->getMessage());
        } elseif (strpos($e->getMessage(), "Provided encryption context does not match information retrieved from S3") !== false) {
            return S3EncryptionClientError($e->getMessage());
        } elseif (strpos($e->getMessage(), "Message is encrypted with a non commiting algorithm but commitment policy is set to REQUIRE_ENCRYPT_REQUIRE_DECRYPT. Select a valid commitment policy to decrypt this object.") !== false) {
            return S3EncryptionClientError($e->getMessage());
        } else {
            error_log("This is the error: " . $e->getMessage());
            return GenericServerError("Server argument: " . $e->getMessage(), 500);
        }
    }
}
