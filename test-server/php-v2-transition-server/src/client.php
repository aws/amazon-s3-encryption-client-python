<?php

require_once __DIR__ . '/errors.php';

use Ramsey\Uuid\Uuid;

function handleCreateClient()
{
    // Get the raw request body
    $rawBody = file_get_contents('php://input');

    // Parse JSON if the body contains JSON
    $requestData = json_decode($rawBody, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return GenericServerError("Invalid JSON in request body", 400);
    }
    $configData = $requestData['config'] ?? [];
    $keyMaterial = $configData["keyMaterial"] ?? null;
    $legacyAlgorithms = $configData["enableLegacyWrappingAlgorithms"] ?? false;
    $clientId = Uuid::uuid4()->toString();
    $kmsKeyId = $keyMaterial["kmsKeyId"] ?? null;
    $instFileConfig = $configData['instructionFileConfig'] ?? null;
    $instFilePut = false;
    if ($instFileConfig != null) {
        $instFilePut = $instFileConfig['enableInstructionFilePutObject'] ?? false;
    }

    if ($configData == []) {
        return GenericServerError("Invalid config in request body", 400);
    }
    if (($keyMaterial || $kmsKeyId) === null) {
        return GenericServerError("Invalid keyMaterial in config", 400);
    }

    // Store client configuration instead of objects (AWS objects can't be serialized)
    $_SESSION['s3ecCache'][$clientId] = [
        's3Config' => [
            'region' => 'us-west-2',
            'version' => 'latest',
            'http' => [
                'debug' => false,
                'verify' => true,
                'curl' => [
                    CURLOPT_VERBOSE => false,
                    CURLOPT_NOPROGRESS => true
                ]
            ]
        ],
        'kmsConfig' => [
            'region' => 'us-west-2',
            'version' => 'latest',
            'http' => [
                'debug' => false,
                'verify' => true,
                'curl' => [
                    CURLOPT_VERBOSE => false,
                    CURLOPT_NOPROGRESS => true
                ]
            ]
        ],
        'kmsKeyId' => $kmsKeyId,
        'legacy' => $legacyAlgorithms,
        'instFilePut' => $instFilePut,
        'created' => time()
    ];

    // Auto-update cookies.txt with current session ID so tests can access cached clients
    writeSessionIdToCookiesFile(session_id());

    header("Content-Type: application/json");
    return json_encode([
        'clientId' => $clientId,
    ]);
}
