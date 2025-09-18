<?php

use Ramsey\Uuid\Uuid;

function handleCreateClient()
{
    // Get the raw request body
    $rawBody = file_get_contents('php://input');

    // Parse JSON if the body contains JSON
    $requestData = json_decode($rawBody, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        return json_encode(['error' => 'Invalid JSON in request body']);
    }
    $config_data = $requestData['config'] ?? [];
    $key_material = $config_data["keyMaterial"] ?? null;

    $clientId = Uuid::uuid4()->toString();
    $kms_key_id = $key_material["kmsKeyId"] ?? null;

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
        'kmsKeyId' => $kms_key_id,
        'created' => time()
    ];

    // Debug: show all cached clients after adding
    error_log("Total clients in cache: " . count($_SESSION['s3ecCache']));
    error_log("ClientID: " . $clientId);

    header("Content-Type: application/json");
    return json_encode([
        'clientId' => $clientId,
    ]);
}
