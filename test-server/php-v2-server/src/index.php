<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Aws\S3\Crypto\S3EncryptionClientV2;
use Aws\Crypto\KmsMaterialsProviderV2;
use Aws\S3\S3Client;
use Aws\Kms\KmsClient;

use Ramsey\Uuid\Uuid;
use GuzzleHttp\Psr7\Response;

// Start session to persist cache across requests
session_start();

// Initialize session cache if it doesn't exist
if (!isset($_SESSION['s3ecCache'])) {
    $_SESSION['s3ecCache'] = [];
}

// Simple router class
class SimpleRouter
{
    private $routes = [];

    public function addRoute($method, $path, $handler)
    {
        $this->routes[] = [
            'method' => strtoupper($method),
            'path' => $path,
            'handler' => $handler
        ];
    }

    public function handleRequest()
    {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

        foreach ($this->routes as $route) {
            if ($route['method'] === $method) {
                $params = $this->matchPathWithParams($route['path'], $path);
                if ($params !== false) {
                    return call_user_func($route['handler'], $params);
                }
            }
        }

        // Default 404 response
        http_response_code(404);
        return json_encode(['error' => 'Not Found']);
    }

    private function matchPathWithParams($routePath, $requestPath)
    {
        // Handle exact matches first (for routes without parameters)
        if ($routePath === $requestPath) {
            return [];
        }

        // Convert route path like '/object/{bucket}/{key}' to regex
        $pattern = preg_replace('/\{([^}]+)\}/', '([^/]+)', $routePath);
        $pattern = '/^' . str_replace('/', '\/', $pattern) . '$/';

        if (preg_match($pattern, $requestPath, $matches)) {
            array_shift($matches); // Remove full match

            // Extract parameter names
            preg_match_all('/\{([^}]+)\}/', $routePath, $paramNames);
            $params = [];

            foreach ($paramNames[1] as $index => $paramName) {
                $params[$paramName] = $matches[$index] ?? null;
            }

            return $params;
        }

        return false;
    }
}

// Helper function to get cached client by ID
function getCachedClient($clientId)
{
    if (!isset($_SESSION['s3ecCache'][$clientId])) {
        return null;
    }

    $config = $_SESSION['s3ecCache'][$clientId];

    // Recreate the AWS clients from stored configuration
    $s3Client = new S3Client($config['s3Config']);
    $encryptionClient = new S3EncryptionClientV2($s3Client);

    $kmsClient = new KmsClient($config['kmsConfig']);
    $materialsProvider = new KmsMaterialsProviderV2($kmsClient, $config['kmsKeyId']);

    return [
        'encryptionClient' => $encryptionClient,
        'materialsProvider' => $materialsProvider,
        'config' => $config
    ];
}

function createDefaultClientTuple(): array
{
    $s3Client = new S3Client([
        'region' => 'us-west-2',
        'version' => 'latest',
    ]);
    $encryptionClient = new S3EncryptionClientV2($s3Client);

    $kmsClient = new KmsClient([
        'region' => 'us-west-2',
        'version' => 'latest',
    ]);
    $materialsProvider = new KmsMaterialsProviderV2($kmsClient, 'arn:aws:kms:us-west-2:370957321024:alias/S3EC-Test-Server-Github-KMS-Key');

    return [
        'encryptionClient' => $encryptionClient,
        'materialsProvider' => $materialsProvider
    ];
}

function metadataStringToMap($metadata): array
{
    $md = [];

    if (empty($metadata)) {
        return $md;
    }

    $mdList = explode(',', $metadata);

    foreach ($mdList as $entry) {
        $parts = explode(']:[', $entry);

        if (count($parts) === 2) {
            $key = substr($parts[0], 1);
            $value = substr($parts[1], 0, -1);
            $md[$key] = $value;
        } else {
            throw new InvalidArgumentException("Malformed metadata list entry: " . $entry);
        }
    }

    return $md;
}
function formatMetadataForResponse($metadata)
{
    $metadataList = [];
    // Handle different metadata input types
    if (is_array($metadata)) {
        // If it's an associative array (like Python dict)
        foreach ($metadata as $key => $value) {
            $metadataList[] = $key . '=' . $value;
        }
    } elseif (is_string($metadata) && !empty($metadata)) {
        // If it's already a string, assume it's in the correct format
        return $metadata;
    }

    // Convert array to comma-separated string
    return implode(',', $metadataList);
}

// Initialize router
$router = new SimpleRouter();

// Add basic routes
$router->addRoute('GET', '/', function () {
    return json_encode([
        'service' => 'S3EC PHP v2 Test Server',
        'status' => 'running',
        'port' => 8087,
        'endpoints' => [
            'GET /' => 'Server status',
            'POST /client' => 'Create an S3EncryptionClient and cache it.',
            'GET /object/{bucket}/{key}' => 'Handle GET requests to /object/{bucket}/{key} by using the S3EncryptionClient to make a GetObject request to S3.',
            'PUT /object/{bucket}/{key}' => 'Handle PUT requests to /object/{bucket}/{key} by using the S3EncryptionClient to make a PutObject request to S3.',
        ]
    ]);
});

$router->addRoute('POST', '/client', function () {
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
        ],
        'kmsConfig' => [
            'region' => 'us-west-2',
            'version' => 'latest',
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
});

$router->addRoute('GET', '/cache', function () {
    return json_encode([
        'sessionId' => session_id(),
        'sessionStatus' => session_status(),
        'totalCachedClients' => count($_SESSION['s3ecCache'] ?? []),
        'allClientIds' => array_keys($_SESSION['s3ecCache'] ?? []),
        'cacheDetails' => $_SESSION['s3ecCache'] ?? []
    ]);
});

$router->addRoute('GET', '/object/{bucket}/{key}', function ($params) {
    // Get ClientID from HTTP header
    $clientId = $_SERVER['HTTP_X_CLIENT_ID'] ?? $_SERVER['HTTP_CLIENTID'] ?? null;

    if (empty($clientId)) {
        http_response_code(400);
        return json_encode(['error' => 'ClientID header is required']);
    }

    error_log("clientId from get /object: " . $clientId);

    # Get the S3EncryptionClient from the client_cache
    $s3ecClientTuple = getCachedClient($clientId);
    if ($s3ecClientTuple === null) {
        error_log("No cached client found :( " . $clientId);
        error_log("Creating a default client now.");
        $s3ecClientTuple = createDefaultClientTuple();
    }

    $metadata = $_SERVER['HTTP_CONTENT_METADATA'] ?? '';
    $encryptionContext = metadataStringToMap($metadata);
    // error_log("encryption context: " . json_encode($encryptionContext));

    // Extract bucket and key from URL parameters
    $bucket = $params['bucket'] ?? null;
    $key = $params['key'] ?? null;

    $s3ec = $s3ecClientTuple["encryptionClient"];
    $materialProvider = $s3ecClientTuple["materialsProvider"];

    try {
        $result = $s3ec->getObject([
            '@KmsAllowDecryptWithAnyCmk' => true,
            '@SecurityProfile' => 'V2',
            '@MaterialsProvider' => $materialProvider,
            '@KmsEncryptionContext' => $encryptionContext,
            'Bucket' => $bucket,
            'Key' => $key,
        ]);

        $body = $result['Body']->getContents();
        $formattedMetadata = formatMetadataForResponse($result["Metadata"]);
        error_log("Response Object: " . $body);
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

});

$router->addRoute('PUT', '/object/{bucket}/{key}', function ($params) {
    // Get the raw request body
    $rawBody = file_get_contents('php://input');
    // Get ClientID from HTTP header
    $clientId = $_SERVER['HTTP_X_CLIENT_ID'] ?? $_SERVER['HTTP_CLIENTID'] ?? null;

    if (empty($clientId)) {
        http_response_code(400);
        return json_encode(['error' => 'ClientID header is required']);
    }

    error_log("clientId from get /object: " . $clientId);

    # Get the S3EncryptionClient from the client_cache
    $s3ecClientTuple = getCachedClient($clientId);
    if ($s3ecClientTuple === null) {
        error_log("No cached client found :( " . $clientId);
        error_log("Creating a default client now.");
        $s3ecClientTuple = createDefaultClientTuple();
    }
    $metadata = $_SERVER['HTTP_CONTENT_METADATA'] ?? '';
    $encryptionContext = metadataStringToMap($metadata);
    error_log("encryption context: " . json_encode($encryptionContext));

    // Extract bucket and key from URL parameters
    $bucket = $params['bucket'] ?? null;
    $key = $params['key'] ?? null;

    $s3ec = $s3ecClientTuple["encryptionClient"];
    $materialProvider = $s3ecClientTuple["materialsProvider"];
    $cipherOptions = [
        'Cipher' => 'gcm',
        'KeySize' => 256,
    ];

    try {
        $result = $s3ec->putObject([
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
            "metadata" => $encryptionContext,
        ]);

    } catch (InvalidArgumentException $e) {
        http_response_code(400);
        return json_encode(['error' => 'Invalid argument: ' . $e->getMessage()]);
    } catch (Exception $e) {
        http_response_code(500);
        return json_encode(['error' => 'Server error: ' . $e->getMessage()]);
    }
});
// Handle the request and output response
$result = $router->handleRequest();
if ($result !== false) {
    echo $result;
}
