<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Aws\S3\Crypto\S3EncryptionClientV2;
use Aws\Crypto\KmsMaterialsProviderV2;
use Aws\S3\S3Client;
use Aws\Kms\KmsClient;

use Ramsey\Uuid\Uuid;

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
            if ($route['method'] === $method && $route['path'] === $path) {
                return call_user_func($route['handler']);
            }
        }

        // Default 404 response
        http_response_code(404);
        return json_encode(['error' => 'Not Found']);
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
    $clientId = Uuid::uuid4()->toString();

    // Debug session info
    // error_log("Session ID: " . session_id());
    // error_log("Session status: " . session_status());
    // error_log("Cache before adding: " . json_encode(array_keys($_SESSION['s3ecCache'] ?? [])));

    // Store client configuration instead of objects (AWS objects can't be serialized)
    $_SESSION['s3ecCache'][$clientId] = [
        's3Config' => [
            'profile' => 'default',
            'region' => 'us-west-2',
            'version' => 'latest',
        ],
        'kmsConfig' => [
            'profile' => 'default',
            'region' => 'us-east-1',
            'version' => 'latest',
        ],
        'kmsKeyId' => 'kms-key-id',
        'created' => time()
    ];

    // Debug: show all cached clients after adding
    error_log("Total clients in cache: " . count($_SESSION['s3ecCache']));

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

$router->addRoute('GET', '/object', function () {
    return json_encode([
        'status' => 'healthy',
        'message' => 'implement me!'
    ]);
});

$router->addRoute('PUT', '/object', function () {
    return json_encode([
        'status' => 'healthy',
        'message' => 'implement me!'
    ]);
});
// Set content type header
header('Content-Type: application/json');

// Handle the request and output response
echo $router->handleRequest();
