#!/usr/bin/env php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Aws\S3\S3Client;
use Aws\Kms\KmsClient;
use Aws\S3\Crypto\S3EncryptionClientV3;
use Aws\Crypto\KmsMaterialsProviderV3;
use Aws\S3\Crypto\S3EncryptionClientV2;
use Aws\Crypto\KmsMaterialsProviderV2;
use Aws\Exception\AwsException;

function main(): void {
    // Check command line arguments
    if (count($GLOBALS['argv']) !== 5) {
        echo "Usage: {$GLOBALS['argv'][0]} <bucket-name> <object-key> <kms-key-id> <region>\n";
        echo "Example: {$GLOBALS['argv'][0]} avp-21638 s3ec-php-v3 arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2\n";
        exit(1);
    }

    $bucketName = $GLOBALS['argv'][1];
    $objectKey = $GLOBALS['argv'][2];
    $kmsKeyId = $GLOBALS['argv'][3];
    $region = $GLOBALS['argv'][4];

    echo "=== S3 Encryption Client v3 Example (PHP) ===\n";
    echo "Bucket: {$bucketName}\n";
    echo "Object Key: {$objectKey}\n";
    echo "KMS Key ID: {$kmsKeyId}\n";
    echo "Region: {$region}\n";
    echo "\n";

    try {
        // Test data for encryption
        $testData = "Hello, World! This is a test message for S3 encryption client v3 in PHP.";
        echo "Original data: {$testData}\n";
        echo "Data length: " . strlen($testData) . " bytes\n";
        echo "\n";

        echo "--- Initialize S3 Encryption Client v3 ---\n";
        
        // Create regular S3 client
        $s3Client = new S3Client([
            'region' => $region,
            'version' => 'latest'
        ]);
        
        // Create KMS client
        $kmsClient = new KmsClient([
            'region' => $region,
            'version' => 'latest'
        ]);
        
        // Create S3 Encryption Client v3
        // Create S3 Encryption Client v2
        $encryptionClient = new S3EncryptionClientV3($s3Client);
        $materialsProvider = new KmsMaterialsProviderV3($kmsClient, $kmsKeyId);
        
        echo "Successfully initialized S3 Encryption Client v3\n";
        echo "--- Encrypt and Upload Object to S3 ---\n";
        
        // Add encryption context
        $encryptionContext = [
            'purpose' => 'example',
            'version' => 'v3',
            'language' => 'php'
        ];
        
        $cipherOptions = [
            'Cipher' => 'gcm',
            'KeySize' => 256,
        ];
        
        // Upload encrypted object using S3 Encryption Client
        $putResponse = $encryptionClient->putObject([
            'Bucket' => $bucketName,
            'Key' => $objectKey,
            'Body' => $testData,
            '@MaterialsProvider' => $materialsProvider,
            '@KmsEncryptionContext' => $encryptionContext,
            '@CommitmentPolicy' => "REQUIRE_ENCRYPT_REQUIRE_DECRYPT",
            '@CipherOptions' => $cipherOptions,
        ]);
        
        echo "Successfully uploaded encrypted object to S3!\n";
        echo "   Bucket: {$bucketName}\n";
        echo "   Key: {$objectKey}\n";
        echo "   Encryption Context: " . json_encode($encryptionContext) . "\n";
        echo "\n";

        echo "--- Download and Decrypt Object from S3 ---\n";
        
        // Download and decrypt object using S3 Encryption Client
        $getResponse = $encryptionClient->getObject([
            'Bucket' => $bucketName,
            'Key' => $objectKey,
            '@KmsEncryptionContext' => $encryptionContext,
            '@MaterialsProvider' => $materialsProvider,
            '@CommitmentPolicy' => "REQUIRE_ENCRYPT_REQUIRE_DECRYPT",
            '@SecurityProfile' => 'V3'
        ]);
        
        // Read the decrypted data
        $decryptedData = (string) $getResponse['Body'];
        
        echo "Successfully downloaded and decrypted object from S3!\n";
        echo "   Object size: " . strlen($decryptedData) . " bytes\n";
        echo "   Decrypted data: {$decryptedData}\n";
        echo "\n";

        echo "--- Verify Roundtrip Success ---\n";
        
        // Verify the roundtrip was successful
        if ($decryptedData === $testData) {
            echo "SUCCESS: Roundtrip encryption/decryption completed successfully!\n";
            echo "   Original data matches decrypted data\n";
            echo "   Data integrity verified\n";
        } else {
            echo "ERROR: Roundtrip failed - data mismatch\n";
            echo "   Original: {$testData}\n";
            echo "   Decrypted: {$decryptedData}\n";
            exit(1);
        }

        // Optionally Delete the Object
        // echo "--- Cleanup ---\n";
        // Clean up the test object using regular S3 client
        // $s3Client->deleteObject([
        //     'Bucket' => $bucketName,
        //     'Key' => $objectKey
        // ]);
        // echo "Test object deleted from S3\n";
        
        echo "\n";
        echo "=== Example completed successfully! ===\n";

    } catch (AwsException $e) {
        $errorCode = $e->getAwsErrorCode();
        $errorMessage = $e->getMessage();
        
        if (strpos($errorCode, 'NoSuchBucket') !== false) {
            echo "Error: S3 bucket '{$bucketName}' does not exist or is not accessible\n";
            echo "   {$errorMessage}\n";
        } elseif (strpos($errorCode, 'NotFoundException') !== false) {
            echo "Error: KMS key '{$kmsKeyId}' not found or not accessible\n";
            echo "   {$errorMessage}\n";
        } elseif (strpos($errorMessage, 'encryption') !== false) {
            echo "S3 Encryption Error: {$errorMessage}\n";
        } else {
            echo "AWS Service Error: {$errorMessage}\n";
            echo "   Error Code: {$errorCode}\n";
        }
        exit(1);
    } catch (Exception $e) {
        echo "Unexpected error: {$e->getMessage()}\n";
        echo "   File: {$e->getFile()}:{$e->getLine()}\n";
        exit(1);
    }
}

function testMigration(): void {
    if (count($GLOBALS['argv']) !== 5) {
        echo "Usage: {$GLOBALS['argv'][0]} <bucket-name> <object-key> <kms-key-id> <region>\n";
        echo "Example: {$GLOBALS['argv'][0]} avp-21638 s3ec-php-v3 arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2\n";
        exit(1);
    }

    $bucketName = $GLOBALS['argv'][1];
    $objectKey = $GLOBALS['argv'][2];
    $kmsKeyId = $GLOBALS['argv'][3];
    $region = $GLOBALS['argv'][4];

    echo "=== S3 Encryption Client Pre-migration (V2) Example ===\n";
    echo "Bucket: {$bucketName}\n";
    echo "Object Key: {$objectKey}\n";
    echo "KMS Key ID: {$kmsKeyId}\n";
    echo "Region: {$region}\n";
    echo "\n";

    try {
        $testData = "Hello, World! This is a test message for S3 encryption client Pre-migration (V2) in PHP.";
        echo "Original data: {$testData}\n";
        echo "Data length: " . strlen($testData) . " bytes\n";
        echo "\n";

        $v2EncryptionClient = new S3EncryptionClientV2(
        new S3Client([
            'region' => $region,
            'version' => 'latest',
        ])
        );

        $materialsProviderV2 = new KmsMaterialsProviderV2(
            new KmsClient([
                'region' => $region,
                'version' => 'latest',
            ]),
            $kmsKeyId
        );

        $cipherOptions = [
            'Cipher' => 'gcm',
            'KeySize' => 256,
        ];

        $v2EncryptionClient->putObject([
            '@MaterialsProvider' => $materialsProviderV2,
            '@CipherOptions' => $cipherOptions,
            '@KmsEncryptionContext' => ['context-key' => 'context-value'],
            'Bucket' => $bucketName,
            'Key' => $objectKey,
            'Body' => $testData,
        ]);

        $getResponse = $v2EncryptionClient->getObject([
            '@KmsAllowDecryptWithAnyCmk' => true,
            '@SecurityProfile' => 'V2_AND_LEGACY',
            '@CommitmentPolicy' => 'FORBID_ENCRYPT_ALLOW_DECRYPT',
            '@MaterialsProvider' => $materialsProviderV2,
            '@CipherOptions' => $cipherOptions,
            'Bucket' => $bucketName,
            'Key' => $objectKey,
        ]);
        
        // Read the decrypted data
        $decryptedData = (string) $getResponse['Body'];
        
        echo "Successfully downloaded and decrypted object from S3!\n";
        echo "   Object size: " . strlen($decryptedData) . " bytes\n";
        echo "   Decrypted data: {$decryptedData}\n";
        echo "\n";

        echo "--- Verify Roundtrip Success ---\n";
        
        // Verify the roundtrip was successful
        if ($decryptedData === $testData) {
            echo "SUCCESS: Roundtrip encryption/decryption completed successfully!\n";
            echo "   Original data matches decrypted data\n";
            echo "   Data integrity verified\n";
        } else {
            echo "ERROR: Roundtrip failed - data mismatch\n";
            echo "   Original: {$testData}\n";
            echo "   Decrypted: {$decryptedData}\n";
            exit(1);
        }

        // Optionally Delete the Object
        // echo "--- Cleanup ---\n";
        // Clean up the test object using regular S3 client
        // $s3Client->deleteObject([
        //     'Bucket' => $bucketName,
        //     'Key' => $objectKey
        // ]);
        // echo "Test object deleted from S3\n";
        
        echo "\n";
        echo "=== Example completed successfully! ===\n";

    } catch (AwsException $e) {
        $errorCode = $e->getAwsErrorCode();
        $errorMessage = $e->getMessage();
        
        if (strpos($errorCode, 'NoSuchBucket') !== false) {
            echo "Error: S3 bucket '{$bucketName}' does not exist or is not accessible\n";
            echo "   {$errorMessage}\n";
        } elseif (strpos($errorCode, 'NotFoundException') !== false) {
            echo "Error: KMS key '{$kmsKeyId}' not found or not accessible\n";
            echo "   {$errorMessage}\n";
        } elseif (strpos($errorMessage, 'encryption') !== false) {
            echo "S3 Encryption Error: {$errorMessage}\n";
        } else {
            echo "AWS Service Error: {$errorMessage}\n";
            echo "   Error Code: {$errorCode}\n";
        }
        exit(1);
    } catch (Exception $e) {
        echo "Unexpected error: {$e->getMessage()}\n";
        echo "   File: {$e->getFile()}:{$e->getLine()}\n";
        exit(1);
    }
    
    echo "=== S3 Encryption Client during migration (V3 with backward compatibility) Example ===\n";
    echo "Bucket: {$bucketName}\n";
    echo "Object Key: {$objectKey}\n";
    echo "KMS Key ID: {$kmsKeyId}\n";
    echo "Region: {$region}\n";
    echo "\n";

    try {
        $testData = "Hello, World! This is a test message for S3 encryption client during migration (V3 with backward compatibility) in PHP.";
        echo "Original data: {$testData}\n";
        echo "Data length: " . strlen($testData) . " bytes\n";
        echo "\n";
        
        $v2EncryptionClient = new S3EncryptionClientV3(
            new S3Client([
                'region' => $region,
                'version' => 'latest',
            ])
        );

        $materialsProviderV3 = new KmsMaterialsProviderV3(
            new KmsClient([
                'region' => $region,
                'version' => 'latest',
            ]),
            $kmsKeyId
        );

        $cipherOptions = [
            'Cipher' => 'gcm',
            'KeySize' => 256,
        ];

        $v2EncryptionClient->putObject([
            '@MaterialsProvider' => $materialsProviderV3,
            '@CipherOptions' => $cipherOptions,
            '@CommitmentPolicy' => 'REQUIRE_ENCRYPT_ALLOW_DECRYPT',
            '@KmsEncryptionContext' => ['context-key' => 'context-value'],
            'Bucket' => $bucketName,
            'Key' => $objectKey,
            'Body' => $testData,
        ]);

        $getResponse = $v2EncryptionClient->getObject([
            '@KmsAllowDecryptWithAnyCmk' => true,
            '@SecurityProfile' => 'V3_AND_LEGACY',
            '@CommitmentPolicy' => 'REQUIRE_ENCRYPT_ALLOW_DECRYPT',
            '@MaterialsProvider' => $materialsProviderV3,
            '@CipherOptions' => $cipherOptions,
            'Bucket' => $bucketName,
            'Key' => $objectKey,
        ]);
        
        // Read the decrypted data
        $decryptedData = (string) $getResponse['Body'];
        
        echo "Successfully downloaded and decrypted object from S3!\n";
        echo "   Object size: " . strlen($decryptedData) . " bytes\n";
        echo "   Decrypted data: {$decryptedData}\n";
        echo "\n";

        echo "--- Verify Roundtrip Success ---\n";
        
        // Verify the roundtrip was successful
        if ($decryptedData === $testData) {
            echo "SUCCESS: Roundtrip encryption/decryption completed successfully!\n";
            echo "   Original data matches decrypted data\n";
            echo "   Data integrity verified\n";
        } else {
            echo "ERROR: Roundtrip failed - data mismatch\n";
            echo "   Original: {$testData}\n";
            echo "   Decrypted: {$decryptedData}\n";
            exit(1);
        }

        // Optionally Delete the Object
        // echo "--- Cleanup ---\n";
        // Clean up the test object using regular S3 client
        // $s3Client->deleteObject([
        //     'Bucket' => $bucketName,
        //     'Key' => $objectKey
        // ]);
        // echo "Test object deleted from S3\n";
        
        echo "\n";
        echo "=== Example completed successfully! ===\n";

    } catch (AwsException $e) {
        $errorCode = $e->getAwsErrorCode();
        $errorMessage = $e->getMessage();
        
        if (strpos($errorCode, 'NoSuchBucket') !== false) {
            echo "Error: S3 bucket '{$bucketName}' does not exist or is not accessible\n";
            echo "   {$errorMessage}\n";
        } elseif (strpos($errorCode, 'NotFoundException') !== false) {
            echo "Error: KMS key '{$kmsKeyId}' not found or not accessible\n";
            echo "   {$errorMessage}\n";
        } elseif (strpos($errorMessage, 'encryption') !== false) {
            echo "S3 Encryption Error: {$errorMessage}\n";
        } else {
            echo "AWS Service Error: {$errorMessage}\n";
            echo "   Error Code: {$errorCode}\n";
        }
        exit(1);
    } catch (Exception $e) {
        echo "Unexpected error: {$e->getMessage()}\n";
        echo "   File: {$e->getFile()}:{$e->getLine()}\n";
        exit(1);
    }
    
    echo "=== S3 Encryption Client post-migration (V3 with key commitment) Example ===\n";
    echo "Bucket: {$bucketName}\n";
    echo "Object Key: {$objectKey}\n";
    echo "KMS Key ID: {$kmsKeyId}\n";
    echo "Region: {$region}\n";
    echo "\n";

    try {
        $testData = "Hello, World! This is a test message for S3 encryption client post-migration (V3 with key commitment) in PHP.";
        echo "Original data: {$testData}\n";
        echo "Data length: " . strlen($testData) . " bytes\n";
        echo "\n";
        
        $v2EncryptionClient = new S3EncryptionClientV3(
            new S3Client([
                'region' => $region,
                'version' => 'latest',
            ])
        );

        $materialsProviderV3 = new KmsMaterialsProviderV3(
            new KmsClient([
                'region' => $region,
                'version' => 'latest',
            ]),
            $kmsKeyId
        );

        $cipherOptions = [
            'Cipher' => 'gcm',
            'KeySize' => 256,
        ];

        $v2EncryptionClient->putObject([
            '@MaterialsProvider' => $materialsProviderV3,
            '@CipherOptions' => $cipherOptions,
            '@CommitmentPolicy' => 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT',
            '@KmsEncryptionContext' => ['context-key' => 'context-value'],
            'Bucket' => $bucketName,
            'Key' => $objectKey,
            'Body' => $testData,
        ]);

        $getResponse = $v2EncryptionClient->getObject([
            '@KmsAllowDecryptWithAnyCmk' => true,
            '@SecurityProfile' => 'V3',
            '@CommitmentPolicy' => 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT',
            '@MaterialsProvider' => $materialsProviderV3,
            '@CipherOptions' => $cipherOptions,
            'Bucket' => $bucketName,
            'Key' => $objectKey,
        ]);
        
        // Read the decrypted data
        $decryptedData = (string) $getResponse['Body'];
        
        echo "Successfully downloaded and decrypted object from S3!\n";
        echo "   Object size: " . strlen($decryptedData) . " bytes\n";
        echo "   Decrypted data: {$decryptedData}\n";
        echo "\n";

        echo "--- Verify Roundtrip Success ---\n";
        
        // Verify the roundtrip was successful
        if ($decryptedData === $testData) {
            echo "SUCCESS: Roundtrip encryption/decryption completed successfully!\n";
            echo "   Original data matches decrypted data\n";
            echo "   Data integrity verified\n";
        } else {
            echo "ERROR: Roundtrip failed - data mismatch\n";
            echo "   Original: {$testData}\n";
            echo "   Decrypted: {$decryptedData}\n";
            exit(1);
        }

        // Optionally Delete the Object
        // echo "--- Cleanup ---\n";
        // Clean up the test object using regular S3 client
        // $s3Client->deleteObject([
        //     'Bucket' => $bucketName,
        //     'Key' => $objectKey
        // ]);
        // echo "Test object deleted from S3\n";
        
        echo "\n";
        echo "=== Example completed successfully! ===\n";

    } catch (AwsException $e) {
        $errorCode = $e->getAwsErrorCode();
        $errorMessage = $e->getMessage();
        
        if (strpos($errorCode, 'NoSuchBucket') !== false) {
            echo "Error: S3 bucket '{$bucketName}' does not exist or is not accessible\n";
            echo "   {$errorMessage}\n";
        } elseif (strpos($errorCode, 'NotFoundException') !== false) {
            echo "Error: KMS key '{$kmsKeyId}' not found or not accessible\n";
            echo "   {$errorMessage}\n";
        } elseif (strpos($errorMessage, 'encryption') !== false) {
            echo "S3 Encryption Error: {$errorMessage}\n";
        } else {
            echo "AWS Service Error: {$errorMessage}\n";
            echo "   Error Code: {$errorCode}\n";
        }
        exit(1);
    } catch (Exception $e) {
        echo "Unexpected error: {$e->getMessage()}\n";
        echo "   File: {$e->getFile()}:{$e->getLine()}\n";
        exit(1);
    }
}

// Run the main function if this script is executed directly
if (php_sapi_name() === 'cli' && isset($GLOBALS['argv']) && basename($GLOBALS['argv'][0]) === basename(__FILE__)) {
    main();
    testMigration();
}
