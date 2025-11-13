package software.amazon.encryption.s3.example;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;
import software.amazon.encryption.s3.materials.KmsKeyring;

/**
 * Example demonstrating the use of Amazon S3 Encryption Client v4 for Java.
 * 
 * This example shows how to:
 * 1. Initialize the S3 Encryption Client with KMS keyring and key commitment
 * 2. Encrypt and upload an object to S3 with key commitment
 * 3. Download and decrypt the object
 * 4. Verify the roundtrip encryption/decryption
 */
public class Main {
    
    public static void main(String[] args) {
        // Check command line arguments
        if (args.length != 4) {
            System.out.println("Usage: ./gradlew run --args=\"<bucket-name> <object-key> <kms-key-id> <region>\"");
            System.out.println("Example: ./gradlew run --args=\"avp-21638 s3ec-java-v4 arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2\"");
            System.exit(1);
        }

        String bucketName = args[0];
        String objectKey = args[1];
        String kmsKeyId = args[2];
        String region = args[3];

        System.out.println("=== S3 Encryption Client v4 Example (Java) ===");
        System.out.println("Bucket: " + bucketName);
        System.out.println("Object Key: " + objectKey);
        System.out.println("KMS Key ID: " + kmsKeyId);
        System.out.println("Region: " + region);
        System.out.println();

        // Test data for encryption
        String testData = "Hello, World! This is a test message for S3 encryption client v4 in Java.";
        System.out.println("Original data: " + testData);
        System.out.println("Data length: " + testData.length() + " bytes");
        System.out.println();

        try {
            System.out.println("--- Initialize S3 Encryption Client v4 ---");

            // Create standard S3 client
            S3Client s3Client = S3Client.builder()
                    .region(Region.of(region))
                    .credentialsProvider(DefaultCredentialsProvider.create())
                    .build();

            // Create KMS client
            KmsClient kmsClient = KmsClient.builder()
                    .region(Region.of(region))
                    .credentialsProvider(DefaultCredentialsProvider.create())
                    .build();

            // Create KMS keyring
            KmsKeyring keyring = KmsKeyring.builder()
                    .kmsClient(kmsClient)
                    .wrappingKeyId(kmsKeyId)
                    .build();

            // Create Cryptographic Materials Manager
            CryptographicMaterialsManager cmm = DefaultCryptoMaterialsManager.builder()
                    .keyring(keyring)
                    .build();

            // Create S3 Encryption Client v4 with key commitment enabled (Defaults to REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            S3EncryptionClient encryptionClient = S3EncryptionClient.builderV4()
                    .wrappedClient(s3Client)
                    .cryptoMaterialsManager(cmm)
                    .enableLegacyUnauthenticatedModes(false)
                    .enableLegacyWrappingAlgorithms(false)
                    .build();

            System.out.println("Successfully initialized S3 Encryption Client v4");
            System.out.println("Key commitment: ENABLED");
            System.out.println("--- Encrypt and Upload Object to S3 ---");

            // Add encryption context
            Map<String, String> encryptionContext = new HashMap<>();
            encryptionContext.put("purpose", "example");
            encryptionContext.put("version", "v4");
            encryptionContext.put("language", "java");

            // Upload encrypted object using S3 Encryption Client
            PutObjectRequest putRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build();

            encryptionClient.putObject(putRequest, RequestBody.fromString(testData));

            System.out.println("Successfully uploaded encrypted object to S3!");
            System.out.println("   Bucket: " + bucketName);
            System.out.println("   Key: " + objectKey);
            System.out.println("   Encryption Context: " + encryptionContext);
            System.out.println("   Key Commitment: ENABLED");
            System.out.println();

            System.out.println("--- Download and Decrypt Object from S3 ---");

            // Download and decrypt object using S3 Encryption Client
            GetObjectRequest getRequest = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build();

            String decryptedData = encryptionClient.getObjectAsBytes(getRequest)
                    .asString(StandardCharsets.UTF_8);

            System.out.println("Successfully downloaded and decrypted object from S3!");
            System.out.println("   Object size: " + decryptedData.length() + " bytes");
            System.out.println("   Decrypted data: " + decryptedData);
            System.out.println();

            System.out.println("--- Verify Roundtrip Success ---");

            // Verify the roundtrip was successful
            if (decryptedData.equals(testData)) {
                System.out.println("SUCCESS: Roundtrip encryption/decryption completed successfully!");
                System.out.println("   Original data matches decrypted data");
                System.out.println("   Data integrity verified");
                System.out.println("   Key commitment verified");
            } else {
                System.out.println("ERROR: Roundtrip failed - data mismatch");
                System.out.println("   Original: " + testData);
                System.out.println("   Decrypted: " + decryptedData);
                System.exit(1);
            }

            System.out.println();
            System.out.println("=== Example completed successfully! ===");

            // Clean up clients
            encryptionClient.close();
            s3Client.close();
            kmsClient.close();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
