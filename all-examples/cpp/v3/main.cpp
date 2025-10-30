#include <aws/core/Aws.h>
#include <aws/core/utils/Outcome.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/GenerateDataKeyRequest.h>
#include <aws/kms/model/DecryptRequest.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <string>

int main(int argc, char* argv[]) {
    // Check command line arguments
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <bucket-name> <object-key> <kms-key-id>" << std::endl;
        std::cerr << "Example: " << argv[0] << " avp-21638 s3ec-cpp-v3 arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01" << std::endl;
        return 1;
    }

    std::string bucketName = argv[1];
    std::string objectKey = argv[2];
    std::string kmsKeyId = argv[3];

    // Initialize AWS SDK
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    try {
        std::cout << "=== S3 Encryption Client v3 Example (Demonstration) ===" << std::endl;
        std::cout << "Bucket: " << bucketName << std::endl;
        std::cout << "Object Key: " << objectKey << std::endl;
        std::cout << "KMS Key ID: " << kmsKeyId << std::endl << std::endl;

        // Set default region
        Aws::Client::ClientConfiguration clientConfig;
        clientConfig.region = "us-east-2";

        // Create KMS client to demonstrate key operations
        Aws::KMS::KMSClient kmsClient(clientConfig);

        // Test data that would be encrypted
        std::string testData = "Hello, World! This is a test message for S3 encryption client v3.";
        std::cout << "Original data: " << testData << std::endl;

        std::cout << "\n--- Demonstrating KMS Data Key Generation (v3 Enhanced) ---" << std::endl;
        
        // Generate a data key using KMS (this is what S3EC would do internally)
        Aws::KMS::Model::GenerateDataKeyRequest dataKeyRequest;
        dataKeyRequest.SetKeyId(kmsKeyId);
        dataKeyRequest.SetKeySpec(Aws::KMS::Model::DataKeySpec::AES_256);
        
        // Add encryption context (v3 uses more comprehensive context)
        Aws::Map<Aws::String, Aws::String> encryptionContext;
        encryptionContext["purpose"] = "example";
        encryptionContext["version"] = "v3";
        encryptionContext["client"] = "cpp";
        encryptionContext["bucket"] = bucketName;
        encryptionContext["key"] = objectKey;
        encryptionContext["security-profile"] = "v2"; // v3 uses enhanced security
        dataKeyRequest.SetEncryptionContext(encryptionContext);

        auto dataKeyOutcome = kmsClient.GenerateDataKey(dataKeyRequest);
        
        if (dataKeyOutcome.IsSuccess()) {
            std::cout << "✅ Successfully generated data key from KMS!" << std::endl;
            std::cout << "Key ID: " << kmsKeyId << std::endl;
            std::cout << "Encryption context includes (v3 enhanced):" << std::endl;
            for (const auto& pair : encryptionContext) {
                std::cout << "  " << pair.first << " = " << pair.second << std::endl;
            }
            
            // In a real S3EC v3 implementation, this data key would be used with enhanced security
            std::cout << "\n--- S3 Encryption Client v3 Workflow (Enhanced Security) ---" << std::endl;
            std::cout << "1. ✅ Generate data key from KMS with enhanced context (completed above)" << std::endl;
            std::cout << "2. 🔄 Use authenticated encryption for object data (requires S3EC v3 library)" << std::endl;
            std::cout << "3. 🔄 Store encrypted data key with strict validation (requires S3EC v3 library)" << std::endl;
            std::cout << "4. 🔄 Upload encrypted object with enhanced metadata (requires S3EC v3 library)" << std::endl;
            std::cout << "5. 🔄 Download encrypted object with validation (requires S3EC v3 library)" << std::endl;
            std::cout << "6. 🔄 Validate encryption context strictly (requires S3EC v3 library)" << std::endl;
            std::cout << "7. 🔄 Decrypt data key with context validation (requires S3EC v3 library)" << std::endl;
            std::cout << "8. 🔄 Decrypt object data with authenticated decryption (requires S3EC v3 library)" << std::endl;
            
            std::cout << "\n--- v3 Security Enhancements ---" << std::endl;
            std::cout << "🔒 Enhanced Security Profile: Enforces authenticated encryption modes" << std::endl;
            std::cout << "🔒 Stricter Validation: More rigorous encryption context validation" << std::endl;
            std::cout << "🔒 Modern Cryptography: Uses latest cryptographic standards" << std::endl;
            std::cout << "🔒 Better Error Handling: More detailed error messages and validation" << std::endl;
            
        } else {
            std::cerr << "❌ Failed to generate data key: " << dataKeyOutcome.GetError().GetMessage() << std::endl;
            Aws::ShutdownAPI(options);
            return 1;
        }

        std::cout << "\n=== Example completed successfully! ===" << std::endl;
        std::cout << "\n📝 NOTE: This example demonstrates the enhanced KMS integration that S3EC v3 uses." << std::endl;
        std::cout << "v3 provides stricter security profiles and enhanced validation compared to v2." << std::endl;
        std::cout << "To run the full S3 encryption client, you need to install the complete" << std::endl;
        std::cout << "Amazon S3 Encryption Client library, which is not part of the standard AWS SDK." << std::endl;
        std::cout << "\nFor the complete S3EC library, visit:" << std::endl;
        std::cout << "https://github.com/aws/amazon-s3-encryption-client-cpp" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Exception occurred: " << e.what() << std::endl;
        Aws::ShutdownAPI(options);
        return 1;
    }

    // Shutdown AWS SDK
    Aws::ShutdownAPI(options);
    return 0;
}
