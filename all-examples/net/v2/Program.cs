using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Amazon.S3;

namespace S3EncryptionClientV3Example
{
    class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("Usage: dotnet run <bucket-name> <object-key> <kms-key-id> <region>");
                Console.WriteLine("Example: dotnet run avp-21638 s3ec-dotnet-v3 arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2");
                Environment.Exit(1);
            }

            string bucketName = args[0];
            string objectKey = args[1];
            string kmsKeyId = args[2];
            string region = args[3];

            Console.WriteLine("=== S3 Encryption Client v3 Example (.NET) ===");
            Console.WriteLine($"Bucket: {bucketName}");
            Console.WriteLine($"Object Key: {objectKey}");
            Console.WriteLine($"KMS Key ID: {kmsKeyId}");
            Console.WriteLine($"Region: {region}");
            Console.WriteLine();

            try
            {
                string testData = "Hello, World! This is a test message for S3 encryption client v3 in .NET.";
                Console.WriteLine($"Original data: {testData}");
                Console.WriteLine($"Data length: {testData.Length} bytes");
                Console.WriteLine();

                Console.WriteLine("--- Initialize S3 Encryption Client v2 ---");
                
                var encryptionContextPerClient = new Dictionary<string, string>
                {
                    ["purpose"] = "example",
                    ["version"] = "v2",
                    ["language"] = "dotnet"
                };

                var s3Client = CreateS3ECClientKMSMaterial(kmsKeyId, encryptionContextPerClient);
                Console.WriteLine("Successfully initialized S3 Encryption Client v2");

                Console.WriteLine("--- Encrypt and Upload Object to S3 ---");
                
                await s3Client.PutObjectAsync(new Amazon.S3.Model.PutObjectRequest
                {
                    BucketName = bucketName,
                    Key = objectKey,
                    ContentBody = testData
                });

                Console.WriteLine("Successfully uploaded encrypted object to S3!");
                Console.WriteLine($"   Bucket: {bucketName}");
                Console.WriteLine($"   Key: {objectKey}");
                Console.WriteLine($"   Encryption Context: {string.Join(", ", encryptionContextPerClient)}");
                Console.WriteLine();

                Console.WriteLine("--- Download and Decrypt Object from S3 ---");
                
                var getResponse = await s3Client.GetObjectAsync(bucketName, objectKey);
                string decryptedData;
                using (var reader = new System.IO.StreamReader(getResponse.ResponseStream))
                {
                    decryptedData = await reader.ReadToEndAsync();
                }

                Console.WriteLine("Successfully downloaded and decrypted object from S3!");
                Console.WriteLine($"   Object size: {decryptedData.Length} bytes");
                Console.WriteLine($"   Decrypted data: {decryptedData}");
                Console.WriteLine();

                Console.WriteLine("--- Verify Roundtrip Success ---");
                
                if (decryptedData == testData)
                {
                    Console.WriteLine("SUCCESS: Roundtrip encryption/decryption completed successfully!");
                    Console.WriteLine("   Original data matches decrypted data");
                    Console.WriteLine("   Data integrity verified");
                }
                else
                {
                    Console.WriteLine("ERROR: Roundtrip failed - data mismatch");
                    Console.WriteLine($"   Original: {testData}");
                    Console.WriteLine($"   Decrypted: {decryptedData}");
                    Environment.Exit(1);
                }

                Console.WriteLine();
                Console.WriteLine("=== Example completed successfully! ===");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }

        public static AmazonS3Client CreateS3ECClientKMSMaterial(string kmsKeyId, Dictionary<string, string> encryptionContextPerClient)
        {
            EncryptionMaterialsV2 encryptionMaterial =
                new EncryptionMaterialsV2(kmsKeyId, KmsType.KmsContext, encryptionContextPerClient);
            var configuration = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm);
            var encryptionClient = new AmazonS3EncryptionClientV2(configuration, encryptionMaterial);
        
            return encryptionClient;
        }
    }
}
