using Amazon;
using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.S3;
using Amazon.S3.Model;

using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.S3;
using Amazon.S3.Model;

namespace S3EncryptionClientV3Example
{
    class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("[NET V3] Usage: dotnet run <bucket-name> <object-key> <kms-key-id> <region>");
                Environment.Exit(1);
            }

            var (bucketName, objectKey, kmsKeyId, region) = (args[0], args[1], args[2], args[3]);
            var testData = "Hello, World! This is a test message for S3 encryption client v3 in .NET.";

            Console.WriteLine("=== S3 Encryption Client v3 Example (.NET) ===");

            try
            {
                var s3Client = CreateS3ECWithKms(kmsKeyId, region);

                await s3Client.PutObjectAsync(new PutObjectRequest
                {
                    BucketName = bucketName,
                    Key = objectKey,
                    ContentBody = testData
                });

                var getResponse = await s3Client.GetObjectAsync(bucketName, objectKey);
                using var reader = new StreamReader(getResponse.ResponseStream);
                var decryptedData = await reader.ReadToEndAsync();

                if (decryptedData != testData)
                {
                    Console.WriteLine("[NET V3] ERROR: Roundtrip failed - data mismatch");
                    Environment.Exit(1);
                }

                Console.WriteLine("[NET V3] SUCCESS: Roundtrip encryption/decryption completed successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[NET V3] Error: {ex.Message}");
                Environment.Exit(1);
            }
        }

        private static AmazonS3Client CreateS3ECWithKms(string kmsKeyId, string region)
        {
            var encryptionContextPerClient = new Dictionary<string, string>
            {
                ["purpose"] = "example",
                ["version"] = "v3",
                ["language"] = "dotnet"
            };

            var encryptionMaterial = new EncryptionMaterialsV2(kmsKeyId, KmsType.KmsContext, encryptionContextPerClient);
            var configuration = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            {
                RegionEndpoint = RegionEndpoint.GetBySystemName(region)
            };
            return new AmazonS3EncryptionClientV2(configuration, encryptionMaterial);
        }
    }
}
