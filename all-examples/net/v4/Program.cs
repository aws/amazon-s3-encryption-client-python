using Amazon;
using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.S3;
using Amazon.S3.Model;

using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.S3;
using Amazon.S3.Model;

namespace S3EncryptionClientV4Example
{
    class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("Usage: dotnet run <bucket-name> <object-key> <kms-key-id> <region>");
                Environment.Exit(1);
            }

            var (bucketName, objectKey, kmsKeyId, region) = (args[0], args[1], args[2], args[3]);
            var testData = "Hello, World! This is a test message for S3 encryption client v4 in .NET.";

            Console.WriteLine("=== S3 Encryption Client v4 Example (.NET) ===");

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
                    Console.WriteLine("ERROR: Roundtrip failed - data mismatch");
                    Environment.Exit(1);
                }

                Console.WriteLine("SUCCESS: Roundtrip encryption/decryption completed successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }

        private static AmazonS3Client CreateS3ECWithKms(string kmsKeyId, string region)
        {
            var encryptionContextPerClient = new Dictionary<string, string>
            {
                ["purpose"] = "example",
                ["version"] = "v4",
                ["language"] = "dotnet"
            };

            var encryptionMaterial = new EncryptionMaterialsV4(kmsKeyId, KmsType.KmsContext, encryptionContextPerClient);
            var configuration = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)
            {
                RegionEndpoint = RegionEndpoint.GetBySystemName(region)
            };
            return new AmazonS3EncryptionClientV4(configuration, encryptionMaterial);
        }
    }
}
