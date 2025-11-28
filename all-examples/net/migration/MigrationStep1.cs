using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.S3.Model;

namespace migration
{
    // Migration Step 1: This example demonstrates how to start using the S3 Encryption Client v4.
    //
    // This example's purpose is to demonstrate the code changes to 
    // migrate from the v3 client to the v4 client while maintaining identical behavior.
    //
    // When starting from a v3 client modeled in "Migration Step 0",
    // "Migration Step 1" should result in no behavioral changes to your application.
    //
    // In this example we configure a v4 client to:
    // - Write objects encrypted with non-key committing algorithms
    // - Read objects encrypted either with or without key committing algorithms
    //
    // In this configuration, the client will continue to read objects encrypted
    // with non-key committing algorithms (written by a v3 client or this migration-in-progress v4 client),
    // as well as objects encrypted by a migrated v4 client
    // that is configured to write objects encrypted with key committing algorithms.
    //
    // This configuration results in identical behavior to the S3 Encryption Client v3 client
    // configured to use the default FORBID_ENCRYPT_ALLOW_DECRYPT commitment policy.
    public static class MigrationStep1
    {
        public static async Task MigrationExampleStep1(string kmsKeyId, string bucket, string putObjectKey, string getObjectKey, string contentToPut)
        {
            Console.WriteLine("\n[Migration Step 1] Starting Step 1 Migration step. Inputs received: \n" +
                              "kms key ID: " + kmsKeyId + "\n" +
                              "bucket: " + bucket + "\n" +
                              "put object key: " + putObjectKey + "\n" +
                              "get object key: " + getObjectKey + "\n" +
                              "content to put: " + contentToPut + "\n"
                );
            
            var encryptionContext = new Dictionary<string, string>();
            var encryptionMaterial = new EncryptionMaterialsV4(kmsKeyId, KmsType.KmsContext, encryptionContext);
            var configuration = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm);
            var encryptionClient = new AmazonS3EncryptionClientV4(configuration, encryptionMaterial);
            
            await encryptionClient.PutObjectAsync(
                new PutObjectRequest
                {
                    BucketName = bucket,
                    Key = putObjectKey,
                    ContentBody = contentToPut
                }
            );
            
            var response = await encryptionClient.GetObjectAsync(
                new GetObjectRequest
                {
                    BucketName = bucket,
                    Key = getObjectKey
                }
            );
            
            using var reader = new StreamReader(response.ResponseStream);
            var returnedContent = await reader.ReadToEndAsync();
            
            if (returnedContent != contentToPut)
            {
                throw new Exception("Content received from getObject call does not match content put to S3.");
            }

            Console.WriteLine($"[Migration Step 1] success: encryption with {putObjectKey} and decryption with {getObjectKey} completed successfully!");
        }
    }
}