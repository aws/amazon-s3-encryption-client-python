using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.S3.Model;

namespace migration
{
    // Migration Step 0: This example demonstrates use of the S3 Encryption Client for .NET v2
    // and is the starting state for migrating your data to the v4 client.
    //
    // This example's purpose is to model behavior of an existing v2 client.
    // Subsequent migration steps will demonstrate code changes needed to use the v4 client.
    //
    // This example configures a v2 client to:
    // - Write objects using non-key committing encryption algorithms
    // - Read objects encrypted with either key committing algorithms or with non-key committing algorithms
    //
    // In this configuration, the client can read objects encrypted
    // with non-key committing algorithms (written by this v2 client or an in-progress v4 migration),
    // as well as objects encrypted by a migrated v4 client
    // that is configured to write objects encrypted with key committing algorithms.
    // You should ensure you are using the latest version of the v2 client
    // that can read objects encrypted with key committing algorithms before proceeding with migration.
    public static class MigrationStep0
    {
        public static async Task MigrationExampleStep0(string kmsKeyId, string bucket, string putObjectKey, string getObjectKey, string contentToPut)
        {
            Console.WriteLine("\n[Migration Step 0] Starting Step 0 Migration step. Inputs received: \n" +
                              "kms key ID: " + kmsKeyId + "\n" +
                              "bucket: " + bucket + "\n" +
                              "put object key: " + putObjectKey + "\n" +
                              "get object key: " + getObjectKey + "\n" +
                              "content to put: " + contentToPut + "\n"
                );
            
            var encryptionContext = new Dictionary<string, string>();
            var encryptionMaterial = new EncryptionMaterialsV2(kmsKeyId, KmsType.KmsContext, encryptionContext);
#pragma warning disable 0618
            var configuration = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
#pragma warning enable 0618
            var encryptionClient = new AmazonS3EncryptionClientV2(configuration, encryptionMaterial);
            
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

            Console.WriteLine($"[Migration Step 0] success: encryption with {putObjectKey} and decryption with {getObjectKey} completed successfully!");
        }
    }
}