using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.S3.Model;

namespace migration
{
    // Migration Step 2: This example demonstrates how to update your v4 client configuration
    // to start writing objects encrypted with key committing algorithms.
    //
    // This example's purpose is to demonstrate the commitment policy code changes required to
    // start writing objects encrypted with key committing algorithms
    // and document the behavioral changes that will result from this change.
    //
    // When starting from a v4 client modeled in "Migration Step 1",
    // "Migration Step 2" WILL result in behavioral changes to your application.
    // The client will start writing objects encrypted with key committing algorithms.
    //
    // IMPORTANT: You MUST have updated your readers to be able to read objects encrypted with key committing algorithms
    // before deploying the changes in this step.
    // This means deploying the changes from either "Migration Step 0" (if readers are v3 clients)
    // or "Migration Step 1" (if readers are v4 clients) to all of your readers
    // before deploying the changes from to "Migration Step 2".
    //
    // Once you deploy this change to your writers, your readers will start seeing
    // some objects encrypted with non-key committing algorithms,
    // and some objects encrypted with key committing algorithms.
    // Because the changes would have already been deployed to all our readers from earlier migration steps,
    // we can be sure that our entire system is ready to read both types of objects.
    // After deploying these changes but before proceeding to "Migration Step 3",
    // you MUST take extra steps to ensure that your system is no longer reading
    // objects encrypted with non-key committing algorithms
    // (such as re-encrypting any existing objects using key committing algorithms).
    public static class MigrationStep2
    {
        public static async Task MigrationExampleStep2(string kmsKeyId, string bucket, string putObjectKey, string getObjectKey, string contentToPut)
        {
            Console.WriteLine("\n[Migration Step 2] Starting Step 2 Migration step. Inputs received: \n" +
                              "kms key ID: " + kmsKeyId + "\n" +
                              "bucket: " + bucket + "\n" +
                              "put object key: " + putObjectKey + "\n" +
                              "get object key: " + getObjectKey + "\n" +
                              "content to put: " + contentToPut + "\n"
                );
            
            var encryptionContext = new Dictionary<string, string>();
            var encryptionMaterial = new EncryptionMaterialsV4(kmsKeyId, KmsType.KmsContext, encryptionContext);
            var configuration = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment);
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

            Console.WriteLine($"[Migration Step 2] success: encryption with {putObjectKey} and decryption with {getObjectKey} completed successfully!");
        }
    }
}