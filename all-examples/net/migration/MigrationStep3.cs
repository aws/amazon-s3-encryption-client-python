using Amazon.Extensions.S3.Encryption;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.S3.Model;

namespace migration
{
    public static class MigrationStep3
    {
        // Migration Step 3: This example demonstrates how to update your v4 client configuration
        // to stop reading objects encrypted with non-key committing algorithms.
        //
        // This example's purpose is to demonstrate the commitment policy code changes required to
        // stop reading objects encrypted with non-key committing algorithms
        // and document the behavioral changes that will result from this change.
        //
        // When starting from a v4 client modeled in "Migration Step 2",
        // "Migration Step 3" WILL result in behavioral changes to your application.
        // The client will no longer be able to read objects encrypted with non-key committing algorithms.
        // Before deploying these changes, you MUST have taken some extra steps 
        // to ensure that your system is no longer reading such objects,
        // such as re-encrypting them with key committing algorithms.
        //
        // IMPORTANT: Before deploying the changes in this step, your system should not be reading
        // any objects encrypted with non-key committing algorithms.
        // The changes in this step will cause such read attempts to fail.
        // This means the changes from "Migration Step 2" should have already been deployed to all of your readers
        // before you deploy the changes from "Migration Step 3".
        //
        // Once you complete Step 3, you can be sure that all items being read by your system
        // have been encrypted using key committing algorithms.
        
        public static async Task MigrationExampleStep3(string kmsKeyId, string bucket, string putObjectKey, string getObjectKey, string contentToPut)
        {
            Console.WriteLine("\n[Migration Step 3] Starting Step 3 Migration step. Inputs received: \n" +
                              "kms key ID: " + kmsKeyId + "\n" +
                              "bucket: " + bucket + "\n" +
                              "put object key: " + putObjectKey + "\n" +
                              "get object key: " + getObjectKey + "\n" +
                              "content to put: " + contentToPut + "\n"
                );
            
            var encryptionContext = new Dictionary<string, string>();
            var encryptionMaterial = new EncryptionMaterialsV4(kmsKeyId, KmsType.KmsContext, encryptionContext);
            var configuration = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment);
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

            Console.WriteLine($"[Migration Step 3] success: encryption with {putObjectKey} and decryption with {getObjectKey} completed successfully!");
        }
    }
}