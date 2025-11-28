using System;
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;

namespace migration
{
    public static class TestUtils
    {
        public static readonly string TEST_KMS_KEY_ID = "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Test-Server-Github-KMS-Key";
        
        public static readonly string TEST_S3_BUCKET = "s3ec-test-server-github-bucket"
            ?? throw new InvalidOperationException("AWS_S3_BUCKET environment variable must be set");

        public static async Task CleanupObject(string bucket, string key)
        {
            var s3Client = new AmazonS3Client();
            await s3Client.DeleteObjectAsync(new DeleteObjectRequest
            {
                BucketName = bucket,
                Key = key
            });
        }
    }
}
