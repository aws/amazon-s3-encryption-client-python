using Xunit;

namespace migration
{
    public class MigrationStep3Test
    {
        [Trait("Category", "Test-Migration-Step3")]
        [Fact]
        public async Task TestMigrationStep3()
        {
            const string content = "test-content";
            var kmsKeyId = TestUtils.TEST_KMS_KEY_ID;
            var bucket = TestUtils.TEST_S3_BUCKET;
            var baseKey = $"migration-test-{Guid.NewGuid()}";
            var objectKeys = new[] { $"{baseKey}-0", $"{baseKey}-1", $"{baseKey}-2", $"{baseKey}-3" };
            var commitmentPolicyError=
                "The requested object is encrypted with non key committing algorithm " +
                "but commitment policy is set to RequireEncryptRequireDecrypt. This commitment policy does not allow " +
                "decryption of object encrypted with non key committing algorithm. " +
                "Retry with RequireEncryptAllowDecrypt to encrypt with key committing algorithm and " +
                "allow decryption for object encrypted with non key committing algorithm.";

            // In cross-step compatibility tests, sometimes only the get operation is needed, so we provide a                                                                                                                                                 
            // dummy key to skip the put operation while maintaining the example's structure. 
            // Examples are intentionally kept simple and unmodified for customer readability.
            var dummyObjectKey = $"{baseKey}-dummy";

            // Successfully round trip step 3
            await MigrationStep3.MigrationExampleStep3(kmsKeyId, bucket, objectKeys[3], objectKeys[3], content);

            // Given: Step 0 round trip has succeeded with put/get object key = 1
            await MigrationStep0.MigrationExampleStep0(kmsKeyId, bucket, objectKeys[0], objectKeys[0], content);

            // When: Execute Step 3 with getObjectKey=0, Then: should error out
            var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
                MigrationStep3.MigrationExampleStep3(kmsKeyId, bucket, dummyObjectKey, objectKeys[0], content));
            Assert.Contains(commitmentPolicyError, exception.Message);

            // Given: Step 1 round trip has succeeded with put/get object key = 2
            await MigrationStep1.MigrationExampleStep1(kmsKeyId, bucket, objectKeys[1], objectKeys[1], content);

            // When: Execute Step 3 with getObjectKey=1, Then: should error out
            exception = await Assert.ThrowsAsync<ArgumentException>(() =>
                MigrationStep3.MigrationExampleStep3(kmsKeyId, bucket, dummyObjectKey, objectKeys[1], content));
            Assert.Contains(commitmentPolicyError, exception.Message);

            // Given: Step 2 round trip has succeeded with put/get object key = 3
            await MigrationStep2.MigrationExampleStep2(kmsKeyId, bucket, objectKeys[2], objectKeys[2], content);

            // When: Execute Step 3 with getObjectKey=2, Then: Success (can read from Step 2)
            await MigrationStep3.MigrationExampleStep3(kmsKeyId, bucket, dummyObjectKey, objectKeys[2], content);

            // Cleanup
            foreach (var key in objectKeys)
            {
                await TestUtils.CleanupObject(bucket, key);
            }
            await TestUtils.CleanupObject(bucket, dummyObjectKey);
        }
    }
}
