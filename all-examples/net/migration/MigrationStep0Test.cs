using Xunit;

namespace migration
{
    public class MigrationStep0Test
    {
        [Trait("Category", "Test-Migration-Step0")]
        [Fact]
        public async Task TestMigrationStep0()
        {
            const string content = "test-content";
            var kmsKeyId = TestUtils.TEST_KMS_KEY_ID;
            var bucket = TestUtils.TEST_S3_BUCKET;
            var baseKey = $"migration-test-{Guid.NewGuid()}";
            var objectKeys = new[] { $"{baseKey}-0", $"{baseKey}-1", $"{baseKey}-2", $"{baseKey}-3" };
            
            // In cross-step compatibility tests, sometimes only the get operation is needed, so we provide a                                                                                                                                                 
            // dummy key to skip the put operation while maintaining the example's structure. 
            // Examples are intentionally kept simple and unmodified for customer readability.
            var dummyObjectKey = $"{baseKey}-dummy";

            // Successfully round trip step 0
            await MigrationStep0.MigrationExampleStep0(kmsKeyId, bucket, objectKeys[0], objectKeys[0], content);

            // Given: Step 1 round trip has succeeded with put/get object key = 1
            await MigrationStep1.MigrationExampleStep1(kmsKeyId, bucket, objectKeys[1], objectKeys[1], content);

            // When: Execute Step 0 with getObjectKey=1, Then: Success (can read objects from Step 1)
            await MigrationStep0.MigrationExampleStep0(kmsKeyId, bucket, dummyObjectKey, objectKeys[1], content);

            // Given: Step 2 round trip has succeeded with put/get object key = 2
            await MigrationStep2.MigrationExampleStep2(kmsKeyId, bucket, objectKeys[2], objectKeys[2], content);

            // When: Execute Step 0 with getObjectKey=2, Then: should error out
            await MigrationStep0.MigrationExampleStep0(kmsKeyId, bucket, dummyObjectKey, objectKeys[2], content);

            // Given: Step 3 round trip has succeeded with put/get object key = 3
            await MigrationStep3.MigrationExampleStep3(kmsKeyId, bucket, objectKeys[3], objectKeys[3], content);

            // When: Execute Step 0 with getObjectKey=3, Then: should error out
            await MigrationStep0.MigrationExampleStep0(kmsKeyId, bucket, dummyObjectKey, objectKeys[3], content);

            // Cleanup
            foreach (var key in objectKeys)
            {
                await TestUtils.CleanupObject(bucket, key);
            }
            await TestUtils.CleanupObject(bucket, dummyObjectKey);
        }
    }
}
