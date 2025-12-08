#include <aws/s3-encryption/S3EncryptionClient.h>
#include <aws/s3-encryption/materials/KMSEncryptionMaterials.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/PutObjectRequest.h>

using namespace Aws::S3Encryption;
using Aws::S3Encryption::Materials::KMSWithContextEncryptionMaterials;

static Aws::Map<Aws::String, Aws::String> get_encryption_context(const char * version)
{
  return {
        {"purpose", "example"},
        {"version", version},
        {"language", "c++"}
    };
}

static int test_migration(const char *bucket, const char *object, const char *kms_key_id, const char *region)
{
  Aws::Client::ClientConfiguration s3ClientConfig;
  s3ClientConfig.region = region;

  auto materials = std::make_shared<KMSWithContextEncryptionMaterials>(kms_key_id, s3ClientConfig);
  CryptoConfigurationV3 config(materials);

  // STEP 1: Upgrade to V3 client to prepare to read messages with commitment.
  //         You want to update your readers before you update your writers
  config.SetCommitmentPolicy(CommitmentPolicy::FORBID_ENCRYPT_ALLOW_DECRYPT);
  auto client = std::make_shared<S3EncryptionClientV3>(config, s3ClientConfig);

  auto encryption_context = get_encryption_context("V3");

  // Put Object - writes objects WITHOUT commitment
  Aws::S3::Model::PutObjectRequest put_request;
  put_request.SetBucket(bucket);
  put_request.SetKey(object);

  auto data = std::string("This is the sample content.");

  auto stream = std::make_shared<std::stringstream>(data);
  put_request.SetBody(stream);

  // Put Object - writes objects WITHOUT commitment
  auto put_outcome = client->PutObject(put_request, encryption_context);
  assert(put_outcome.IsSuccess());

  Aws::S3::Model::GetObjectRequest get_request;
  get_request.SetBucket(bucket);
  get_request.SetKey(object);

  // Get Object - can read objects with or without commitment
  auto get_outcome = client->GetObject(get_request, encryption_context);
  assert(get_outcome.IsSuccess());

  // STEP 2: If all of the readers can read with or without commitment
  // you can upgrade the commitment policy to write objects with commitment
  config.SetCommitmentPolicy(CommitmentPolicy::REQUIRE_ENCRYPT_ALLOW_DECRYPT);
  client = std::make_shared<S3EncryptionClientV3>(config, s3ClientConfig);

  stream = std::make_shared<std::stringstream>(data);
  put_request.SetBody(stream);

  // Put Object - writes objects WITH commitment
  put_outcome = client->PutObject(put_request, encryption_context);
  assert(put_outcome.IsSuccess());

  // Get Object - can read objects with or without commitment
  get_outcome = client->GetObject(get_request, encryption_context);
  assert(get_outcome.IsSuccess());

  // STEP 3: Once your system no longer has to read messages without commitment,
  // you may update your client to only read messages written with key commitment
  config.SetCommitmentPolicy(CommitmentPolicy::REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
  client = std::make_shared<S3EncryptionClientV3>(config, s3ClientConfig);

  stream = std::make_shared<std::stringstream>(data);
  put_request.SetBody(stream);

  // Put Object - writes objects WITH commitment
  put_outcome = client->PutObject(put_request, encryption_context);
  assert(put_outcome.IsSuccess());

  // Get Object - can only read objects with commitment
  get_outcome = client->GetObject(get_request, encryption_context);
  assert(get_outcome.IsSuccess());

  return 0;
}

static int test_v3(const char *bucket, const char *object, const char *kms_key_id, const char *region)
{
  Aws::Client::ClientConfiguration s3ClientConfig;
  s3ClientConfig.region = region;

  auto materials = std::make_shared<KMSWithContextEncryptionMaterials>(kms_key_id, s3ClientConfig);
  CryptoConfigurationV3 config(materials);
  // config.AllowLegacy();
  // config.SetStorageMethod(StorageMethod::INSTRUCTION_FILE);
  // config.SetCommitmentPolicy(CommitmentPolicy::FORBID_ENCRYPT_ALLOW_DECRYPT);


  auto client = std::make_shared<S3EncryptionClientV3>(config, s3ClientConfig);

  auto encryption_context = get_encryption_context("V3");

  Aws::S3::Model::PutObjectRequest put_request;
  put_request.SetBucket(bucket);
  put_request.SetKey(object);

  auto data = std::string("This is the sample content.");

  auto stream = std::make_shared<std::stringstream>(data);
  put_request.SetBody(stream);

  auto put_outcome = client->PutObject(put_request, encryption_context);
  if (put_outcome.IsSuccess())
  {
    fprintf(stderr, "PutObject V3 Successful.\n");
  }
  else
  {
    fprintf(stderr, "PutObject V3 Failed : %s\n", put_outcome.GetError().GetMessage().c_str());
    return 1;
  }

  Aws::S3::Model::GetObjectRequest get_request;
  get_request.SetBucket(bucket);
  get_request.SetKey(object);
  auto get_outcome = client->GetObject(get_request, encryption_context);
  if (get_outcome.IsSuccess())
  {
    fprintf(stderr, "GetObject V3 Successful.\n");
    Aws::StringStream response_stream;
    response_stream << get_outcome.GetResult().GetBody().rdbuf();
    if (response_stream.str() != data)
    {
      fprintf(stderr, "GetObject V3 returned the wrong data.\n");
      return 1;
    }
  }
  else
  {
    fprintf(stderr, "GetObject V3 Failed : %s\n", put_outcome.GetError().GetMessage().c_str());
    return 1;
  }
  return 0;
}

static int test_v2(const char *bucket, const char *object, const char *kms_key_id, const char *region)
{
  Aws::Client::ClientConfiguration s3ClientConfig;
  s3ClientConfig.region = region;

  auto materials = std::make_shared<KMSWithContextEncryptionMaterials>(kms_key_id, s3ClientConfig);
  CryptoConfigurationV2 config(materials);
  // config.SetSecurityProfile(SecurityProfile::V2_AND_LEGACY);
  // config.SetStorageMethod(StorageMethod::INSTRUCTION_FILE);


  auto client = std::make_shared<S3EncryptionClientV2>(config, s3ClientConfig);

  auto encryption_context = get_encryption_context("V2");

  Aws::S3::Model::PutObjectRequest put_request;
  put_request.SetBucket(bucket);
  put_request.SetKey(object);

  auto data = std::string("This is the sample content.");

  auto stream = std::make_shared<std::stringstream>(data);
  put_request.SetBody(stream);

  auto put_outcome = client->PutObject(put_request, encryption_context);
  if (put_outcome.IsSuccess())
  {
    fprintf(stderr, "PutObject V2 Successful.\n");
  }
  else
  {
    fprintf(stderr, "PutObject V2 Failed : %s\n", put_outcome.GetError().GetMessage().c_str());
    return 1;
  }

  Aws::S3::Model::GetObjectRequest get_request;
  get_request.SetBucket(bucket);
  get_request.SetKey(object);
  auto get_outcome = client->GetObject(get_request, encryption_context);
  if (get_outcome.IsSuccess())
  {
    fprintf(stderr, "GetObject V2 Successful.\n");
    Aws::StringStream response_stream;
    response_stream << get_outcome.GetResult().GetBody().rdbuf();
    if (response_stream.str() != data)
    {
      fprintf(stderr, "GetObject V2 returned the wrong data.\n");
      return 1;
    }
  }
  else
  {
    fprintf(stderr, "GetObject V2 Failed : %s\n", put_outcome.GetError().GetMessage().c_str());
    return 1;
  }
  return 0;
}

int main(int argc, char **argv)
{
  if (argc != 6)
  {
    fprintf(stderr, "USAGE : s3ec-test version bucket object key_id region");
    return 1;
  }

  auto version_str = argv[1];
  auto bucket = argv[2];
  auto object = argv[3];
  auto kms_key_id = argv[4];
  auto region = argv[5];

  bool is_v3;
  if (strcasecmp(version_str, "v3") == 0)
  {
    is_v3 = true;
  }
  else if (strcasecmp(version_str, "v2") == 0)
  {
    is_v3 = false;
  }
  else
  {
    fprintf(stderr, "Version was <%s> must be V2 or V3\n", version_str);
    return 1;
  }

  Aws::SDKOptions options;
  Aws::InitAPI(options);

  if (is_v3)
    test_v3(bucket, object, kms_key_id, region);
  else
    test_v2(bucket, object, kms_key_id, region);

  Aws::ShutdownAPI(options);
}
