#include <aws/core/Aws.h>
#include <aws/kms/KMSClient.h>
#include <aws/s3-encryption/CryptoConfiguration.h>
#include <aws/s3-encryption/S3EncryptionClient.h>
#include <aws/s3-encryption/materials/KMSEncryptionMaterials.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/core/client/ClientConfiguration.h>

#include <memory>
#include <string>
#include <unordered_map>

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


static int test_v1(const char *bucket, const char *object, const char *kms_key_id, const char *region)
{
  Aws::Client::ClientConfiguration s3ClientConfig;
  s3ClientConfig.region = region;

  auto materials = std::make_shared<KMSWithContextEncryptionMaterials>(kms_key_id, s3ClientConfig);
  CryptoConfiguration config;

  auto client = std::make_shared<S3EncryptionClient>(materials, config, s3ClientConfig);

  Aws::S3::Model::PutObjectRequest put_request;
  put_request.SetBucket(bucket);
  put_request.SetKey(object);

  auto data = std::string("This is the sample content.");

  auto stream = std::make_shared<std::stringstream>(data);
  put_request.SetBody(stream);

  auto put_outcome = client->PutObject(put_request);
  if (put_outcome.IsSuccess())
  {
    fprintf(stderr, "PutObject V1 Successful.\n");
  }
  else
  {
    fprintf(stderr, "PutObject V1 Failed : %s\n", put_outcome.GetError().GetMessage().c_str());
    return 1;
  }

  Aws::S3::Model::GetObjectRequest get_request;
  get_request.SetBucket(bucket);
  get_request.SetKey(object);
  auto get_outcome = client->GetObject(get_request);
  if (get_outcome.IsSuccess())
  {
    fprintf(stderr, "GetObject V1 Successful.\n");
    Aws::StringStream response_stream;
    response_stream << get_outcome.GetResult().GetBody().rdbuf();
    if (response_stream.str() != data)
    {
      fprintf(stderr, "GetObject V1 returned the wrong data.\n");
      return 1;
    }
  }
  else
  {
    fprintf(stderr, "GetObject V1 Failed : %s\n", put_outcome.GetError().GetMessage().c_str());
    return 1;
  }

  CryptoConfigurationV3 config_v3(materials);
  auto v3_client_no_legacy = std::make_shared<S3EncryptionClientV3>(config_v3, s3ClientConfig);

  config_v3.SetCommitmentPolicy(CommitmentPolicy::REQUIRE_ENCRYPT_ALLOW_DECRYPT);
  config_v3.AllowLegacy();
  auto v3_client_legacy = std::make_shared<S3EncryptionClientV3>(config_v3, s3ClientConfig);

  get_outcome = v3_client_no_legacy->GetObject(get_request);
  if (get_outcome.IsSuccess())
    fprintf(stderr, "Badness. V3 with no legacy should have failed.\n");
  else
    fprintf(stderr, "V3 with no legacy successfully failed to read legacy object.\n");

  get_outcome = v3_client_legacy->GetObject(get_request);
  if (get_outcome.IsSuccess())
    fprintf(stderr, "V3 with legacy support successfully read legacy object.\n");
  else
    fprintf(stderr, "Badness. V3 with legacy should have succeeded.\n");

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

  Aws::SDKOptions options;
  Aws::InitAPI(options);

  if (strcasecmp(version_str, "v3") == 0)
    test_v3(bucket, object, kms_key_id, region);
  else if (strcasecmp(version_str, "v2") == 0)
    test_v2(bucket, object, kms_key_id, region);
  else if (strcasecmp(version_str, "v1") == 0)
    test_v1(bucket, object, kms_key_id, region);
  else
  {
    fprintf(stderr, "Version was <%s> must be V1, V2 or V3\n", version_str);
    return 1;
  }

  Aws::ShutdownAPI(options);
}
