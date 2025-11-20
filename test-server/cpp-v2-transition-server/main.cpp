#include <aws/core/Aws.h>
#include <aws/kms/KMSClient.h>
#include <aws/s3-encryption/CryptoConfiguration.h>
#include <aws/s3-encryption/S3EncryptionClient.h>
#include <aws/s3-encryption/materials/KMSEncryptionMaterials.h>
#include <aws/s3-encryption/materials/SimpleEncryptionMaterials.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <microhttpd.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <string>
#include <unordered_map>
#include <uuid/uuid.h>

using json = nlohmann::json;
using namespace Aws::S3Encryption;
using Aws::S3Encryption::Materials::KMSWithContextEncryptionMaterials;
std::unordered_map<std::string, std::shared_ptr<S3EncryptionClientV2>> client_cache_secret;
std::mutex client_mutex;

std::string generate_uuid() {
  uuid_t uuid;
  uuid_generate(uuid);
  char uuid_str[37];
  uuid_unparse(uuid, uuid_str);
  return std::string(uuid_str);
}

std::shared_ptr<S3EncryptionClientV2> get_client(const std::string &client_id)
{
    std::lock_guard<std::mutex> lock(client_mutex);
    auto it = client_cache_secret.find(client_id);
    if (it == client_cache_secret.end()) {
      return std::shared_ptr<S3EncryptionClientV2>();
    } else {
      return it->second;
    }
}

void set_client(const std::string &client_id, std::shared_ptr<S3EncryptionClientV2> client)
{
  std::lock_guard<std::mutex> lock(client_mutex);
  client_cache_secret[client_id] = client;
}

std::string get_header_value(struct MHD_Connection *connection,
                             const char *key) {
  const char *value =
      MHD_lookup_connection_value(connection, MHD_HEADER_KIND, key);
  return value ? std::string(value) : "";
}

MHD_Result send_response(struct MHD_Connection *connection, int status_code,
                         const std::string &content) {
  struct MHD_Response *response = MHD_create_response_from_buffer(
      content.length(), (void *)content.data(), MHD_RESPMEM_MUST_COPY);
  MHD_Result ret = MHD_queue_response(connection, status_code, response);
  MHD_destroy_response(response);
  return ret;
}

std::string make_error(const std::string &message, int status_code) {
  return "{\"__type\": "
         "\"software.amazon.encryption.s3#S3EncryptionClientError\", "
         "\"message\": \"" +
         message + "\"}";
}

bool unsupported(std::string& commitmentPolicy, std::string& encryptionAlgorithm)
{
  if (encryptionAlgorithm == "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY") return true;
  if (commitmentPolicy == "REQUIRE_ENCRYPT_REQUIRE_DECRYPT") return true;
  if (commitmentPolicy == "REQUIRE_ENCRYPT_ALLOW_DECRYPT") return true;
  return false;
}

std::string get_config(json & request, const char * x)
{
  if (!request.contains("config")) return "";
  auto config = request["config"];
  if (config.contains(x))
    return config[x];
  return "";
}

MHD_Result handle_create_client(struct MHD_Connection *connection,
                                const std::string &body) {
  // Make a copy of body so we own the data even if request_completed fires
  std::string body_copy(body);
  
  try {
    json request = json::parse(body_copy);
    std::string commitmentPolicy = get_config(request, "commitmentPolicy");
    std::string encryptionAlgorithm = get_config(request, "encryptionAlgorithm");
    
    if (unsupported(commitmentPolicy, encryptionAlgorithm)) {
      send_response(connection, 404, "{\"error\":\"Unsupported Option.\"}");
      return MHD_YES;
    }

    // Extract all key material types
    std::string kms_key_id;
    std::string rsa_key_blob;
    std::string aes_key_blob;
    
    if (request["config"]["keyMaterial"].contains("kmsKeyId") && 
        !request["config"]["keyMaterial"]["kmsKeyId"].is_null()) {
      kms_key_id = request["config"]["keyMaterial"]["kmsKeyId"];
    }
    if (request["config"]["keyMaterial"].contains("rsaKey") && 
        !request["config"]["keyMaterial"]["rsaKey"].is_null()) {
      rsa_key_blob = request["config"]["keyMaterial"]["rsaKey"];
    }
    if (request["config"]["keyMaterial"].contains("aesKey") && 
        !request["config"]["keyMaterial"]["aesKey"].is_null()) {
      aes_key_blob = request["config"]["keyMaterial"]["aesKey"];
    }
    
    // Validate that only one key type is provided
    int key_count = 0;
    if (!kms_key_id.empty()) key_count++;
    if (!rsa_key_blob.empty()) key_count++;
    if (!aes_key_blob.empty()) key_count++;
    
    if (key_count != 1) {
      return send_response(connection, 400,
          "{\"error\":\"KeyMaterial must contain exactly one non-null key type\"}");
    }
    
    // RSA is not supported by C++ SDK
    if (!rsa_key_blob.empty()) {
      return send_response(connection, 501,
          "{\"error\":\"RSA key wrapping is not supported in C++ S3 Encryption Client\"}");
    }
    
    bool legacy1 = request["config"]["enableLegacyWrappingAlgorithms"];
    bool legacy2 = request["config"]["enableLegacyUnauthenticatedModes"];
    bool inst_put = false;
    if (request["config"].contains("instructionFileConfig") &&
        request["config"]["instructionFileConfig"].contains("enableInstructionFilePutObject")) {
        inst_put = request["config"]["instructionFileConfig"]["enableInstructionFilePutObject"];
    }

    // Create CryptoConfigurationV2 and S3EncryptionClientV2 based on key type
    std::shared_ptr<S3EncryptionClientV2> encryption_client;
    
    if (!aes_key_blob.empty()) {
      // Base64 decode the AES key
      Aws::Utils::ByteBuffer decoded = Aws::Utils::HashingUtils::Base64Decode(aes_key_blob);
      if (decoded.GetLength() == 0) {
        return send_response(connection, 400,
            "{\"error\":\"Failed to decode AES key\"}");
      }
      
      Aws::Utils::CryptoBuffer key_buffer(
          decoded.GetUnderlyingData(),
          decoded.GetLength()
      );
      
      auto materials = std::make_shared<
          Aws::S3Encryption::Materials::SimpleEncryptionMaterialsWithGCMAAD>(
          key_buffer
      );
      CryptoConfigurationV2 config(materials);
      
      if (legacy1 || legacy2)
        config.SetSecurityProfile(SecurityProfile::V2_AND_LEGACY);
      if (inst_put)
        config.SetStorageMethod(StorageMethod::INSTRUCTION_FILE);
      
      // Configure ClientConfiguration with retry strategy for throttling
      Aws::Client::ClientConfiguration clientConfig;
      clientConfig.maxConnections = 25;
      clientConfig.retryStrategy = Aws::Client::InitRetryStrategy("standard");
      
      encryption_client = std::make_shared<S3EncryptionClientV2>(config, clientConfig);
    } else if (!kms_key_id.empty()) {
      auto materials = std::make_shared<KMSWithContextEncryptionMaterials>(kms_key_id);
      CryptoConfigurationV2 config(materials);
      
      if (legacy1 || legacy2)
        config.SetSecurityProfile(SecurityProfile::V2_AND_LEGACY);
      if (inst_put)
        config.SetStorageMethod(StorageMethod::INSTRUCTION_FILE);
      
      // Configure ClientConfiguration with retry strategy for throttling
      Aws::Client::ClientConfiguration clientConfig;
      clientConfig.maxConnections = 25;
      clientConfig.retryStrategy = Aws::Client::InitRetryStrategy("standard");
      
      encryption_client = std::make_shared<S3EncryptionClientV2>(config, clientConfig);
    } else {
      return send_response(connection, 400,
          "{\"error\":\"No valid key material provided\"}");
    }

    std::string client_id = generate_uuid();
    set_client(client_id, encryption_client);

    json response = {{"clientId", client_id}};
    return send_response(connection, 200, response.dump());
  } catch (const std::exception &e) {
    return send_response(connection, 500,
                         "{\"error\":\"An exception was thrown.\"}");
  } catch (...) {
    return send_response(connection, 500, "{\"error\":\"Unknown error\"}");
  }
}

void fill_context(Aws::Map<Aws::String, Aws::String> &map,
                  const std::string &metadata) {
  if (metadata.empty()) {
    return;
  }

  // Parse metadata format: [key1]:[value1],[key2]:[value2],...
  // or single pair: [key]:[value]
  std::string current = metadata;
  size_t pos = 0;

  while (pos < current.length()) {
    // Find opening bracket for key
    size_t key_start = current.find('[', pos);
    if (key_start == std::string::npos)
      break;

    // Find closing bracket for key
    size_t key_end = current.find(']', key_start);
    if (key_end == std::string::npos)
      break;

    // Find colon separator
    size_t colon = current.find(':', key_end);
    if (colon == std::string::npos)
      break;

    // Find opening bracket for value
    size_t value_start = current.find('[', colon);
    if (value_start == std::string::npos)
      break;

    // Find closing bracket for value
    size_t value_end = current.find(']', value_start);
    if (value_end == std::string::npos)
      break;

    // Extract key and value
    std::string key = current.substr(key_start + 1, key_end - key_start - 1);
    std::string value =
        current.substr(value_start + 1, value_end - value_start - 1);

    // Add to map
    map.emplace(key, value);

    // Move to next pair (look for comma or next opening bracket)
    pos = value_end + 1;
    size_t comma = current.find(',', pos);
    if (comma != std::string::npos) {
      pos = comma + 1;
    }
  }
}

MHD_Result handle_get_object(struct MHD_Connection *connection,
                             const std::string &bucket, const std::string &key,
                             const std::string &client_id,
                             const std::string &metadata) {
  auto client = get_client(client_id);
  if (!client) {
    return send_response(connection, 404, "{\"error\":\"Client not found\"}");
  }

  try {
    Aws::S3::Model::GetObjectRequest request;
    request.SetBucket(bucket);
    request.SetKey(key);

    Aws::Map<Aws::String, Aws::String> kmsContextMap;
    fill_context(kmsContextMap, metadata);
    auto outcome = client->GetObject(request, kmsContextMap);

    if (outcome.IsSuccess()) {
      auto &stream = outcome.GetResult().GetBody();
      std::string content((std::istreambuf_iterator<char>(stream)),
                          std::istreambuf_iterator<char>());
      return send_response(connection, 200, content);
    } else {
      auto msg = make_error(outcome.GetError().GetMessage(), 500);
      return send_response(connection, 500, msg);
    }
  } catch (const std::exception &e) {
    auto msg = make_error("An exception was thrown", 500);
    return send_response(connection, 500, msg);
  }
}

MHD_Result handle_put_object(struct MHD_Connection *connection,
                             const std::string &bucket, const std::string &key,
                             const std::string &client_id,
                             const std::string &body,
                             const std::string &metadata) {
  auto client = get_client(client_id);
  if (!client) {
    return send_response(connection, 404, "{\"error\":\"Client not found\"}");
  }

  try {
    // Create owned copy of body data to ensure it lives through the S3 operation
    auto body_ptr = std::make_shared<std::string>(body);
    
    Aws::Map<Aws::String, Aws::String> kmsContextMap;
    fill_context(kmsContextMap, metadata);

    Aws::S3::Model::PutObjectRequest request;
    request.SetBucket(bucket);
    request.SetKey(key);

    // Create stream from owned body data
    auto stream = std::make_shared<std::stringstream>(*body_ptr);
    request.SetBody(stream);

    // Synchronous call - waits for S3 operation to complete
    // body_ptr keeps the data alive through this entire operation
    auto outcome = client->PutObject(request, kmsContextMap);
    if (outcome.IsSuccess()) {
      json response = {{"bucket", bucket}, {"key", key}};
      return send_response(connection, 200, response.dump());
    } else {
      auto msg = make_error(outcome.GetError().GetMessage(), 500);
      return send_response(connection, 500, msg);
    }
  } catch (const std::exception &e) {
    auto msg = make_error(e.what(), 500);
    return send_response(connection, 500, msg);
  }
}

void request_completed(void *cls, struct MHD_Connection *connection,
                      void **con_cls, enum MHD_RequestTerminationCode toe) {
  // Clean up the request-specific context when request is truly complete
  if (*con_cls != nullptr) {
    std::string *body = static_cast<std::string *>(*con_cls);
    delete body;
    *con_cls = nullptr;
  }
}

MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                           const char *url, const char *method,
                           const char *version, const char *upload_data,
                           size_t *upload_data_size, void **con_cls) {
  std::string method_str(method);
  bool is_push = method_str == "POST" || method_str == "PUT";
  
  // Initialize request context on first call
  if (*con_cls == nullptr) {
    // Allocate unique state for each request to avoid race conditions
    *con_cls = new std::string();
    return MHD_YES;
  }
  
  // Accumulate request body data for POST/PUT requests
  if (is_push && *upload_data_size) {
    std::string *body = static_cast<std::string *>(*con_cls);
    body->append(upload_data, *upload_data_size);
    *upload_data_size = 0;
    return MHD_YES;
  }

  std::string url_str(url);

  // Handle client creation endpoint
  if (is_push && url_str == "/client") {
    std::string *body = static_cast<std::string*>(*con_cls);
    return handle_create_client(connection, *body);
  }

  // Handle object operations
  if (url_str.find("/object/") == 0) {
    std::string path = url_str.substr(8); // Remove "/object/"
    size_t slash_pos = path.find('/');
    if (slash_pos != std::string::npos) {
      std::string bucket = path.substr(0, slash_pos);
      std::string key = path.substr(slash_pos + 1);
      std::string client_id = get_header_value(connection, "clientid");
      std::string metadata = get_header_value(connection, "content-metadata");
      
      if (method_str == "GET") {
        return handle_get_object(connection, bucket, key, client_id, metadata);
      } else if (method_str == "PUT") {
        std::string *body = static_cast<std::string *>(*con_cls);
        return handle_put_object(connection, bucket, key, client_id, *body, metadata);
      } else {
        return send_response(connection, 405, "{\"error\":\"Method not allowed\"}");
      }
    }
  }

  // Return error for unrecognized endpoints
  return send_response(connection, 404,
                       "{\"error\":\"Not idea what is happening\"}");
}

int main() {
  Aws::SDKOptions options;
  Aws::InitAPI(options);
  int port = 8097;

  struct MHD_Daemon *daemon =
      MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD, port, NULL, NULL,
                       &request_handler, NULL,
                       MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
                       MHD_OPTION_CONNECTION_LIMIT, 250,
                       MHD_OPTION_CONNECTION_TIMEOUT, 30,
                       MHD_OPTION_END);

  if (!daemon) {
    fprintf(stderr, "Failed to start server on port %d\n", port);
    Aws::ShutdownAPI(options);
    return 1;
  }

  fprintf(stderr, "Server running on port %d\n", port);
  sleep(10000);

  MHD_stop_daemon(daemon);
  Aws::ShutdownAPI(options);
  fprintf(stderr, "Ending server\n");
  return 0;
}
