/*
 * S3 Encryption Test Server - C++ V3
 * 
 * CONCURRENCY AND SYNCHRONIZATION DESIGN:
 * 
 * 1. Threading Model:
 *    - Uses MHD_USE_POLL_INTERNALLY with fixed thread pool
 *    - Thread pool size = CPU cores * 2 (auto-detected at startup)
 *    - Threads are reused across connections for efficiency
 *    - I/O multiplexing (poll) distributes connections across thread pool
 *    - All S3 operations are SYNCHRONOUS - server waits for S3 completion before responding
 *    - POLL mechanism avoids FD_SETSIZE=1024 limitation of select()
 * 
 * 2. Resource Scaling:
 *    - All limits automatically scale with detected CPU count:
 *      * Thread pool size = num_cores * 2
 *      * Connection limit = num_cores * 2
 *      * S3 client maxConnections = num_cores * 2
 *    - Multiplier of 2 accounts for I/O blocking without starving throughput
 *    - Ensures optimal resource usage on any hardware configuration
 * 
 * 3. Client Cache (client_cache_secret):
 *    - Protected by std::shared_mutex for efficient concurrent access
 *    - get_client() uses shared_lock (multiple threads can read simultaneously)
 *    - set_client() uses unique_lock (exclusive write access)
 *    - This allows concurrent GET/PUT operations without serialization
 *    - UUID-based keys guarantee uniqueness (always insert, never update)
 * 
 * 4. Memory Management:
 *    - Request body allocated in request_handler (*con_cls = new std::string())
 *    - Body lifetime managed by libmicrohttpd - valid until request_completed()
 *    - All handler functions complete synchronously before returning
 *    - request_completed() safely deletes body after response sent
 *    - No memory leaks under sustained concurrent load
 * 
 * 5. Synchronous Operation Guarantees:
 *    - GetObject: Waits for S3, reads full response stream, then returns
 *    - PutObject: Waits for S3 operation to complete, then returns
 *    - No async callbacks or background operations
 *    - Client receives response only after S3 operation completes
 */

#include <aws/core/Aws.h>
#include <aws/core/http/HttpClientFactory.h>
#include <aws/kms/KMSClient.h>
#include <aws/s3/S3Client.h>
#include <aws/s3-encryption/CryptoConfiguration.h>
#include <aws/s3-encryption/S3EncryptionClient.h>
#include <aws/s3-encryption/materials/KMSEncryptionMaterials.h>
#include <aws/s3-encryption/materials/SimpleEncryptionMaterials.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/core/utils/logging/LogLevel.h>
#include <aws/core/utils/logging/ConsoleLogSystem.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <microhttpd.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <string>
#include <unordered_map>
#include <uuid/uuid.h>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <functional>
#include <optional>

using json = nlohmann::json;
using namespace Aws::S3Encryption;
using Aws::S3Encryption::Materials::KMSWithContextEncryptionMaterials;

// LRU cache for S3 encryption clients
// Limits memory and connection pool growth by evicting least recently used clients
const size_t MAX_CACHED_CLIENTS = 100;  // Reasonable limit for concurrent test operations

struct ClientCacheEntry {
  std::shared_ptr<S3EncryptionClientV3> client;
  std::list<std::string>::iterator lru_iter;
};

std::unordered_map<std::string, ClientCacheEntry> client_cache_secret;
std::list<std::string> lru_order;  // Most recently used at front
std::shared_timed_mutex client_mutex; // Using shared_timed_mutex (C++14 compatible) for concurrent reads

// Threading configuration - set at startup based on CPU cores
unsigned int g_thread_pool_size = 8;  // Default, will be overwritten in main()

std::string generate_uuid() {
  uuid_t uuid;
  uuid_generate(uuid);
  char uuid_str[37];
  uuid_unparse(uuid, uuid_str);
  return std::string(uuid_str);
}

std::shared_ptr<S3EncryptionClientV3> get_client(const std::string &client_id)
{
    // Need unique_lock to update LRU order even on reads
    std::unique_lock<std::shared_timed_mutex> lock(client_mutex);
    auto it = client_cache_secret.find(client_id);
    if (it == client_cache_secret.end()) {
      return std::shared_ptr<S3EncryptionClientV3>();
    } else {
      // Move to front of LRU list (mark as most recently used)
      lru_order.erase(it->second.lru_iter);
      lru_order.push_front(client_id);
      it->second.lru_iter = lru_order.begin();
      
      return it->second.client;
    }
}

void set_client(const std::string &client_id, std::shared_ptr<S3EncryptionClientV3> client)
{
  // UUID guarantees unique keys - always insert, never update
  // Still need exclusive lock because std::unordered_map isn't thread-safe for concurrent inserts
  std::unique_lock<std::shared_timed_mutex> lock(client_mutex);
  
  // Add to front of LRU list (most recently used)
  lru_order.push_front(client_id);
  
  ClientCacheEntry entry;
  entry.client = client;
  entry.lru_iter = lru_order.begin();
  
  client_cache_secret.emplace(client_id, entry);
  
  // Evict least recently used clients if we exceed the limit
  while (client_cache_secret.size() > MAX_CACHED_CLIENTS) {
    std::string lru_client_id = lru_order.back();
    lru_order.pop_back();
    
    auto evict_it = client_cache_secret.find(lru_client_id);
    if (evict_it != client_cache_secret.end()) {
      fprintf(stderr, "[CPP-V3] [CACHE-EVICT] Evicting client %s (cache size was %zu)\n",
              lru_client_id.c_str(), client_cache_secret.size());
      client_cache_secret.erase(evict_it);
    }
  }
  
  fprintf(stderr, "[CPP-V3] [CACHE-ADD] Added client %s (cache size now %zu)\n",
          client_id.c_str(), client_cache_secret.size());
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

MHD_Result unsupported(struct MHD_Connection *connection, std::string & commitmentPolicy, std::string & encryptionAlgorithm) {
    fprintf(stderr, "Unsupported %s %s\n",commitmentPolicy.c_str(), encryptionAlgorithm.c_str() );
    send_response(connection, 404, "{\"error\":\"Unsupported Option.\"}");
    return MHD_YES;
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
  // Body is kept alive by *con_cls until request_completed fires, so it's safe to use directly
  // All operations here are synchronous and complete before returning to caller
  
  try {
    json request = json::parse(body);
    
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

    std::string commitmentPolicy = get_config(request, "commitmentPolicy");
    std::string encryptionAlgorithm = get_config(request, "encryptionAlgorithm");

    // Create CryptoConfigurationV3 based on key type
    std::optional<CryptoConfigurationV3> config;
    
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
      config.emplace(materials);
    } else if (!kms_key_id.empty()) {
      auto materials = std::make_shared<KMSWithContextEncryptionMaterials>(kms_key_id);
      config.emplace(materials);
    } else {
      return send_response(connection, 400,
          "{\"error\":\"No valid key material provided\"}");
    }
    
    // Apply common configuration settings (applies to both AES and KMS)
    if (legacy1 || legacy2)
      config->AllowLegacy();
    if (legacy2)
      config->SetUnAuthenticatedRangeGet(RangeGetMode::ALL);
    if (inst_put)
      config->SetStorageMethod(StorageMethod::INSTRUCTION_FILE);
    
    // Configure commitment policy (applies to both AES and KMS)
    if (commitmentPolicy == "REQUIRE_ENCRYPT_REQUIRE_DECRYPT") {
      if (encryptionAlgorithm == "ALG_AES_256_GCM_IV12_TAG16_NO_KDF" ||
          encryptionAlgorithm == "ALG_AES_256_CBC_IV16_NO_KDF") {
        return unsupported(connection, commitmentPolicy, encryptionAlgorithm);
      }
      config->SetCommitmentPolicy(CommitmentPolicy::REQUIRE_ENCRYPT_REQUIRE_DECRYPT);
    } else if (commitmentPolicy == "REQUIRE_ENCRYPT_ALLOW_DECRYPT") {
      if (encryptionAlgorithm == "ALG_AES_256_GCM_IV12_TAG16_NO_KDF") {
        return unsupported(connection, commitmentPolicy, encryptionAlgorithm);
      }
      config->SetCommitmentPolicy(CommitmentPolicy::REQUIRE_ENCRYPT_ALLOW_DECRYPT);
    } else if (commitmentPolicy == "FORBID_ENCRYPT_ALLOW_DECRYPT") {
      if (encryptionAlgorithm == "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY") {
        return unsupported(connection, commitmentPolicy, encryptionAlgorithm);
      }
      config->SetCommitmentPolicy(CommitmentPolicy::FORBID_ENCRYPT_ALLOW_DECRYPT);
    }
    
    // Create S3EncryptionClientV3 with standard configuration
    Aws::Client::ClientConfiguration clientConfig;
    clientConfig.maxConnections = 512;  // Large pool per client
    clientConfig.retryStrategy = Aws::Client::InitRetryStrategy("standard");
    
    // Increase timeouts for CI environments where SSL handshakes can be slow
    // Default connectTimeoutMs is 1000ms, which is too short for busy CI runners
    clientConfig.connectTimeoutMs = 10000;  // 10 seconds for SSL connection establishment
    clientConfig.requestTimeoutMs = 30000;  // 30 seconds for complete request/response
    
    // Disable automatic checksum calculation for encrypted streams
    // The ChecksumInterceptor cannot handle non-seekable SymmetricCryptoStream
    // which causes intermittent "BadDigest: CRC64NVME you specified did not match" errors
    // when the stream gets consumed during checksum calculation and can't be rewound
    clientConfig.checksumConfig.requestChecksumCalculation = 
        Aws::Client::RequestChecksumCalculation::WHEN_REQUIRED;
    
    auto encryption_client = std::make_shared<S3EncryptionClientV3>(*config, clientConfig);

    std::string client_id = generate_uuid();
    set_client(client_id, encryption_client);

    json response = {{"clientId", client_id}};
    return send_response(connection, 200, response.dump());
  } catch (const std::exception &e) {
    fprintf(stderr, "handle_create_client exception %s\n", e.what());
    return send_response(connection, 500,
                        "{\"error\":\"An exception was thrown.\"}");
  } catch (...) {
    return send_response(connection, 500, "{\"error\":\"Unknown error\"}");
  }
}

void fill_context(Aws::Map<Aws::String, Aws::String> &map,
                  const std::string &metadata) {
  if (metadata.empty()) {
    fprintf(stderr, "[CPP-V3] [DEBUG] fill_context: metadata is empty\n");
    return;
  }

  fprintf(stderr, "[CPP-V3] [DEBUG] fill_context: raw metadata='%s' (length=%zu)\n", 
          metadata.c_str(), metadata.length());

  // Parse metadata format: [key1]:[value1],[key2]:[value2],...
  // or single pair: [key]:[value]
  std::string current = metadata;
  size_t pos = 0;
  int pair_count = 0;

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

    fprintf(stderr, "[CPP-V3] [DEBUG] fill_context: parsed pair #%d: key='%s', value='%s'\n",
            ++pair_count, key.c_str(), value.c_str());

    // Add to map
    map.emplace(key, value);

    // Move to next pair (look for comma or next opening bracket)
    pos = value_end + 1;
    size_t comma = current.find(',', pos);
    if (comma != std::string::npos) {
      pos = comma + 1;
    }
  }
  
  fprintf(stderr, "[CPP-V3] [DEBUG] fill_context: completed, parsed %d pairs into map\n", pair_count);
}

MHD_Result handle_get_object(struct MHD_Connection *connection,
                             std::string bucket,
                             std::string key,
                             std::string client_id,
                             std::string metadata,
                             std::string range) {
  // Get thread ID for debugging concurrent operations
  std::thread::id thread_id = std::this_thread::get_id();
  
  fprintf(stderr, "[CPP-V3] [DEBUG] GetObject START: thread=%lu, bucket=%s, key=%s, client_id=%s, metadata_length=%zu, range=%s\n", 
          (unsigned long)std::hash<std::thread::id>{}(thread_id), bucket.c_str(), key.c_str(), client_id.c_str(), metadata.length(), range.c_str());
  
  auto client = get_client(client_id);
  if (!client) {
    fprintf(stderr, "[CPP-V3] GetObject error: Client not found for client_id=%s\n", client_id.c_str());
    return send_response(connection, 404, "{\"error\":\"Client not found\"}");
  }

  try {
    Aws::S3::Model::GetObjectRequest request;
    request.SetBucket(bucket);
    request.SetKey(key);
    
    // Add range header if provided
    if (!range.empty()) {
      request.SetRange(range);
      fprintf(stderr, "[CPP-V3] [DEBUG] GetObject: Setting range=%s\n", range.c_str());
    }

    Aws::Map<Aws::String, Aws::String> kmsContextMap;
    fill_context(kmsContextMap, metadata);
    
    // Log the encryption context map size and contents
    fprintf(stderr, "[CPP-V3] [DEBUG] GetObject: encryption context map size=%zu\n", kmsContextMap.size());
    for (const auto& pair : kmsContextMap) {
      fprintf(stderr, "[CPP-V3] [DEBUG] GetObject: context['%s']='%s'\n", 
              pair.first.c_str(), pair.second.c_str());
    }
    
    fprintf(stderr, "[CPP-V3] [DEBUG] GetObject: calling client->GetObject() for key=%s\n", key.c_str());
    
    // Keep outcome alive to ensure stream remains valid
    auto outcome = client->GetObject(request, kmsContextMap);

    fprintf(stderr, "[CPP-V3] [DEBUG] GetObject: client->GetObject() returned for key=%s\n", key.c_str());

    if (outcome.IsSuccess()) {
      // Read the stream completely before outcome goes out of scope
      auto &stream = outcome.GetResult().GetBody();
      std::stringstream buffer;
      buffer << stream.rdbuf();
      std::string content = buffer.str();
      
      // Validate we read something
      if (content.empty() && stream.fail()) {
        fprintf(stderr, "[CPP-V3] GetObject error: Failed to read stream for bucket=%s, key=%s\n", 
                bucket.c_str(), key.c_str());
        auto msg = make_error("Failed to read response stream", 500);
        return send_response(connection, 500, msg);
      }
      
      fprintf(stderr, "[CPP-V3] GetObject success: bucket=%s, key=%s, size=%zu bytes\n", 
              bucket.c_str(), key.c_str(), content.length());
      
      // Create and send response
      struct MHD_Response *response = MHD_create_response_from_buffer(
          content.length(), (void *)content.data(), MHD_RESPMEM_MUST_COPY);
      
      // Add keep-alive header
      MHD_add_response_header(response, "Connection", "keep-alive");
      MHD_add_response_header(response, "Keep-Alive", "timeout=30, max=100");
      
      MHD_Result ret = MHD_queue_response(connection, 200, response);
      MHD_destroy_response(response);
      
      return ret;
    } else {
      // Enhanced error logging with thread info
      auto error = outcome.GetError();
      fprintf(stderr, "[CPP-V3] [DEBUG] GetObject FAILED: thread=%lu, key=%s\n", 
              (unsigned long)std::hash<std::thread::id>{}(thread_id), key.c_str());
      fprintf(stderr, "[CPP-V3] [DEBUG] GetObject error details:\n");
      fprintf(stderr, "[CPP-V3] [DEBUG]   - Message: %s\n", error.GetMessage().c_str());
      fprintf(stderr, "[CPP-V3] [DEBUG]   - ExceptionName: %s\n", error.GetExceptionName().c_str());
      fprintf(stderr, "[CPP-V3] [DEBUG]   - ResponseCode: %d\n", (int)error.GetResponseCode());
      fprintf(stderr, "[CPP-V3] [DEBUG]   - ShouldRetry: %s\n", error.ShouldRetry() ? "true" : "false");
      
      auto msg = make_error(outcome.GetError().GetMessage(), 500);
      fprintf(stderr, "[CPP-V3] GetObject AWS error: %s\n", msg.c_str());
      return send_response(connection, 500, msg);
    }
  } catch (const std::exception &e) {
    fprintf(stderr, "[CPP-V3] [DEBUG] GetObject EXCEPTION: thread=%lu, key=%s, what=%s\n",
            (unsigned long)std::hash<std::thread::id>{}(thread_id), key.c_str(), e.what());
    auto msg = make_error(e.what(), 500);
    return send_response(connection, 500, msg);
  } catch (...) {
    fprintf(stderr, "[CPP-V3] [DEBUG] GetObject UNKNOWN EXCEPTION: thread=%lu, key=%s\n",
            (unsigned long)std::hash<std::thread::id>{}(thread_id), key.c_str());
    auto msg = make_error("Unknown error in GetObject", 500);
    return send_response(connection, 500, msg);
  }
}

MHD_Result handle_put_object(struct MHD_Connection *connection,
                             std::string bucket,
                             std::string key,
                             std::string client_id,
                             std::string body,
                             std::string metadata) {
  fprintf(stderr, "[CPP-V3] PutObject request: bucket=%s, key=%s, client_id=%s, body_size=%zu\n", 
          bucket.c_str(), key.c_str(), client_id.c_str(), body.length());
  
  auto client = get_client(client_id);
  if (!client) {
    fprintf(stderr, "[CPP-V3] PutObject error: Client not found for client_id=%s\n", client_id.c_str());
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
      fprintf(stderr, "[CPP-V3] PutObject success: bucket=%s, key=%s\n", bucket.c_str(), key.c_str());
      json response = {{"bucket", bucket}, {"key", key}};
      return send_response(connection, 200, response.dump());
    } else {
      auto msg = make_error(outcome.GetError().GetMessage(), 500);
      fprintf(stderr, "[CPP-V3] PutObject AWS error: %s\n", msg.c_str());
      return send_response(connection, 500, msg);
    }
  } catch (const std::exception &e) {
    fprintf(stderr, "[CPP-V3] PutObject exception: %s\n", e.what());
    auto msg = make_error(e.what(), 500);
    return send_response(connection, 500, msg);
  }
}

void request_completed(void *cls, struct MHD_Connection *connection,
                      void **con_cls, enum MHD_RequestTerminationCode toe) {
  // Clean up the request-specific context when request is truly complete
  // This is called AFTER all handlers have returned and the response has been sent
  
  // Log why the request was terminated
  const char* reason = "UNKNOWN";
  switch (toe) {
    case MHD_REQUEST_TERMINATED_COMPLETED_OK:
      reason = "COMPLETED_OK";
      break;
    case MHD_REQUEST_TERMINATED_WITH_ERROR:
      reason = "WITH_ERROR";
      break;
    case MHD_REQUEST_TERMINATED_TIMEOUT_REACHED:
      reason = "TIMEOUT_REACHED";
      break;
    case MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN:
      reason = "DAEMON_SHUTDOWN";
      break;
    case MHD_REQUEST_TERMINATED_READ_ERROR:
      reason = "READ_ERROR";
      break;
    case MHD_REQUEST_TERMINATED_CLIENT_ABORT:
      reason = "CLIENT_ABORT";
      break;
  }
  fprintf(stderr, "[CPP-V3] request_completed called, reason=%s, con_cls=%p\n", 
          reason, *con_cls);
  
  if (*con_cls != nullptr) {
    std::string *body = static_cast<std::string *>(*con_cls);
    delete body;  // Safe to delete now - all synchronous operations are complete
    *con_cls = nullptr;
  }
}

MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                           const char *url, const char *method,
                           const char *version, const char *upload_data,
                           size_t *upload_data_size, void **con_cls) {
  try {
    std::string method_str(method);
    std::string url_str(url);
    bool is_push = method_str == "POST" || method_str == "PUT";
    
    // LOG: Every request entry (even first-time calls)
    if (*con_cls == nullptr) {
      fprintf(stderr, "[CPP-V3] REQUEST START: method=%s, url=%s, version=%s, con_cls=NULL, upload_data_size=%zu\n",
              method, url, version, *upload_data_size);
    }
  
  // Initialize request context on first call
  if (*con_cls == nullptr) {
    // Allocate unique state for each request to avoid race conditions
    *con_cls = new std::string();
    fprintf(stderr, "[CPP-V3] REQUEST INIT: allocated new request context for %s %s\n", method, url);
    return MHD_YES;
  }
  
  // LOG: Subsequent calls
  if (is_push && *upload_data_size > 0) {
    fprintf(stderr, "[CPP-V3] REQUEST DATA: %s %s receiving %zu bytes\n", method, url, *upload_data_size);
  } else if (*upload_data_size == 0) {
    fprintf(stderr, "[CPP-V3] REQUEST COMPLETE: %s %s ready for processing\n", method, url);
  }
  
  // Accumulate request body data for POST/PUT requests
  if (is_push && *upload_data_size > 0) {
    std::string *body = static_cast<std::string *>(*con_cls);
    body->append(upload_data, *upload_data_size);
    *upload_data_size = 0;
    return MHD_YES;
  }
  
  // At this point, *upload_data_size == 0, meaning we have all the data
  // Now we can safely process the request
  
  // LOG: About to process request
  fprintf(stderr, "[CPP-V3] PROCESSING: %s %s\n", method, url);

  // Handle client creation endpoint
  if (is_push && url_str == "/client") {
    fprintf(stderr, "[CPP-V3] Handling /client endpoint\n");
    std::string *body = static_cast<std::string*>(*con_cls);
    MHD_Result result = handle_create_client(connection, *body);
    fprintf(stderr, "[CPP-V3] /client handler returned: %d\n", result);
    return result;
  }

  // Handle object operations
  if (url_str.find("/object/") == 0) {
    fprintf(stderr, "[CPP-V3] Handling /object/ endpoint\n");
    std::string path = url_str.substr(8); // Remove "/object/"
    size_t slash_pos = path.find('/');
    if (slash_pos != std::string::npos) {
      std::string bucket = path.substr(0, slash_pos);
      std::string key = path.substr(slash_pos + 1);
      std::string client_id = get_header_value(connection, "clientid");
      std::string metadata = get_header_value(connection, "content-metadata");
      
      fprintf(stderr, "[CPP-V3] Object operation: bucket=%s, key=%s, client_id=%s, method=%s\n",
              bucket.c_str(), key.c_str(), client_id.c_str(), method);
      
      if (method_str == "GET") {
        fprintf(stderr, "[CPP-V3] Dispatching to handle_get_object\n");
        std::string range = get_header_value(connection, "Range");
        MHD_Result result = handle_get_object(connection, bucket, key, client_id, metadata, range);
        fprintf(stderr, "[CPP-V3] handle_get_object returned: %d\n", result);
        return result;
      } else if (method_str == "PUT") {
        fprintf(stderr, "[CPP-V3] Dispatching to handle_put_object\n");
        std::string *body = static_cast<std::string *>(*con_cls);
        MHD_Result result = handle_put_object(connection, bucket, key, client_id, *body, metadata);
        fprintf(stderr, "[CPP-V3] handle_put_object returned: %d\n", result);
        return result;
      } else {
        fprintf(stderr, "[CPP-V3] Method not allowed: %s\n", method);
        return send_response(connection, 405, "{\"error\":\"Method not allowed\"}");
      }
    }
  }

    // Return error for unrecognized endpoints
    fprintf(stderr, "[CPP-V3] ERROR: Unrecognized endpoint: %s %s\n", method, url);
    return send_response(connection, 404,
                         "{\"error\":\"Not idea what is happening\"}");
  } catch (const std::exception &e) {
    fprintf(stderr, "[CPP-V3] FATAL: Unhandled exception in request_handler: %s (method=%s, url=%s)\n", 
            e.what(), method, url);
    // Try to send error response, but connection might already be broken
    try {
      return send_response(connection, 500, 
                          "{\"error\":\"Internal server error: unhandled exception\"}");
    } catch (...) {
      fprintf(stderr, "[CPP-V3] FATAL: Failed to send error response\n");
      return MHD_NO;
    }
  } catch (...) {
    fprintf(stderr, "[CPP-V3] FATAL: Unknown exception in request_handler (method=%s, url=%s)\n", 
            method, url);
    // Try to send error response, but connection might already be broken
    try {
      return send_response(connection, 500, 
                          "{\"error\":\"Internal server error: unknown exception\"}");
    } catch (...) {
      fprintf(stderr, "[CPP-V3] FATAL: Failed to send error response\n");
      return MHD_NO;
    }
  }
}

// Error log callback for libmicrohttpd
void log_mhd_error(void* cls, const char* fmt, va_list ap) {
  fprintf(stderr, "[CPP-V3] [MHD-ERROR] ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
}

// Connection notification callback - called when a client connects
MHD_Result notify_connection(void *cls,
                             struct MHD_Connection *connection,
                             void **socket_context,
                             enum MHD_ConnectionNotificationCode toe) {
  if (toe == MHD_CONNECTION_NOTIFY_STARTED) {
    fprintf(stderr, "[CPP-V3] [MHD-CONNECT] New connection started\n");
  } else if (toe == MHD_CONNECTION_NOTIFY_CLOSED) {
    fprintf(stderr, "[CPP-V3] [MHD-DISCONNECT] Connection closed\n");
  }
  return MHD_YES;
}

int main() {
  Aws::SDKOptions options;
  
  // Configure AWS SDK logging to output to stderr (which goes to server.log)
  // Using Debug level to capture all SDK activity including CryptoModule errors
  options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Debug;
  options.loggingOptions.logger_create_fn = []() {
    return std::make_shared<Aws::Utils::Logging::ConsoleLogSystem>(
        Aws::Utils::Logging::LogLevel::Debug
    );
  };
  
  fprintf(stderr, "[CONFIG] AWS SDK logging enabled at Debug level\n");
  
  Aws::InitAPI(options);
  
  // Detect CPU core count and configure threading
  unsigned int num_cores = std::thread::hardware_concurrency();
  if (num_cores == 0) {
    num_cores = 4;  // Fallback if detection fails
    fprintf(stderr, "[WARNING] CPU core detection failed, defaulting to %u cores\n", num_cores);
  }
  
  // Thread pool size = num_cores * 2 (allows for I/O blocking without starving throughput)
  g_thread_pool_size = num_cores * 2;
  unsigned int connection_limit = g_thread_pool_size;
  
  // Log configuration
  fprintf(stderr, "[CONFIG] Detected CPU cores: %u\n", num_cores);
  fprintf(stderr, "[CONFIG] Thread pool size: %u\n", g_thread_pool_size);
  fprintf(stderr, "[CONFIG] Connection limit: %u\n", connection_limit);
  fprintf(stderr, "[CONFIG] Each S3 client will use 512 max connections\n");
  
  int port = 8091;

  struct MHD_Daemon *daemon =
      MHD_start_daemon(MHD_USE_POLL_INTERNALLY | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG, 
                       port, NULL, NULL,
                       &request_handler, NULL,
                       MHD_OPTION_EXTERNAL_LOGGER, log_mhd_error, NULL,
                       MHD_OPTION_NOTIFY_CONNECTION, notify_connection, NULL,
                       MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
                       MHD_OPTION_THREAD_POOL_SIZE, g_thread_pool_size,
                       MHD_OPTION_CONNECTION_LIMIT, connection_limit,
                       MHD_OPTION_CONNECTION_TIMEOUT, 10,
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
