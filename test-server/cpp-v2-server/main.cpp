#include <aws/core/Aws.h>
#include <aws/kms/KMSClient.h>
#include <aws/s3-encryption/CryptoConfiguration.h>
#include <aws/s3-encryption/S3EncryptionClient.h>
#include <aws/s3-encryption/materials/KMSEncryptionMaterials.h>
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
std::unordered_map<std::string, std::shared_ptr<S3EncryptionClientV2>>
    client_cache;

std::string generate_uuid() {
  uuid_t uuid;
  uuid_generate(uuid);
  char uuid_str[37];
  uuid_unparse(uuid, uuid_str);
  return std::string(uuid_str);
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

MHD_Result handle_create_client(struct MHD_Connection *connection,
                                const std::string &body) {
  try {
    json request = json::parse(body);
    std::string kms_key_id = request["config"]["keyMaterial"]["kmsKeyId"];
    bool legacy = request["config"]["enableLegacyWrappingAlgorithms"];

    Aws::KMS::KMSClient kms_client;
    auto materials =
        std::make_shared<KMSWithContextEncryptionMaterials>(kms_key_id);
    CryptoConfigurationV2 config(materials);
    if (legacy) {
      config.SetSecurityProfile(SecurityProfile::V2_AND_LEGACY);
    } else {
      config.SetSecurityProfile(SecurityProfile::V2);
    }

    auto encryption_client = std::make_shared<S3EncryptionClientV2>(config);

    std::string client_id = generate_uuid();
    client_cache[client_id] = encryption_client;

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
  auto it = client_cache.find(client_id);
  if (it == client_cache.end()) {
    return send_response(connection, 404, "{\"error\":\"Client not found\"}");
  }

  try {
    Aws::S3::Model::GetObjectRequest request;
    request.SetBucket(bucket);
    request.SetKey(key);

    // S3EncryptionGetObjectOutcome outcome ;
    // if (metadata.empty()) {
    //   outcome = it->second->GetObject(request);
    // } else {
    //   Aws::Map<Aws::String, Aws::String> kmsContextMap;
    //   fill_context(kmsContextMap, metadata);
    //   outcome = it->second->GetObject(request, kmsContextMap);
    // }

    Aws::Map<Aws::String, Aws::String> kmsContextMap;
    fill_context(kmsContextMap, metadata);
    auto outcome = it->second->GetObject(request, kmsContextMap);

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
  auto it = client_cache.find(client_id);
  if (it == client_cache.end()) {
    return send_response(connection, 404, "{\"error\":\"Client not found\"}");
  }

  try {
    Aws::Map<Aws::String, Aws::String> kmsContextMap;
    fill_context(kmsContextMap, metadata);

    Aws::S3::Model::PutObjectRequest request;
    request.SetBucket(bucket);
    request.SetKey(key);

    auto stream = std::make_shared<std::stringstream>(body);
    request.SetBody(stream);

    auto outcome = it->second->PutObject(request, kmsContextMap);
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

MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                           const char *url, const char *method,
                           const char *version, const char *upload_data,
                           size_t *upload_data_size, void **con_cls) {
  std::string method_str(method);
  bool is_push = method_str == "POST" || method_str == "PUT";
  static int dummy;
  if (*con_cls == nullptr) {
    if (is_push) {
      *con_cls = new std::string();
    } else {
      *con_cls = &dummy;
    }
    return MHD_YES;
  }
  if (is_push && *upload_data_size) {
    std::string *body = static_cast<std::string *>(*con_cls);
    body->append(upload_data, *upload_data_size);
    *upload_data_size = 0;
    return MHD_YES;
  }

  std::string url_str(url);

  if (is_push && url_str == "/client") {
    std::unique_ptr<std::string> body(static_cast<std::string*>(*con_cls));
    return handle_create_client(connection, *body);
  }

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
        std::unique_ptr<std::string> body(static_cast<std::string*>(*con_cls));
        *upload_data_size = 0;
        return handle_put_object(connection, bucket, key, client_id, *body, metadata);
      }
    }
  }

  return send_response(connection, 404,
                       "{\"error\":\"Not idea what is happening\"}");
}

int main() {
  Aws::SDKOptions options;
  Aws::InitAPI(options);

  struct MHD_Daemon *daemon =
      MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, 8085, NULL, NULL,
                       &request_handler, NULL, MHD_OPTION_END);

  if (!daemon) {
    fprintf(stderr, "Failed to start server on port 8085\n");
    Aws::ShutdownAPI(options);
    return 1;
  }

  fprintf(stderr, "Server running on port 8085\n");
  sleep(10000);

  MHD_stop_daemon(daemon);
  Aws::ShutdownAPI(options);
  fprintf(stderr, "Ending server\n");
  return 0;
}
