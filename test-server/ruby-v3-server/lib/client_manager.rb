require 'concurrent-ruby'
require 'securerandom'
require 'aws-sdk-s3'
require 'aws-sdk-kms'
require 'openssl'
require 'base64'
require_relative 'logger'

# Manages S3 Encryption Client instances
class ClientManager
  def initialize
    @client_cache = Concurrent::Hash.new
    @kms_client = Aws::KMS::Client.new(region: 'us-west-2')
    S3ECLogger.info("CLIENT_MANAGER: Initialized with KMS client for us-west-2")
  end

  # Create a new S3 encryption client and return its ID
  def create_client(config)
    # Extract all key material types
    kms_key_id = config.dig('keyMaterial', 'kmsKeyId')
    rsa_key_blob = config.dig('keyMaterial', 'rsaKey')
    aes_key_blob = config.dig('keyMaterial', 'aesKey')
    inst_file_put = config.dig('instructionFileConfig', 'enableInstructionFilePutObject')
    content_alg = config.dig('encryptionAlgorithm')

    # Validate that only one key type is provided
    key_count = [kms_key_id, rsa_key_blob, aes_key_blob].compact.count
    raise 'KeyMaterial must contain exactly one non-null key type' unless key_count == 1

    # translate between canonical AlgSuite and Ruby symbols
    if content_alg.nil? || content_alg == 'ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY'
        content_alg = :alg_aes_256_gcm_hkdf_sha512_commit_key
    elsif content_alg == 'ALG_AES_256_GCM_IV12_TAG16_NO_KDF'
        content_alg = :aes_gcm_no_padding
    else
        raise 'Unknown content encryption algorithm provided: ' + content_alg
    end

    # Create S3 encryption client configuration
    encryption_config = {
      envelope_location: inst_file_put ? :instruction_file : :metadata,
      content_encryption_schema: content_alg
    }

    # Configure based on key type
    if kms_key_id
      encryption_config[:kms_key_id] = kms_key_id
      encryption_config[:kms_client] = @kms_client
      encryption_config[:key_wrap_schema] = :kms_context
    elsif rsa_key_blob
      # Parse RSA private key from PKCS8 format
      key_bytes = Base64.decode64(rsa_key_blob)
      rsa_key = OpenSSL::PKey::RSA.new(key_bytes)
      encryption_config[:encryption_key] = rsa_key
      encryption_config[:key_wrap_schema] = :rsa_oaep_sha1
    elsif aes_key_blob
      # Extract AES key bytes
      key_bytes = Base64.decode64(aes_key_blob)
      encryption_config[:encryption_key] = key_bytes
      encryption_config[:key_wrap_schema] = :aes_gcm
    end

    # Apply additional configuration
    encryption_config.tap do |hash|
      if !config['commitmentPolicy'].nil?
        hash[:commitment_policy] = case config['commitmentPolicy']
          when 'FORBID_ENCRYPT_ALLOW_DECRYPT'
            :forbid_encrypt_allow_decrypt
          when 'REQUIRE_ENCRYPT_ALLOW_DECRYPT'
            :require_encrypt_allow_decrypt
          when 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT'
            :require_encrypt_require_decrypt
          else
            raise "Unsupported commitment_policy " + config['commitmentPolicy']
          end
        if config['commitmentPolicy'] == 'FORBID_ENCRYPT_ALLOW_DECRYPT' && config['encryptionAlgorithm'].nil?
          hash[:content_encryption_schema] = :aes_gcm_no_padding
        end
      end
      if !config['enableLegacyWrappingAlgorithms'].nil? || !config['enableLegacyUnauthenticatedModes'].nil?
        legacy_modes = config['enableLegacyWrappingAlgorithms'] || config['enableLegacyUnauthenticatedModes']
        # Set security profile based on legacy wrapping algorithms setting
        hash[:security_profile] = legacy_modes ? :v3_and_legacy : :v3
      end
    end

    # Create the S3 encryption client
    # Create the S3 encryption client with retry configuration for throttling
    s3_client = Aws::S3::Client.new(
      region: 'us-west-2',
      retry_mode: 'adaptive',
      retry_limit: 5,
      retry_backoff: lambda { |c| sleep(2 ** c.retries * 0.3 * rand) }
    )
    encryption_client = Aws::S3::EncryptionV3::Client.new(
      client: s3_client,
      **encryption_config
    )

    # Generate client ID and store in cache
    client_id = SecureRandom.uuid
    @client_cache[client_id] = encryption_client
    
    # Log client creation
    S3ECLogger.log_client_creation(config, client_id)
    S3ECLogger.log_cache_stats(@client_cache.size)
    
    client_id
  end

  # Get a client by ID
  def get_client(client_id)
    client = @client_cache[client_id]
    if client
      S3ECLogger.log_client_cache_hit(client_id)
    else
      S3ECLogger.log_client_cache_miss(client_id)
    end
    client
  end

  # Remove a client from cache (optional cleanup)
  def remove_client(client_id)
    removed = @client_cache.delete(client_id)
    S3ECLogger.info("CLIENT_CACHE: Removed client #{client_id} from cache") if removed
    S3ECLogger.log_cache_stats(@client_cache.size)
    removed
  end

  # Get cache size (for debugging)
  def cache_size
    @client_cache.size
  end
end
