require 'concurrent-ruby'
require 'securerandom'
require 'aws-sdk-s3'
require 'aws-sdk-kms'
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
    # Extract configuration
    kms_key_id = config.dig('keyMaterial', 'kmsKeyId')
    
    raise 'KMS Key ID is required' if kms_key_id.nil? || kms_key_id.empty?

    # Create S3 encryption client configuration
    encryption_config = {
      kms_key_id: kms_key_id,
      kms_client: @kms_client,
      key_wrap_schema: :kms_context,
      # content_encryption_schema: :aes_gcm_no_padding,
    }.tap do |hash|
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
    s3_client = Aws::S3::Client.new(region: 'us-west-2')
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
