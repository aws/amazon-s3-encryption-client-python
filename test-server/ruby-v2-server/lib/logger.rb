require 'logger'
require 'securerandom'

# Centralized logging utility for the S3EC Ruby server
class S3ECLogger
  def self.instance
    @instance ||= new
  end

  def initialize
    @logger = Logger.new(STDOUT)
    @logger.level = ENV['LOG_LEVEL'] ? Logger.const_get(ENV['LOG_LEVEL'].upcase) : Logger::INFO
    @logger.formatter = proc do |severity, datetime, progname, msg|
      "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] #{severity}: #{msg}\n"
    end
  end

  # Generate a unique request ID for correlation
  def self.generate_request_id
    SecureRandom.hex(8)
  end

  # Request/Response logging
  def self.log_request(method, path, headers = {}, request_id = nil)
    client_id = headers['HTTP_CLIENTID'] || headers['ClientID'] || 'none'
    content_metadata = headers['HTTP_CONTENT_METADATA'] || headers['Content-Metadata'] || 'none'
    
    instance.logger.info("REQUEST [#{request_id}] #{method} #{path} | ClientID: #{client_id} | Metadata: #{content_metadata}")
  end

  def self.log_response(status, request_id = nil, additional_info = "")
    info_str = additional_info.empty? ? "" : " | #{additional_info}"
    instance.logger.info("RESPONSE [#{request_id}] Status: #{status}#{info_str}")
  end

  # Operation-level logging
  def self.log_client_creation(config, client_id)
    kms_key = config.dig('keyMaterial', 'kmsKeyId') || 'unknown'
    legacy_enabled = config['enableLegacyWrappingAlgorithms'] || false
    instance.logger.info("CLIENT_CREATION: Created S3EC client #{client_id} | KMS Key: #{kms_key} | Legacy: #{legacy_enabled}")
  end

  def self.log_client_cache_hit(client_id)
    instance.logger.debug("CACHE_HIT: Found client #{client_id} in cache")
  end

  def self.log_client_cache_miss(client_id)
    instance.logger.warn("CACHE_MISS: Client #{client_id} not found in cache")
  end

  def self.log_cache_stats(cache_size)
    instance.logger.debug("CACHE_STATS: Current client cache size: #{cache_size}")
  end

  def self.log_s3_operation(operation, bucket, key, encryption_context = {}, additional_info = "")
    enc_ctx_str = encryption_context.empty? ? "none" : encryption_context.inspect
    info_str = additional_info.empty? ? "" : " | #{additional_info}"
    instance.logger.info("S3_OPERATION: #{operation.upcase} s3://#{bucket}/#{key} | EncCtx: #{enc_ctx_str}#{info_str}")
  end

  def self.log_metadata_processing(operation, input, output)
    instance.logger.debug("METADATA_#{operation.upcase}: Input: #{input.inspect} | Output: #{output.inspect}")
  end

  # Enhanced error logging
  def self.log_error(error, context = {}, request_id = nil)
    error_context = context.empty? ? "" : " | Context: #{context.inspect}"
    instance.logger.error("ERROR [#{request_id}] #{error.class}: #{error.message}#{error_context}")
    
    if error.backtrace && instance.debug?
      instance.logger.debug("ERROR_BACKTRACE [#{request_id}]:\n#{error.backtrace.join("\n")}")
    end
  end

  def self.log_validation_error(field, value, request_id = nil)
    instance.logger.warn("VALIDATION_ERROR [#{request_id}] Invalid #{field}: #{value}")
  end

  def self.log_aws_error(error, operation, request_id = nil)
    instance.logger.error("AWS_ERROR [#{request_id}] #{operation} failed: #{error.class} - #{error.message}")
  end

  # Standard logging methods
  def self.debug(message)
    instance.logger.debug(message)
  end

  def self.info(message)
    instance.logger.info(message)
  end

  def self.warn(message)
    instance.logger.warn(message)
  end

  def self.error(message)
    instance.logger.error(message)
  end

  attr_reader :logger

  def debug?
    @logger.debug?
  end
end
