require 'sinatra'
require 'json'
require_relative 'lib/client_manager'
require_relative 'lib/metadata_utils'
require_relative 'lib/error_handlers'
require_relative 'lib/logger'

class S3ECRubyServer < Sinatra::Base
  configure do
    set :port, 8092
    set :bind, '0.0.0.0'
    set :show_exceptions, false
    set :raise_errors, false
  end

  def initialize
    super
    @client_manager = ClientManager.new
    S3ECLogger.info("S3EC_SERVER: Ruby server initialized on port #{settings.port}")
  end

  # Request logging middleware
  before do
    @request_id = S3ECLogger.generate_request_id
    S3ECLogger.log_request(request.request_method, request.path_info, request.env, @request_id)
  end

  # Response logging middleware
  after do
    S3ECLogger.log_response(response.status, @request_id)
  end

  # Health check endpoint
  get '/health' do
    content_type :json
    { status: 'OK', server: 'Ruby S3EC Test Server', port: settings.port.to_i }.to_json
  end

  # POST /client - Create S3 encryption client
  post '/client' do
    begin
      S3ECLogger.debug("CLIENT_ENDPOINT [#{@request_id}]: Processing client creation request")

      # Parse request body
      request_body = request.body.read
      S3ECLogger.debug("CLIENT_ENDPOINT [#{@request_id}]: Request body size: #{request_body.length} bytes")

      parsed_data = JSON.parse(request_body)
      config = parsed_data['config'] || {}

      S3ECLogger.debug("CLIENT_ENDPOINT [#{@request_id}]: Parsed config: #{config.inspect}")

      # Create client using client manager
      client_id = @client_manager.create_client(config)

      S3ECLogger.info("CLIENT_ENDPOINT [#{@request_id}]: Successfully created client #{client_id}")

      # Return client ID
      content_type :json
      { clientId: client_id }.to_json

    rescue JSON::ParserError => e
      S3ECLogger.log_error(e, { endpoint: '/client', operation: 'JSON parsing' }, @request_id)
      ErrorHandlers.send_generic_server_error(self, "Invalid JSON in request body", 400)
    rescue => e
      S3ECLogger.log_error(e, { endpoint: '/client', operation: 'client creation', config: config }, @request_id)
      ErrorHandlers.send_s3_encryption_client_error(self, "Failed to create client: #{e.message}")
    end
  end

  # PUT /object/{bucket}/{key} - Encrypt and put object
  put '/object/:bucket/:key' do
    bucket = params[:bucket]
    key = params[:key]
    client_id = request.env['HTTP_CLIENTID']

    begin
      S3ECLogger.debug("PUT_ENDPOINT [#{@request_id}]: Processing PUT request for s3://#{bucket}/#{key}")

      # Validate client ID
      unless client_id
        S3ECLogger.log_validation_error('ClientID', 'missing', @request_id)
        ErrorHandlers.send_generic_server_error(self, "ClientID header is required", 400)
      end

      # Get client from cache
      client = @client_manager.get_client(client_id)
      unless client
        S3ECLogger.log_validation_error('ClientID', client_id, @request_id)
        ErrorHandlers.send_generic_server_error(self, "No client found for ClientID: #{client_id}", 404)
      end

      # Get request body
      body = request.body.read
      S3ECLogger.debug("PUT_ENDPOINT [#{@request_id}]: Request body size: #{body.length} bytes")

      # Parse metadata from header
      metadata_header = request.env['HTTP_CONTENT_METADATA'] || ''
      encryption_context = MetadataUtils.string_to_map(metadata_header)
      S3ECLogger.log_metadata_processing('parse', metadata_header, encryption_context)

      # Prepare S3 put_object parameters
      put_params = {
        bucket: bucket,
        key: key,
        body: body
      }

      # Add encryption context if present
      put_params[:kms_encryption_context] = encryption_context unless encryption_context.empty?

      # Log S3 operation
      S3ECLogger.log_s3_operation('put', bucket, key, encryption_context, "ClientID: #{client_id}, BodySize: #{body.length}")

      # Make the put_object request
      response = client.put_object(put_params)

      S3ECLogger.info("PUT_ENDPOINT [#{@request_id}]: Successfully put object s3://#{bucket}/#{key}")

      # Prepare response metadata
      response_metadata = MetadataUtils.map_to_array(encryption_context)
      S3ECLogger.log_metadata_processing('response', encryption_context, response_metadata)

      # Return response matching Smithy model
      content_type :json
      {
        bucket: bucket,
        key: key,
        metadata: response_metadata
      }.to_json

    rescue Aws::S3::EncryptionV2::Errors::EncryptionError => e
      S3ECLogger.log_error(e, { endpoint: '/put', error_category: 'EncryptionError' }, @request_id)
      ErrorHandlers.send_s3_encryption_client_error(self, e.message)
    rescue StandardError => e
      # Handle generic server errors (return as GenericServerError)
      S3ECLogger.log_error(e, { endpoint: '/put', error_category: 'generic_server' }, @request_id)
      status_code = e.respond_to?(:code) ? e.code : 500
      ErrorHandlers.send_generic_server_error(self, e.message, status_code)
    end
  end

  # GET /object/{bucket}/{key} - Get and decrypt object
  get '/object/:bucket/:key' do
    bucket = params[:bucket]
    key = params[:key]
    client_id = request.env['HTTP_CLIENTID']

    begin
      S3ECLogger.debug("GET_ENDPOINT [#{@request_id}]: Processing GET request for s3://#{bucket}/#{key}")

      # Validate client ID
      unless client_id
        S3ECLogger.log_validation_error('ClientID', 'missing', @request_id)
        ErrorHandlers.send_generic_server_error(self, "ClientID header is required", 400)
      end

      # Get client from cache
      client = @client_manager.get_client(client_id)
      unless client
        S3ECLogger.log_validation_error('ClientID', client_id, @request_id)
        ErrorHandlers.send_generic_server_error(self, "No client found for ClientID: #{client_id}", 404)
      end

      # Parse metadata from header
      metadata_header = request.env['HTTP_CONTENT_METADATA'] || ''
      encryption_context = MetadataUtils.string_to_map(metadata_header)
      S3ECLogger.log_metadata_processing('parse', metadata_header, encryption_context)

      # Prepare S3 get_object parameters
      get_params = {
        bucket: bucket,
        key: key
      }

      # Add encryption context if present
      get_params[:kms_encryption_context] = encryption_context unless encryption_context.empty?

      # Log S3 operation
      S3ECLogger.log_s3_operation('get', bucket, key, encryption_context, "ClientID: #{client_id}")

      # Make the get_object request
      response = client.get_object(get_params)

      # Extract body and metadata
      body = response.body.read
      metadata = response.metadata || {}

      S3ECLogger.info("GET_ENDPOINT [#{@request_id}]: Successfully got object s3://#{bucket}/#{key}, BodySize: #{body.length}")

      # Set Content-Metadata header in response
      metadata_str = MetadataUtils.map_to_string(metadata)
      S3ECLogger.log_metadata_processing('response', metadata, metadata_str)

      headers['Content-Metadata'] = metadata_str unless metadata_str.empty?

      # Return the body as response
      content_type 'application/octet-stream'
      body

    rescue Aws::S3::EncryptionV2::Errors::DecryptionError => e
      S3ECLogger.log_error(e, { endpoint: '/get', error_category: 'DecryptionError' }, @request_id)
      ErrorHandlers.send_s3_encryption_client_error(self, e.message)
    rescue StandardError => e
      # Handle generic server errors (return as GenericServerError)
      S3ECLogger.log_error(e, { endpoint: '/get', error_category: 'generic_server' }, @request_id)
      status_code = e.respond_to?(:code) ? e.code : 500
      ErrorHandlers.send_generic_server_error(self, e.message, status_code)
    end
  end

  # Global error handler
  error do
    error = env['sinatra.error']
    context = {
      endpoint: request.path_info,
      method: request.request_method,
      params: params,
      error_type: 'global_error_handler'
    }

    S3ECLogger.log_error(error, context, @request_id)
    ErrorHandlers.send_generic_server_error(self, "Internal server error: #{error.message}")
  end

  # Start server when run directly
  if __FILE__ == $0
    S3ECLogger.info("S3EC_SERVER: Starting Ruby server on port #{settings.port}...")
    run!
  end
end
