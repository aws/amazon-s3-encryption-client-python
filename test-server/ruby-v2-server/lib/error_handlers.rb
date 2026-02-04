# Error handling utilities to match Smithy error types
require 'json'

class ErrorHandlers
  # Create a response that matches the GenericServerError type from the Smithy model
  # Used for internal server errors
  def self.create_generic_server_error(message, status_code = 500)
    {
      status: status_code,
      headers: { 'Content-Type' => 'application/json' },
      body: {
        '__type' => 'software.amazon.encryption.s3#GenericServerError',
        'message' => message
      }.to_json
    }
  end

  # Create a response that matches the S3EncryptionClientError type from the Smithy model
  # Used for errors thrown by the S3 Encryption Client
  def self.create_s3_encryption_client_error(message, status_code = 500)
    {
      status: status_code,
      headers: { 'Content-Type' => 'application/json' },
      body: {
        '__type' => 'software.amazon.encryption.s3#S3EncryptionClientError',
        'message' => message
      }.to_json
    }
  end

  # Helper method to send error response in Sinatra
  def self.send_generic_server_error(app, message, status_code = 500)
    error_response = create_generic_server_error(message, status_code)
    app.halt error_response[:status], error_response[:headers], error_response[:body]
  end

  # Helper method to send S3EC error response in Sinatra
  def self.send_s3_encryption_client_error(app, message, status_code = 500)
    error_response = create_s3_encryption_client_error(message, status_code)
    app.halt error_response[:status], error_response[:headers], error_response[:body]
  end
end
