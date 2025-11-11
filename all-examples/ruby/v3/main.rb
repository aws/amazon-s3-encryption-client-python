#!/usr/bin/env ruby

require 'aws-sdk-s3'
require 'aws-sdk-kms'
require 'json'

# See: https://github.com/ruby/openssl/issues/949
Aws.use_bundled_cert!

def main
  # Check command line arguments
  if ARGV.length != 4
    puts "Usage: #{$0} <bucket-name> <object-key> <kms-key-id> <region>"
    puts "Example: #{$0} avp-21638 s3ec-ruby-v3 arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2"
    exit 1
  end

  bucket_name = ARGV[0]
  object_key = ARGV[1]
  kms_key_id = ARGV[2]
  region = ARGV[3]

  puts "=== S3 Encryption Client v3 Example (Ruby) ==="
  puts "Bucket: #{bucket_name}"
  puts "Object Key: #{object_key}"
  puts "KMS Key ID: #{kms_key_id}"
  puts "Region: #{region}"
  puts

  begin
    # Test data for encryption
    test_data = "Hello, World! This is a test message for S3 encryption client v3 in Ruby."
    puts "Original data: #{test_data}"
    puts "Data length: #{test_data.length} bytes"
    puts

    puts "--- Initialize S3 Encryption Client v3 ---"
    
    # Create regular S3 client
    s3_client = Aws::S3::Client.new(region: region)
    
    # Create KMS client
    kms_client = Aws::KMS::Client.new(region: region)
    
    # Create S3 Encryption Client v3
    encryption_client = Aws::S3::EncryptionV3::Client.new(
      client: s3_client,
      kms_key_id: kms_key_id,
      kms_client: kms_client,
      key_wrap_schema: :kms_context
    )
    
    puts "Successfully initialized S3 Encryption Client v3"
    puts "--- Encrypt and Upload Object to S3 ---"
    
    # Add encryption context
    encryption_context = {
      'purpose' => 'example',
      'version' => 'v3',
      'language' => 'ruby'
    }
    
    # Upload encrypted object using S3 Encryption Client
    put_response = encryption_client.put_object({
      bucket: bucket_name,
      key: object_key,
      body: test_data,
      kms_encryption_context: encryption_context
    })
    
    puts "Successfully uploaded encrypted object to S3!"
    puts "   Bucket: #{bucket_name}"
    puts "   Key: #{object_key}"
    puts "   Encryption Context: #{encryption_context}"
    puts

    puts "--- Download and Decrypt Object from S3 ---"
    
    # Download and decrypt object using S3 Encryption Client
    get_response = encryption_client.get_object({
      bucket: bucket_name,
      key: object_key,
      kms_encryption_context: encryption_context
    })
    
    # Read the decrypted data
    decrypted_data = get_response.body.read
    
    puts "Successfully downloaded and decrypted object from S3!"
    puts "   Object size: #{decrypted_data.length} bytes"
    puts "   Decrypted data: #{decrypted_data}"
    puts

    puts "--- Verify Roundtrip Success ---"
    
    # Verify the roundtrip was successful
    if decrypted_data == test_data
      puts "SUCCESS: Roundtrip encryption/decryption completed successfully!"
      puts "   Original data matches decrypted data"
      puts "   Data integrity verified"
    else
      puts "ERROR: Roundtrip failed - data mismatch"
      puts "   Original: #{test_data}"
      puts "   Decrypted: #{decrypted_data}"
      exit 1
    end

    # Optionally Delete the Object
    #puts "--- Cleanup ---"
    # Clean up the test object using regular S3 client
    # s3_client.delete_object({
    #   bucket: bucket_name,
    #   key: object_key
    # })
    # puts "Test object deleted from S3"
    
    puts
    puts "=== Example completed successfully! ==="

  rescue Aws::S3::Errors::NoSuchBucket => e
    puts "Error: S3 bucket '#{bucket_name}' does not exist or is not accessible"
    puts "   #{e.message}"
    exit 1
  rescue Aws::KMS::Errors::NotFoundException => e
    puts "Error: KMS key '#{kms_key_id}' not found or not accessible"
    puts "   #{e.message}"
    exit 1
  rescue Aws::S3::EncryptionV3::Errors::EncryptionError => e
    puts "S3 Encryption Error: #{e.message}"
    exit 1
  rescue Aws::S3::EncryptionV3::Errors::DecryptionError => e
    puts "S3 Decryption Error: #{e.message}"
    exit 1
  rescue Aws::Errors::ServiceError => e
    puts "AWS Service Error: #{e.message}"
    puts "   Error Code: #{e.code}" if e.respond_to?(:code)
    exit 1
  rescue StandardError => e
    puts "Unexpected error: #{e.message}"
    puts e.backtrace.first(5)
    exit 1
  end
end

# Run the main function if this script is executed directly
if __FILE__ == $0
  main
end
