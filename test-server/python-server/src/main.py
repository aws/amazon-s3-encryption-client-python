"""
Main entry point for the Python server.
"""
from fastapi import FastAPI, Request, HTTPException, Response, status
from fastapi.responses import JSONResponse
from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.kms_keyring import KmsKeyring
import boto3
import uvicorn
import json
import uuid

app = FastAPI(title="Python Server")

# Dictionary to store clients with their UUIDs as keys
client_cache = {}

# Java gets a list, but since there's no Smithy Python Server, 
# this is just a string.
def metadata_string_to_map(md_string):
    md = {}
    if md_string == '':
        return md
    md_list = md_string.split(",")
    for entry in md_list:
        # Split on "]:[" to separate key and value
        parts = entry.split("]:[")
        if len(parts) == 2:
            # Remove remaining brackets from start and end
            key = parts[0][1:]  # Remove first character
            value = parts[1][:-1]  # Remove last character
            md[key] = value
        else:
            raise ValueError(f"Malformed metadata list entry: {entry}")
    return md


def create_generic_server_error(message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
    """
    Create a response that matches the GenericServerError type from the Smithy model.
    Used for internal server errors.
    """
    return JSONResponse(
        status_code=status_code,
        content={
            "__type": "software.amazon.encryption.s3#GenericServerError",
            "message": message
        }
    )

def create_s3_encryption_client_error(message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
    """
    Create a response that matches the S3EncryptionClientError type from the Smithy model.
    Used for errors thrown by the S3 Encryption Client.
    """
    return JSONResponse(
        status_code=status_code,
        content={
            "__type": "software.amazon.encryption.s3#S3EncryptionClientError",
            "message": message
        }
    )

@app.put("/object/{bucket}/{key}")
async def put_object(bucket: str, key: str, request: Request):
    """
    Handle PUT requests to /object/{bucket}/{key} by using the S3EncryptionClient
    to make a PutObject request to S3.
    """
    client_id = request.headers.get("ClientID")
    body = await request.body()
    print(f"PUT object request - Bucket: {bucket}, Key: {key}")
    print(f"ClientID from header: {client_id}")
    
    if not client_id:
        return create_generic_server_error("ClientID header is required", status.HTTP_400_BAD_REQUEST)
    
    # Get the S3EncryptionClient from the client_cache
    client = client_cache.get(client_id)
    if not client:
        return create_generic_server_error(f"No client found for ClientID: {client_id}", status.HTTP_404_NOT_FOUND)
    
    try:
        metadata = request.headers.get("Content-Metadata", '')
        enc_ctx = metadata_string_to_map(metadata)
        
        # Make the PutObject request
        response = client.put_object(
            **{
                "Bucket": bucket,
                "Key": key,
                "Body": body,
                "EncryptionContext": enc_ctx
            }
        )
        
        print(f"PutObject response: {response}")
        
        # Return the appropriate response
        return {
            "bucket": bucket,
            "key": key,
            "metadata": metadata if isinstance(metadata, list) else []
        }
    except Exception as e:
        print(f"Error making PutObject request: {e}")
        return create_s3_encryption_client_error(f"Failed to put object: {str(e)}")

@app.get("/object/{bucket}/{key}")
async def get_object(bucket: str, key: str, request: Request):
    """
    Handle GET requests to /object/{bucket}/{key} by using the S3EncryptionClient
    to make a GetObject request to S3.
    """
    client_id = request.headers.get("ClientID")
    print(f"GET object request - Bucket: {bucket}, Key: {key}")
    print(f"ClientID from header: {client_id}")
    
    if not client_id:
        return create_generic_server_error("ClientID header is required", status.HTTP_400_BAD_REQUEST)
    
    # Get the S3EncryptionClient from the client_cache
    client = client_cache.get(client_id)
    if not client:
        return create_generic_server_error(f"No client found for ClientID: {client_id}", status.HTTP_404_NOT_FOUND)

    metadata = request.headers.get("Content-Metadata", '')
    enc_ctx = metadata_string_to_map(metadata)
    
    try:
        # Use the client to make a GetObject request to S3
        print("making Get for " + key)
        response = client.get_object(
            **{
                "Bucket": bucket,
                "Key": key,
                "EncryptionContext": enc_ctx
            }
        )
        
        print(f"GetObject response: {response}")
        
        # Extract the body and metadata from the response
        body = response.get('Body').read() if response.get('Body') else b''
        # print(f"body:" + body)
        metadata = response.get('Metadata', [])
        print(f"md: {metadata}")
        
        # Convert metadata dictionary to a list of key-value pairs if it's a dict
        if isinstance(metadata, dict):
            metadata_list = [f"{key}={value}" for key, value in metadata.items()]
        else:
            metadata_list = metadata if isinstance(metadata, list) else []
        
        # Set the Content-Metadata header in the response
        # Convert metadata_list to a comma-separated string
        metadata_str = ",".join(metadata_list) if metadata_list else ""
        headers = {"Content-Metadata": metadata_str}
        print(f"headers: {headers}")
        
        # Return the body as the response payload
        return Response(
            content=body,
            headers=headers
        )
    except S3EncryptionClientError as ex:
        print(f"Modeled Error making GetObject request: {ex}")
        return create_s3_encryption_client_error(str(ex))
    except Exception as e:
        print(f"Generic Error making GetObject request: {e}")
        return create_generic_server_error(e)

@app.post("/client")
async def client_endpoint(request: Request):
    """
    Handle POST requests to /client by creating an S3EncryptionClient.
    """
    body = await request.body()
    print(f"Received client request with body: {body}")
    
    # Parse the bytes object as JSON
    try:
        # Decode bytes to string and parse as JSON
        parsed_data = json.loads(body.decode('utf-8'))
        print(f"Parsed JSON data: {parsed_data}")
        
        # Extract config from the parsed data
        config_data = parsed_data.get("config", {})
        # Extract key material if provided
        key_material = config_data.get("keyMaterial", {})
        if key_material:
            # Note: This is a placeholder. The actual implementation would depend on how
            # the S3EncryptionClient handles key material
            print(f"Key material provided: {key_material}")
        
        enable_legacy_wrapping_algorithms = config_data.get("enableLegacyWrappingAlgorithms", False)
        
        # TODO pull region from ARN
        kms_client = boto3.client("kms", region_name="us-west-2")
        kms_key_id = key_material['kmsKeyId']
        keyring = KmsKeyring(kms_client, kms_key_id=kms_key_id, enable_legacy_wrapping_algorithms=enable_legacy_wrapping_algorithms)
        wrapped_client = boto3.client("s3")
        client_config = S3EncryptionClientConfig(keyring)
        # Create S3EncryptionClientConfig
        # client_config = S3EncryptionClientConfig(
            # enable_legacy_unauthenticated_modes=config_data.get("enableLegacyUnauthenticatedModes", False),
            # enable_delayed_authentication_mode=config_data.get("enableDelayedAuthenticationMode", False),
            # enable_legacy_wrapping_algorithms=config_data.get("enableLegacyWrappingAlgorithms", False),
            # buffer_size=config_data.get("setBufferSize", 0)
        # )
        
        # Create S3EncryptionClient
        client = S3EncryptionClient(wrapped_client, client_config)
        print(f"Created S3EncryptionClient: {client}")
        
        # Generate a client ID using UUID
        client_id = str(uuid.uuid4())
        
        # Add the client to the client_cache dictionary
        client_cache[client_id] = client
        print(f"Added client to cache with ID: {client_id}")
        
        return {"clientId": client_id}
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return create_generic_server_error("Invalid JSON in request body", status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        print(f"Error creating S3EncryptionClient: {e}")
        return create_s3_encryption_client_error(f"Failed to create client: {str(e)}")

def main():
    """
    Main function to start the server.
    """
    uvicorn.run(app, host="localhost", port=8081)

if __name__ == "__main__":
    main()
