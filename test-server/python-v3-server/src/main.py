"""
Main entry point for the Python server.
"""

from fastapi import FastAPI, Request, HTTPException, Response, status
from fastapi.responses import JSONResponse
from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.kms_keyring import KmsKeyring
from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy
import boto3
import uvicorn
import json
import logging
import uuid

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("python-v3-server")

app = FastAPI(title="Python Server")

# Dictionary to store clients with their UUIDs as keys
client_cache = {}


# Java gets a list, but since there's no Smithy Python Server,
# this is just a string.
def metadata_string_to_map(md_string):
    md = {}
    if md_string == "":
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


def create_generic_server_error(
    message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
):
    """
    Create a response that matches the GenericServerError type from the Smithy model.
    Used for internal server errors.
    """
    return JSONResponse(
        status_code=status_code,
        content={"__type": "software.amazon.encryption.s3#GenericServerError", "message": message},
    )


def create_s3_encryption_client_error(
    message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
):
    """
    Create a response that matches the S3EncryptionClientError type from the Smithy model.
    Used for errors thrown by the S3 Encryption Client.
    """
    return JSONResponse(
        status_code=status_code,
        content={
            "__type": "software.amazon.encryption.s3#S3EncryptionClientError",
            "message": message,
        },
    )


# Maps from Smithy model enum strings to Python AlgorithmSuite/CommitmentPolicy enums
_ALGORITHM_SUITE_MAP = {
    "ALG_AES_256_GCM_IV12_TAG16_NO_KDF": AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
    "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY": AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
}

_COMMITMENT_POLICY_MAP = {
    "FORBID_ENCRYPT_ALLOW_DECRYPT": CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
    "REQUIRE_ENCRYPT_ALLOW_DECRYPT": CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
    "REQUIRE_ENCRYPT_REQUIRE_DECRYPT": CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
}


@app.put("/object/{bucket}/{key}")
async def put_object(bucket: str, key: str, request: Request):
    """
    Handle PUT requests to /object/{bucket}/{key} by using the S3EncryptionClient
    to make a PutObject request to S3.
    """
    client_id = request.headers.get("ClientID")
    body = await request.body()

    if not client_id:
        return create_generic_server_error(
            "ClientID header is required", status.HTTP_400_BAD_REQUEST
        )

    # Get the S3EncryptionClient from the client_cache
    client = client_cache.get(client_id)
    if not client:
        return create_generic_server_error(
            f"No client found for ClientID: {client_id}", status.HTTP_404_NOT_FOUND
        )

    try:
        metadata = request.headers.get("Content-Metadata", "")
        enc_ctx = metadata_string_to_map(metadata)

        logger.info(
            "PUT /object/%s/%s — clientID=%s, raw Content-Metadata=%r, parsed enc_ctx=%s",
            bucket, key, client_id, metadata, enc_ctx,
        )

        # Make the PutObject request
        response = client.put_object(
            **{"Bucket": bucket, "Key": key, "Body": body, "EncryptionContext": enc_ctx}
        )

        # Return the appropriate response
        return {
            "bucket": bucket,
            "key": key,
            "metadata": metadata if isinstance(metadata, list) else [],
        }
    except Exception as e:
        return create_s3_encryption_client_error(f"Failed to put object: {str(e)}")


@app.get("/object/{bucket}/{key}")
async def get_object(bucket: str, key: str, request: Request):
    """
    Handle GET requests to /object/{bucket}/{key} by using the S3EncryptionClient
    to make a GetObject request to S3.
    """
    client_id = request.headers.get("ClientID")

    if not client_id:
        return create_generic_server_error(
            "ClientID header is required", status.HTTP_400_BAD_REQUEST
        )

    # Get the S3EncryptionClient from the client_cache
    client = client_cache.get(client_id)
    if not client:
        return create_generic_server_error(
            f"No client found for ClientID: {client_id}", status.HTTP_404_NOT_FOUND
        )

    metadata = request.headers.get("Content-Metadata", "")
    enc_ctx = metadata_string_to_map(metadata)

    logger.info(
        "GET /object/%s/%s — clientID=%s, raw Content-Metadata=%r, parsed enc_ctx=%s",
        bucket, key, client_id, metadata, enc_ctx,
    )

    try:
        # Use the client to make a GetObject request to S3
        response = client.get_object(**{"Bucket": bucket, "Key": key, "EncryptionContext": enc_ctx})

        # Extract the body and metadata from the response
        body = response.get("Body").read() if response.get("Body") else b""
        metadata = response.get("Metadata", [])

        logger.info(
            "GET /object/%s/%s — decryption succeeded, body length=%d",
            bucket, key, len(body),
        )

        # Convert metadata dictionary to a list of key-value pairs if it's a dict
        if isinstance(metadata, dict):
            metadata_list = [f"{key}={value}" for key, value in metadata.items()]
        else:
            metadata_list = metadata if isinstance(metadata, list) else []

        # Set the Content-Metadata header in the response
        # Convert metadata_list to a comma-separated string
        metadata_str = ",".join(metadata_list) if metadata_list else ""
        headers = {"Content-Metadata": metadata_str}

        # Return the body as the response payload
        return Response(content=body, headers=headers)
    except S3EncryptionClientError as ex:
        logger.info(
            "GET /object/%s/%s — S3EncryptionClientError: %s",
            bucket, key, ex,
        )
        return create_s3_encryption_client_error(str(ex))
    except Exception as e:
        logger.info(
            "GET /object/%s/%s — unexpected %s: %s",
            bucket, key, type(e).__name__, e,
        )
        return create_generic_server_error(str(e))


@app.post("/client")
async def client_endpoint(request: Request):
    """
    Handle POST requests to /client by creating an S3EncryptionClient.
    """
    body = await request.body()

    # Parse the bytes object as JSON
    try:
        # Decode bytes to string and parse as JSON
        parsed_data = json.loads(body.decode("utf-8"))

        # Extract config from the parsed data
        config_data = parsed_data.get("config", {})
        # Extract key material if provided
        key_material = config_data.get("keyMaterial", {})

        enable_legacy_wrapping_algorithms = config_data.get("enableLegacyWrappingAlgorithms", False)
        enable_legacy_unauthenticated_modes = config_data.get("enableLegacyUnauthenticatedModes", False)

        # TODO pull region from ARN
        kms_client = boto3.client("kms", region_name="us-west-2")
        kms_key_id = key_material["kmsKeyId"]
        keyring = KmsKeyring(
            kms_client,
            kms_key_id=kms_key_id,
            enable_legacy_wrapping_algorithms=enable_legacy_wrapping_algorithms,
        )
        wrapped_client = boto3.client("s3")

        # Build config kwargs, only including algorithm_suite and commitment_policy if provided
        config_kwargs = {
            "keyring": keyring,
            "enable_legacy_unauthenticated_modes": enable_legacy_unauthenticated_modes,
        }

        encryption_algorithm = config_data.get("encryptionAlgorithm")
        if encryption_algorithm is not None:
            if encryption_algorithm not in _ALGORITHM_SUITE_MAP:
                raise ValueError(f"Unknown encryption algorithm: {encryption_algorithm}")
            config_kwargs["encryption_algorithm"] = _ALGORITHM_SUITE_MAP[encryption_algorithm]

        commitment_policy = config_data.get("commitmentPolicy")
        if commitment_policy is not None:
            if commitment_policy not in _COMMITMENT_POLICY_MAP:
                raise ValueError(f"Unknown commitment policy: {commitment_policy}")
            config_kwargs["commitment_policy"] = _COMMITMENT_POLICY_MAP[commitment_policy]

        client_config = S3EncryptionClientConfig(**config_kwargs)

        # Create S3EncryptionClient
        client = S3EncryptionClient(wrapped_client, client_config)

        # Generate a client ID using UUID
        client_id = str(uuid.uuid4())

        # Add the client to the client_cache dictionary
        client_cache[client_id] = client

        return {"clientId": client_id}
    except json.JSONDecodeError as e:
        return create_generic_server_error(
            "Invalid JSON in request body", status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return create_s3_encryption_client_error(f"Failed to create client: {str(e)}")


def main():
    """
    Main function to start the server.
    """
    uvicorn.run(app, host="localhost", port=8081)


if __name__ == "__main__":
    main()
