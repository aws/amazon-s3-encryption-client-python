# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Top-level S3 Encryption Client v3 for Python package."""
import io

from attrs import define, field
from botocore.response import StreamingBody

from .materials.crypto_materials_manager import (
    AbstractCryptoMaterialsManager,
    DefaultCryptoMaterialsManager,
)
from .materials.keyring import AbstractKeyring
from .pipelines import GetEncryptedObjectPipeline, PutEncryptedObjectPipeline


@define
class S3EncryptionClientConfig:
    """Configuration object for the S3 Encryption Client."""

    keyring: AbstractKeyring
    cmm: AbstractCryptoMaterialsManager = field()

    @cmm.default
    def _default_cmm_for_keyring(self):
        return DefaultCryptoMaterialsManager(self.keyring)


@define
class S3EncryptionClient:
    """Client for encrypting and decrypting S3 objects.

    This client wraps a boto3 S3 client and provides encryption and decryption
    capabilities for S3 objects using the configured keyring and crypto materials manager.
    """

    wrapped_s3_client = field()
    config: S3EncryptionClientConfig = field()

    def put_object(self, **kwargs):
        """Encrypt and upload an object to S3.

        This method encrypts the provided object body before uploading it to S3.
        It handles the encryption process using the configured crypto materials manager.

        Args:
            **kwargs: Arguments to pass to the S3 client's put_object method.
                      Must include Bucket, Key, and Body parameters.
                      May include EncryptionContext for additional authenticated data.

        Returns:
            The response from the S3 client's put_object method.
        """
        # Extract required parameters from kwargs
        bucket = kwargs.pop("Bucket")
        key = kwargs.pop("Key")
        body = kwargs.pop("Body")
        encryption_context = kwargs.pop("EncryptionContext", None)

        # Create a pipeline for this operation
        pipeline = PutEncryptedObjectPipeline(self.config.cmm)

        # Encrypt the data using the pipeline
        data_bytes = body
        # We probably just shouldn't support strings, use utf8 for now
        # TODO: look deeper into this, what does normal boto3 do?
        if isinstance(body, str):
            data_bytes = body.encode("utf-8")
        encrypted_data, encryption_metadata = pipeline.encrypt(
            data_bytes, encryption_context=encryption_context
        )

        # Add encryption metadata to the request parameters
        params = {"Bucket": bucket, "Key": key, "Body": encrypted_data, **kwargs}

        # Add encryption metadata to the parameters
        if encryption_metadata:
            # Merge any existing metadata with our encryption metadata
            metadata = params.get("Metadata", {})
            metadata.update(encryption_metadata)
            params["Metadata"] = metadata

        return self.wrapped_s3_client.put_object(**params)

    def get_object(self, **kwargs):
        """Download and decrypt an object from S3.

        This method downloads an encrypted object from S3 and decrypts it
        using the configured crypto materials manager.

        Args:
            **kwargs: Arguments to pass to the S3 client's get_object method.
                      May include EncryptionContext if it was used during encryption.

        Returns:
            The response from the S3 client's get_object method with the Body
            replaced with a StreamingBody containing the decrypted data.
        """
        # Extract encryption context if provided
        encryption_context = kwargs.pop("EncryptionContext", None)

        # Create params for the S3 client
        params = {**kwargs}

        # Get the encrypted object from S3
        response = self.wrapped_s3_client.get_object(**params)

        # Create a pipeline for this operation
        pipeline = GetEncryptedObjectPipeline(self.config.cmm)

        # Decrypt the data using the pipeline
        decrypted_data = pipeline.decrypt(
            response, encryption_context
        )  # encrypted_data, encryption_metadata)

        # Create a new streaming body with the decrypted data
        stream = io.BytesIO(decrypted_data)
        streaming_body = StreamingBody(stream, len(decrypted_data))

        # Update the response with the decrypted data
        response["Body"] = streaming_body

        return response
