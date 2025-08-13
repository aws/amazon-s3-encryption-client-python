# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Top-level S3 Encryption Client v3 for Python package."""
import io

from attrs import define, field
from botocore import serialize
from botocore.response import StreamingBody

from .exceptions import S3EncryptionClientError
from .materials.crypto_materials_manager import (
    AbstractCryptoMaterialsManager,
    DefaultCryptoMaterialsManager,
)
from .materials.keyring import AbstractKeyring
from .pipelines import GetEncryptedObjectPipeline, PutEncryptedObjectPipeline

DEFAULT_ENCODING = "utf-8"


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

    def __attrs_post_init__(self):
        """Validate serialization encoding after initialization.

        Ensures boto3 serializers are using the expected default encoding.
        """
        # Sanity check that boto3 serialization are ONLY using the default encoding (utf-8)
        # This should always be the case, but changes in encoding would break the assumption that
        # the decrypted plaintext adheres to the non-utf8 encoding scheme. So we avoid that.
        for sz_name, sz in serialize.SERIALIZERS.items():
            if sz.DEFAULT_ENCODING != DEFAULT_ENCODING:
                raise S3EncryptionClientError(
                    f"All Serializers MUST only support utf-8 encoding, but {sz_name} is using "
                    f"{sz.DEFAULT_ENCODING}!"
                )

    def put_object(self, **kwargs):
        """Encrypt and upload an object to S3.

        This method encrypts the provided object body before uploading it to S3.
        It handles the encryption process using the configured crypto materials manager.

        Args:
            **kwargs: Arguments to pass to the S3 client's put_object method.
                      Must include Bucket and Key parameters.
                      Body parameter is optional; if not provided, an empty object is uploaded.
                      May include EncryptionContext for additional authenticated data.

        Returns:
            The response from the S3 client's put_object method.
        """
        # Extract required parameters from kwargs
        bucket = kwargs.pop("Bucket")
        key = kwargs.pop("Key")
        body = kwargs.pop("Body", b"")  # Default to empty bytes when Body is not provided
        encryption_context = kwargs.pop("EncryptionContext", None)

        # Create a pipeline for this operation
        pipeline = PutEncryptedObjectPipeline(self.config.cmm)

        # The documentation for boto3 asks for bytes or a file-like object,
        # but in reality, it is possible to pass strings.
        # Strings will be encoded using DEFAULT_ENCODING,
        # which MUST match the default encoding defined int the Serializer class in botocore.
        if isinstance(body, str):
            data_bytes = body.encode(DEFAULT_ENCODING)
        elif isinstance(body, bytes):
            data_bytes = body
        elif isinstance(body, io.IOBase):
            # TODO: Streaming support
            raise S3EncryptionClientError(
                f"Body parameter of type {type(body)} is not an acceptable type! "
                f"Streaming operations are not yet supported."
            )
        else:
            raise S3EncryptionClientError(
                f"Body parameter of type {type(body)} is not an acceptable type! "
                f"Use bytes or a file-like object."
            )

        # Now encrypt the bytes/file-like IOBase object
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
