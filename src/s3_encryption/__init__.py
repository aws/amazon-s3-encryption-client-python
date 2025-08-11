# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import io

from attrs import define, field
from botocore.response import StreamingBody

from .materials.crypto_materials_manager import (
    AbstractCryptoMaterialsManager,
    DefaultCryptoMaterialsManager,
)
from .materials.keyring import AbstractKeyring
from .metadata import ObjectMetadata
from .pipelines import GetEncryptedObjectPipeline, PutEncryptedObjectPipeline


@define
class S3EncryptionClientConfig:
    """Configuration object for the S3 Encryption Client"""

    keyring: AbstractKeyring
    cmm: AbstractCryptoMaterialsManager = field()

    @cmm.default
    def _default_cmm_for_keyring(self):
        return DefaultCryptoMaterialsManager(self.keyring)


@define
class S3EncryptionClient:
    wrapped_s3_client = field()
    config: S3EncryptionClientConfig = field()

    # TODO: rename Data-> Body to match boto
    def put_object(self, Bucket, Key, Data, EncryptionContext=None, **kwargs):
        # Create a pipeline for this operation
        pipeline = PutEncryptedObjectPipeline(self.config.cmm)

        # Encrypt the data using the pipeline
        data_bytes = Data
        # We probably just shouldn't support strings, use utf8 for now
        # TODO: look deeper into this, what does normal boto3 do?
        if type(Data) == str:
            data_bytes = Data.encode("utf-8")
        encrypted_data, encryption_metadata = pipeline.encrypt(
            data_bytes, encryption_context=EncryptionContext
        )

        # Add encryption metadata to the request parameters
        params = {"Bucket": Bucket, "Key": Key, "Body": encrypted_data, **kwargs}

        # Add encryption metadata to the parameters
        if encryption_metadata:
            # Merge any existing metadata with our encryption metadata
            metadata = params.get("Metadata", {})
            metadata.update(encryption_metadata)
            params["Metadata"] = metadata

        return self.wrapped_s3_client.put_object(**params)

    def get_object(self, EncryptionContext=None, **kwargs):
        # try just straight kwargs
        params = {**kwargs}

        # Get the encrypted object from S3
        response = self.wrapped_s3_client.get_object(**params)

        # Create a pipeline for this operation
        pipeline = GetEncryptedObjectPipeline(self.config.cmm)

        # Decrypt the data using the pipeline
        decrypted_data = pipeline.decrypt(
            response, EncryptionContext
        )  # encrypted_data, encryption_metadata)

        # Create a new streaming body with the decrypted data
        stream = io.BytesIO(decrypted_data)
        streaming_body = StreamingBody(stream, len(decrypted_data))

        # Update the response with the decrypted data
        response["Body"] = streaming_body

        return response
