# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Top-level S3 Encryption Client v3 for Python package."""

import io

from attrs import define, field
from botocore.exceptions import ParamValidationError
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


class S3EncryptionClientPlugin:
    """Plugin that adds encryption/decryption capabilities to a boto3 S3 client.

    This plugin uses boto3's event system to intercept put_object and get_object
    calls to provide transparent encryption and decryption of S3 objects.
    """

    def __init__(self, config: S3EncryptionClientConfig):
        """Initialize the plugin with encryption configuration.

        Args:
            config: S3EncryptionClientConfig containing keyring and CMM
        """
        self.config = config

    def on_put_object_before_call(self, params, **kwargs):
        """Event handler for before-call.s3.PutObject.

        This handler encrypts the body after serialization but before the request is sent.

        Args:
            params: Dictionary of parameters for the PutObject call (after serialization)
            **kwargs: Additional event arguments
        """
        # At this point, boto3 has already serialized the Body
        # Extract the serialized body from the request
        body = params.get("body")
        if body is None:
            body_bytes = b""
        elif isinstance(body, bytes):
            body_bytes = body
        elif hasattr(body, "read"):
            # It's a file-like object (BytesIO, etc.)
            # TODO: Stream Encryption
            body_bytes = body.read()
        else:
            body_bytes = b""

        # Extract encryption context from headers if present
        headers = params.get("headers", {})
        encryption_context = None

        # Check if EncryptionContext was passed (it would be in a custom header)
        # For now, we'll handle it through metadata

        # Get metadata from headers
        metadata = {}
        for key, value in headers.items():
            if key.lower().startswith("x-amz-meta-"):
                # Extract the metadata key (remove x-amz-meta- prefix)
                meta_key = key[11:]  # len("x-amz-meta-") = 11
                metadata[meta_key] = value

        # Create a pipeline and encrypt the data
        pipeline = PutEncryptedObjectPipeline(self.config.cmm)
        encrypted_data, encryption_metadata = pipeline.encrypt(
            body_bytes, encryption_context=encryption_context
        )

        # Update the body with encrypted data
        params["body"] = encrypted_data

        # Add encryption metadata to headers
        if encryption_metadata:
            for key, value in encryption_metadata.items():
                # Add as S3 metadata headers
                header_key = f"x-amz-meta-{key}"
                headers[header_key] = value

    def on_get_object_after_call(self, parsed, **kwargs):
        """Event handler for after-call.s3.GetObject.

        This handler decrypts the body after the response is received from S3.

        Args:
            parsed: Dictionary containing the parsed response
            **kwargs: Additional event arguments (includes 'params' with request parameters)
        """
        # Extract encryption context from original request params if available
        request_params = kwargs.get("params", {})
        encryption_context = request_params.pop("EncryptionContext", None)

        # The parsed response already has the Body as a StreamingBody
        # We need to read it, decrypt it, and replace it

        # Create a response dict that matches what the pipeline expects
        response = {
            "Body": parsed.get("Body"),
            "Metadata": parsed.get("Metadata", {}),
        }

        # Create a pipeline and decrypt the data
        pipeline = GetEncryptedObjectPipeline(self.config.cmm)
        decrypted_data = pipeline.decrypt(response, encryption_context)

        # Replace body with decrypted data
        stream = io.BytesIO(decrypted_data)
        streaming_body = StreamingBody(stream, len(decrypted_data))
        parsed["Body"] = streaming_body


@define
class S3EncryptionClient:
    """Client for encrypting and decrypting S3 objects.

    This client wraps a boto3 S3 client and provides encryption and decryption
    capabilities for S3 objects using the configured keyring and crypto materials manager.

    The encryption/decryption is implemented using boto3's event system, registering
    handlers for before-call and after-call events.
    """

    wrapped_s3_client = field()
    config: S3EncryptionClientConfig = field()
    _plugin: S3EncryptionClientPlugin = field(init=False)

    def __attrs_post_init__(self):
        """Install the encryption plugin on the wrapped client using boto3 events."""
        # Create the plugin
        object.__setattr__(self, "_plugin", S3EncryptionClientPlugin(self.config))

        # Register event handlers using boto3's event system
        event_system = self.wrapped_s3_client.meta.events

        # Register before-call handler for PutObject to encrypt data
        # This happens after serialization, so Body is already bytes
        event_system.register("before-call.s3.PutObject", self._plugin.on_put_object_before_call)

        # Register after-call handler for GetObject to decrypt data
        event_system.register("after-call.s3.GetObject", self._plugin.on_get_object_after_call)

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

        Raises:
            S3EncryptionClientError: If the Body parameter has an invalid type.
        """
        try:
            return self.wrapped_s3_client.put_object(**kwargs)
        except ParamValidationError as e:
            # Wrap boto3's ParamValidationError with our custom error
            raise S3EncryptionClientError(
                f"Body parameter of type {type(kwargs.get('Body'))} is not an acceptable type! "
                f"Use bytes or a file-like object."
            ) from e

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
        return self.wrapped_s3_client.get_object(**kwargs)
