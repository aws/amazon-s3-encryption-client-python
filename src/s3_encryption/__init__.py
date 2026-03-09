# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Top-level S3 Encryption Client v3 for Python package."""

import io
import threading

from attrs import define, field
from botocore.response import StreamingBody

from .exceptions import S3EncryptionClientError
from .instruction_file import parse_instruction_file
from .materials.crypto_materials_manager import (
    AbstractCryptoMaterialsManager,
    DefaultCryptoMaterialsManager,
)
from .materials.keyring import AbstractKeyring
from .pipelines import GetEncryptedObjectPipeline, PutEncryptedObjectPipeline

S3_METADATA_PREFIX = "x-amz-meta-"


@define
class S3EncryptionClientConfig:
    """Configuration object for the S3 Encryption Client."""

    keyring: AbstractKeyring
    cmm: AbstractCryptoMaterialsManager = field()
    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=implementation
    ##% The S3EC SHOULD support providing a custom Instruction File suffix
    ##% on GetObject requests, regardless of whether or not re-encryption is supported.

    ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
    ##= type=implementation
    ##% The default Instruction File behavior uses the same S3 object key
    ##% as its associated object suffixed with ".instruction".
    instruction_file_suffix: str = field(default=".instruction")

    ##= specification/s3-encryption/client.md#enable-delayed-authentication
    ##= type=implementation
    ##% The S3EC MUST support the option to enable or disable Delayed Authentication mode.

    ##= specification/s3-encryption/client.md#enable-delayed-authentication
    ##= type=implication
    ##% Delayed Authentication mode MUST be set to false by default.
    enable_delayed_authentication: bool = field(default=False)

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
        self._context = threading.local()

    def on_put_object_before_call(self, params, **kwargs):
        """Event handler for before-call.s3.PutObject.

        This handler encrypts the body after serialization but before the request is sent.

        Args:
            params: Dictionary of parameters for the PutObject call (after serialization)
            **kwargs: Additional event arguments
        """
        if getattr(self._context, "instruction_file_mode", False):
            raise S3EncryptionClientError(
                "Instruction file mode is exclusively for reading instruction files "
                "and not supported in put_object!"
            )
        # At this point, boto3 has already serialized the Body
        # Extract the serialized body from the request
        body = params.get("body")
        if body is None:
            body_bytes = b""
        elif isinstance(body, bytes):
            body_bytes = body
        elif hasattr(body, "read"):
            # It's a file-like object (BytesIO, etc.)
            # TODO(streaming): Add support for streaming encryption without reading entire body
            # into memory
            body_bytes = body.read()
        else:
            # Unexpected body type - should not happen as boto3 validates before this point
            raise S3EncryptionClientError("Unexpected type of body parameter!")

        encryption_context = getattr(self._context, "encryption_context", None)

        pipeline = PutEncryptedObjectPipeline(self.config.cmm)
        encrypted_data, encryption_metadata = pipeline.encrypt(
            body_bytes, encryption_context=encryption_context
        )

        params["body"] = encrypted_data

        headers = params.get("headers", {})

        # Add encryption metadata to headers
        if encryption_metadata:
            for key, value in encryption_metadata.items():
                # Add as S3 metadata headers
                header_key = f"{S3_METADATA_PREFIX}{key}"
                headers[header_key] = value

        params["headers"] = headers

    def on_get_object_after_call(self, parsed, **kwargs):
        """Event handler for after-call.s3.GetObject.

        This handler decrypts the body after the response is received from S3.

        Args:
            parsed: Dictionary containing the parsed response
            **kwargs: Additional event arguments (includes 'params' with request parameters)
        """
        # Check if plaintext mode is enabled via thread-local flag
        if getattr(self._context, "instruction_file_mode", False):
            self.process_instruction_file(parsed)
            return

        # Get encryption context from thread-local storage (set by get_object wrapper)
        encryption_context = getattr(self._context, "encryption_context", None)

        # The parsed response already has the Body as a StreamingBody
        # We need to read it, decrypt it, and replace it

        # Create a response dict that matches what the pipeline expects
        response = {
            "Body": parsed.get("Body"),
            "Metadata": parsed.get("Metadata", {}),
        }

        # Create a pipeline and decrypt the data
        pipeline = GetEncryptedObjectPipeline(
            self.config.cmm,
            s3_client=getattr(self._context, "s3_client", None),
        )
        decrypted_data = pipeline.decrypt(
            response,
            encryption_context,
            bucket=getattr(self._context, "bucket", None),
            key=getattr(self._context, "key", None),
            instruction_suffix=self.config.instruction_file_suffix,
            enable_delayed_authentication=self.config.enable_delayed_authentication,
        )

        # Replace body with decrypting stream
        parsed["Body"] = decrypted_data

    def process_instruction_file(self, parsed):
        """Process instruction file in plaintext mode.

        Validates the instruction file marker, parses the JSON body,
        and updates the response metadata with parsed content.

        Args:
            parsed: Dictionary containing the parsed response
        """
        instruction_key = getattr(self._context, "key", None)

        # In plaintext mode, parse instruction file and append to metadata
        existing_metadata = parsed.get("Metadata", {})
        instruction_data = parsed.get("Body").read()
        instruction_metadata = parse_instruction_file(instruction_data, instruction_key)

        # Append parsed instruction file content to existing metadata
        existing_metadata.update(instruction_metadata)
        parsed["Metadata"] = existing_metadata

        # Clear the body since instruction files shouldn't return body content
        stream = io.BytesIO(b"")
        streaming_body = StreamingBody(stream, 0)
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

        # Expose plugin context on wrapped client for instruction file fetching
        self.wrapped_s3_client._s3ec_plugin_context = self._plugin._context

        # Register event handlers using boto3's event system
        event_system = self.wrapped_s3_client.meta.events
        event_system.register("before-call.s3.PutObject", self._plugin.on_put_object_before_call)
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
            S3EncryptionClientError: Any problem with encryption, including if the Body parameter
            has an invalid type.
        """
        # Extract EncryptionContext if provided (not a standard S3 parameter)
        encryption_context = kwargs.pop("EncryptionContext", None)

        # Store encryption context in thread-local storage for the event handler
        self._plugin._context.encryption_context = encryption_context

        try:
            return self.wrapped_s3_client.put_object(**kwargs)
        except S3EncryptionClientError:
            # Re-raise our own exceptions without wrapping
            raise
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to encrypt object: {str(e)}") from e
        finally:
            # Clean up thread-local storage
            if hasattr(self._plugin._context, "encryption_context"):
                delattr(self._plugin._context, "encryption_context")

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

        Raises:
            S3EncryptionClientError: If decryption fails or the object is not properly encrypted.
        """
        # Extract EncryptionContext if provided (not a standard S3 parameter)
        encryption_context = kwargs.pop("EncryptionContext", None)

        # Store encryption context in thread-local storage for the event handler
        self._plugin._context.encryption_context = encryption_context
        # Store wrapped client in thread-local storage for
        # the event handler to fetch instruction files
        self._plugin._context.s3_client = self.wrapped_s3_client
        self._plugin._context.bucket = kwargs.get("Bucket")
        self._plugin._context.key = kwargs.get("Key")

        try:
            return self.wrapped_s3_client.get_object(**kwargs)
        except S3EncryptionClientError:
            # Re-raise our own exceptions without wrapping
            raise
        except Exception as e:
            # Wrap any unexpected errors during decryption
            raise S3EncryptionClientError(f"Failed to decrypt object: {str(e)}") from e
        finally:
            # Clean up thread-local storage;
            # do not clean up the client as it is not thread local only
            attrs = ["encryption_context", "Bucket", "Key"]
            for attr in attrs:
                if hasattr(self._plugin._context, attr):
                    delattr(self._plugin._context, attr)
