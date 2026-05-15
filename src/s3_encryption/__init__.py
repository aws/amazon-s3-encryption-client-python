# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Top-level S3 Encryption Client v4 for Python package."""

import io
import os
import threading

from attrs import define, field
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from ._utils import _USER_AGENT_SUFFIX, append_user_agent, safe_get_dict
from .exceptions import S3EncryptionClientError
from .instruction_file import parse_instruction_file
from .instruction_file_config import InstructionFileConfig
from .materials.crypto_materials_manager import (
    AbstractCryptoMaterialsManager,
    DefaultCryptoMaterialsManager,
)
from .materials.keyring import AbstractKeyring
from .materials.materials import AlgorithmSuite, CommitmentPolicy
from .pipelines import (
    GetEncryptedObjectPipeline,
    MultipartUploadPipeline,
    PutEncryptedObjectPipeline,
)

S3_METADATA_PREFIX = "x-amz-meta-"

# Default multipart threshold and chunk size (same as boto3 defaults)
_DEFAULT_MULTIPART_THRESHOLD = 8 * 1024 * 1024  # 8 MB
_DEFAULT_MULTIPART_CHUNKSIZE = 8 * 1024 * 1024  # 8 MB
_MIN_MULTIPART_PART_SIZE = 5 * 1024 * 1024  # 5 MB — S3 minimum for non-final parts

# Thread-local context attribute names
_CTX_ENCRYPTION_CONTEXT = "encryption_context"
_CTX_BUCKET = "bucket"
_CTX_KEY = "key"
_CTX_S3_CLIENT = "s3_client"
_CTX_INSTRUCTION_FILE_MODE = "instruction_file_mode"
_CTX_INSTRUCTION_FILE_SUFFIX = "instruction_file_suffix"

# Attributes to clean up after get_object completes
# (s3_client is intentionally excluded — it is not request-scoped)
_GET_OBJECT_CLEANUP_ATTRS = (
    _CTX_ENCRYPTION_CONTEXT,
    _CTX_BUCKET,
    _CTX_KEY,
    _CTX_INSTRUCTION_FILE_SUFFIX,
)


@define
class S3EncryptionClientConfig:
    """Configuration for the S3 Encryption Client.

    Attributes:
        keyring: Keyring used for encrypting/decrypting data keys.
        encryption_algorithm: Algorithm suite for encryption. Defaults to
            ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY (V3 key-committing).
        commitment_policy: Key commitment policy for encryption and decryption.
            Defaults to REQUIRE_ENCRYPT_REQUIRE_DECRYPT.
        enable_legacy_unauthenticated_modes: If True, allow decryption of objects
            encrypted with legacy CBC algorithm suites. Defaults to False.
        cmm: Crypto materials manager. Defaults to a DefaultCryptoMaterialsManager
            wrapping the provided keyring.
        enable_delayed_authentication: If True, release plaintext from streams
            before GCM tag verification. Defaults to False. Has no effect for
            CBC encrypted ciphertext, which is always streamed as there is no
            authentication tag.
        instruction_file_config: Configuration for instruction file behavior.
            Defaults to InstructionFileConfig() which enables instruction file
            reads on GetObject.

    Raises:
        S3EncryptionClientError: If the encryption algorithm is legacy, or if
            the algorithm suite is incompatible with the commitment policy.
    """

    keyring: AbstractKeyring
    encryption_algorithm: AlgorithmSuite = field(
        default=AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
    )
    commitment_policy: CommitmentPolicy = field(
        default=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    ##= specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
    ##% The S3EC MUST support the option to enable or disable legacy unauthenticated modes (content encryption algorithms).
    ##= specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
    ##% The option to enable legacy unauthenticated modes MUST be set to false by default.
    enable_legacy_unauthenticated_modes: bool = field(default=False)
    cmm: AbstractCryptoMaterialsManager = field()

    ##= specification/s3-encryption/client.md#enable-delayed-authentication
    ##= type=implementation
    ##% The S3EC MUST support the option to enable or disable Delayed Authentication mode.

    ##= specification/s3-encryption/client.md#enable-delayed-authentication
    ##= type=implication
    ##% Delayed Authentication mode MUST be set to false by default.
    enable_delayed_authentication: bool = field(default=False)

    instruction_file_config: InstructionFileConfig = field(factory=InstructionFileConfig)

    @cmm.default
    def _default_cmm_for_keyring(self):
        return DefaultCryptoMaterialsManager(self.keyring)

    ##= specification/s3-encryption/client.md#encryption-algorithm
    ##% The S3EC MUST validate that the configured encryption algorithm is not legacy.
    ##= specification/s3-encryption/client.md#encryption-algorithm
    ##% If the configured encryption algorithm is legacy, then the S3EC MUST throw an exception.
    ##= specification/s3-encryption/client.md#key-commitment
    ##% The S3EC MUST validate the configured Encryption Algorithm against the provided key commitment policy.
    ##= specification/s3-encryption/client.md#key-commitment
    ##% If the configured Encryption Algorithm is incompatible with the key commitment policy, then it MUST throw an exception.
    def __attrs_post_init__(self):
        """Validate algorithm suite and commitment policy configuration."""
        if self.encryption_algorithm.is_legacy:
            raise S3EncryptionClientError(
                f"Cannot configure S3 Encryption Client with legacy algorithm suite "
                f"{self.encryption_algorithm.name}. Legacy algorithm suites are only "
                f"supported for decryption (and enable_legacy_unauthenticated_modes is True)."
            )

        ##= specification/s3-encryption/key-commitment.md#commitment-policy
        ##% When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
        ##= specification/s3-encryption/key-commitment.md#commitment-policy
        ##% When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
        if (
            self.commitment_policy
            in (
                CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            )
            and not self.encryption_algorithm.supports_key_commitment
        ):
            raise S3EncryptionClientError(
                f"Commitment policy {self.commitment_policy.name} requires a key-committing "
                f"algorithm suite, but {self.encryption_algorithm.name} does not support key commitment."
            )

        ##= specification/s3-encryption/key-commitment.md#commitment-policy
        ##% When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
        if (
            self.commitment_policy == CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
            and self.encryption_algorithm.supports_key_commitment
        ):
            raise S3EncryptionClientError(
                f"Commitment policy {self.commitment_policy.name} forbids key-committing "
                f"algorithm suites, but {self.encryption_algorithm.name} supports key commitment."
            )


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
        if getattr(self._context, _CTX_INSTRUCTION_FILE_MODE, False):
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

        encryption_context = getattr(self._context, _CTX_ENCRYPTION_CONTEXT, None)

        pipeline = PutEncryptedObjectPipeline(self.config.cmm, self.config.encryption_algorithm)
        encrypted_data, encryption_metadata = pipeline.encrypt(
            body_bytes,
            encryption_context=encryption_context,
        )

        params["body"] = encrypted_data

        headers = safe_get_dict(params, "headers")

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
        if getattr(self._context, _CTX_INSTRUCTION_FILE_MODE, False):
            self.process_instruction_file(parsed)
            return

        # Get encryption context from thread-local storage (set by get_object wrapper)
        encryption_context = getattr(self._context, _CTX_ENCRYPTION_CONTEXT, None)

        # If Body is None, the S3 request failed (e.g., NoSuchKey).
        # Return early and let boto3 raise the original error.
        if parsed.get("Body", None) is None:
            return

        # The parsed response already has the Body as a StreamingBody
        # We need to read it, decrypt it, and replace it

        # content_length is going to the cipher-text's content length
        content_length = parsed.get("ContentLength")
        if content_length is None:
            obj_key = getattr(self._context, _CTX_KEY, None)
            raise S3EncryptionClientError(
                f"S3 response is missing ContentLength and is invalid. Key: {obj_key}"
            )
        # Create a response dict that matches what the pipeline expects
        response = {
            "Body": parsed.get("Body"),
            "Metadata": safe_get_dict(parsed, "Metadata"),
            "ContentLength": content_length,
        }

        # Create a pipeline and decrypt the data
        pipeline = GetEncryptedObjectPipeline(
            self.config.cmm,
            commitment_policy=self.config.commitment_policy,
            s3_client=getattr(self._context, _CTX_S3_CLIENT, None),
            enable_legacy_unauthenticated_modes=self.config.enable_legacy_unauthenticated_modes,
            instruction_file_config=self.config.instruction_file_config,
        )
        decrypted_data = pipeline.decrypt(
            response,
            instruction_suffix=getattr(self._context, _CTX_INSTRUCTION_FILE_SUFFIX, ".instruction"),
            enable_delayed_authentication=self.config.enable_delayed_authentication,
            encryption_context=encryption_context,
            bucket=getattr(self._context, _CTX_BUCKET, None),
            key=getattr(self._context, _CTX_KEY, None),
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
        instruction_key = getattr(self._context, _CTX_KEY, None)

        body = parsed.get("Body", None)
        if body is None:
            raise S3EncryptionClientError(
                f"Instruction file body is empty for key: {instruction_key}"
            )

        # In plaintext mode, parse instruction file and append to metadata
        existing_metadata = safe_get_dict(parsed, "Metadata")
        instruction_data = body.read()
        instruction_metadata = parse_instruction_file(instruction_data, instruction_key)

        # Append parsed instruction file content to existing metadata
        existing_metadata.update(instruction_metadata)
        parsed["Metadata"] = existing_metadata

        # Clear the body since instruction files shouldn't return body content
        stream = io.BytesIO(b"")
        streaming_body = StreamingBody(stream, 0)
        parsed["Body"] = streaming_body


def _validate_encryption_context(encryption_context):
    """Validate that all encryption context keys and values are US-ASCII.

    S3 applies double-encoding to non-ASCII metadata values that SDKs do not
    automatically decode, which causes decryption to fail because the stored
    encryption context won't match the original.

    Raises:
        S3EncryptionClientError: If any key or value contains non-ASCII characters.
    """
    if encryption_context is None:
        return
    if not isinstance(encryption_context, dict):
        raise S3EncryptionClientError("EncryptionContext must be a dictionary")
    for k, v in encryption_context.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise S3EncryptionClientError("EncryptionContext keys and values must be strings")
        if not k.isascii() or not v.isascii():
            raise S3EncryptionClientError(
                f"EncryptionContext keys and values must contain only US-ASCII characters. "
                f"Non-ASCII characters in S3 metadata are encoded by the server "
                f"and will cause decryption to fail. "
                f"First offending entry: {repr(k)}: {repr(v)}"
            )


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
    # Each upload gets its own pipeline with independent cipher state, keyed by UploadId.
    # Access is protected by a lock for thread safety across all Python runtimes.
    _multipart_uploads: dict = field(init=False, factory=dict)
    _multipart_lock: threading.Lock = field(init=False, factory=threading.Lock)

    def __attrs_post_init__(self):
        """Install the encryption plugin on the wrapped client using boto3 events."""
        # Create the plugin
        object.__setattr__(self, "_plugin", S3EncryptionClientPlugin(self.config))

        # Expose plugin context on wrapped client for instruction file fetching
        self.wrapped_s3_client._s3ec_plugin_context = self._plugin._context

        append_user_agent(self.wrapped_s3_client, _USER_AGENT_SUFFIX)

        # Register event handlers using boto3's event system
        event_system = self.wrapped_s3_client.meta.events
        event_system.register("before-call.s3.PutObject", self._plugin.on_put_object_before_call)
        event_system.register("after-call.s3.GetObject", self._plugin.on_get_object_after_call)

    def __getattr__(self, name):
        """Proxy unrecognized attributes to the wrapped S3 client.

        This allows the S3EncryptionClient to be used like a regular boto3 S3
        client for operations it doesn't intercept (e.g. copy_object,
        list_objects_v2, etc.).
        """
        return getattr(self.wrapped_s3_client, name)

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
        _validate_encryption_context(encryption_context)

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
            if hasattr(self._plugin._context, _CTX_ENCRYPTION_CONTEXT):
                delattr(self._plugin._context, _CTX_ENCRYPTION_CONTEXT)

    ##= specification/s3-encryption/client.md#required-api-operations
    ##% - DeleteObject MUST be implemented by the S3EC.
    def delete_object(self, **kwargs):
        """Delete an object and its associated instruction file from S3.

        Args:
            **kwargs: Arguments to pass to the S3 client's delete_object method.
                      Must include Bucket and Key parameters.
                      May include InstructionFileSuffix to override the default
                      ".instruction" suffix for instruction file deletion.

        Returns:
            The response from the S3 client's delete_object call for the object.

        Raises:
            S3EncryptionClientError: If the delete operation fails.
        """
        ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        ##= type=implementation
        ##% The default Instruction File behavior uses the same S3 object key
        ##% as its associated object suffixed with ".instruction".
        instruction_file_suffix = kwargs.pop("InstructionFileSuffix", ".instruction")

        try:
            ##= specification/s3-encryption/client.md#required-api-operations
            ##= type=implementation
            ##% - DeleteObject MUST delete the given object key.
            response = self.wrapped_s3_client.delete_object(**kwargs)

            ##= specification/s3-encryption/client.md#required-api-operations
            ##= type=implementation
            ##% - DeleteObject MUST delete the associated instruction file
            ##%   using the default instruction file suffix.
            if not self.config.instruction_file_config.disable_delete_object:
                instruction_key = kwargs["Key"] + instruction_file_suffix
                self.wrapped_s3_client.delete_object(Bucket=kwargs["Bucket"], Key=instruction_key)

            return response
        except S3EncryptionClientError:
            raise
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to delete object: {str(e)}") from e

    ##= specification/s3-encryption/client.md#required-api-operations
    ##% - DeleteObjects MUST be implemented by the S3EC.
    def delete_objects(self, **kwargs):
        """Delete multiple objects and their associated instruction files from S3.

        2 requests are issued, one for the objects, and one for the instruction files.
        If either requests fail, the operation fails, and maybe tried again to clean up any missed files.

        Args:
            **kwargs: Arguments to pass to the S3 client's delete_objects method.
                      Must include Bucket and Delete (with Objects list) parameters.
                      May include InstructionFileSuffix to override the default
                      ".instruction" suffix for instruction file deletion.

        Returns:
            The response from the S3 client's delete_objects call for the objects.

        Raises:
            S3EncryptionClientError: If either delete operations fails.
        """
        instruction_file_suffix = kwargs.pop("InstructionFileSuffix", ".instruction")

        try:
            ##= specification/s3-encryption/client.md#required-api-operations
            ##= type=implementation
            ##% - DeleteObjects MUST delete each of the given objects.
            response = self.wrapped_s3_client.delete_objects(**kwargs)

            ##= specification/s3-encryption/client.md#required-api-operations
            ##= type=implementation
            ##% - DeleteObjects MUST delete each of the corresponding instruction files
            ##%   using the default instruction file suffix.
            if not self.config.instruction_file_config.disable_delete_objects:
                instruction_objects = [
                    {"Key": obj["Key"] + instruction_file_suffix}
                    for obj in kwargs["Delete"]["Objects"]
                ]
                self.wrapped_s3_client.delete_objects(
                    Bucket=kwargs["Bucket"], Delete={"Objects": instruction_objects}
                )

            return response
        except S3EncryptionClientError:
            raise
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to delete objects: {str(e)}") from e

    def get_object(self, **kwargs):
        """Download and decrypt an object from S3.

        This method downloads an encrypted object from S3 and decrypts it
        using the configured crypto materials manager.

        Args:
            **kwargs: Arguments to pass to the S3 client's get_object method.
                      May include EncryptionContext if it was used during encryption.
                      May include InstructionFileSuffix to override the default
                      ".instruction" suffix for instruction file lookups.

        Returns:
            The response from the S3 client's get_object method with the Body
            replaced with a StreamingBody containing the decrypted data.

        Raises:
            S3EncryptionClientError: If decryption fails or the object is not properly encrypted.
        """
        # Ranged gets are not supported — decryption requires the full ciphertext.
        if "Range" in kwargs:
            raise S3EncryptionClientError(
                "Ranged gets are currently not supported by the S3 Encryption Client for Python."
            )

        # Extract EncryptionContext if provided (not a standard S3 parameter)
        encryption_context = kwargs.pop("EncryptionContext", None)
        _validate_encryption_context(encryption_context)
        ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        ##= type=implementation
        ##% The S3EC SHOULD support providing a custom Instruction File suffix
        ##% on GetObject requests, regardless of whether or not re-encryption is supported.

        ##= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        ##= type=implementation
        ##% The default Instruction File behavior uses the same S3 object key
        ##% as its associated object suffixed with ".instruction".
        instruction_file_suffix = kwargs.pop("InstructionFileSuffix", ".instruction")

        # Store encryption context in thread-local storage for the event handler
        setattr(self._plugin._context, _CTX_ENCRYPTION_CONTEXT, encryption_context)
        setattr(self._plugin._context, _CTX_INSTRUCTION_FILE_SUFFIX, instruction_file_suffix)
        # Store wrapped client in thread-local storage for
        # the event handler to fetch instruction files
        setattr(self._plugin._context, _CTX_S3_CLIENT, self.wrapped_s3_client)
        setattr(self._plugin._context, _CTX_BUCKET, kwargs.get("Bucket"))
        setattr(self._plugin._context, _CTX_KEY, kwargs.get("Key"))

        try:
            return self.wrapped_s3_client.get_object(**kwargs)
        except S3EncryptionClientError:
            # Re-raise our own exceptions without wrapping
            raise
        except ClientError as e:
            # Wrap S3 service errors (e.g., NoSuchKey) with context
            raise S3EncryptionClientError(
                f"Failed to retrieve and/or decrypt object: {str(e)}"
            ) from e
        except Exception as e:
            # Wrap any unexpected errors during decryption
            raise S3EncryptionClientError(
                f"Failed to retrieve and/or decrypt object: {str(e)}"
            ) from e
        finally:
            # Clean up thread-local storage;
            # do not clean up the client as it is not thread local only
            for attr in _GET_OBJECT_CLEANUP_ATTRS:
                if hasattr(self._plugin._context, attr):
                    delattr(self._plugin._context, attr)

    ##= specification/s3-encryption/client.md#optional-api-operations
    ##= type=implementation
    ##% CreateMultipartUpload MAY be implemented by the S3EC.
    def create_multipart_upload(self, **kwargs):
        """Initiate an encrypted multipart upload.

        Obtains encryption materials, initializes the cipher, and calls
        the underlying S3 CreateMultipartUpload. Encryption metadata is
        set on the object at this point.

        Args:
            **kwargs: Arguments for S3 create_multipart_upload.
                      May include EncryptionContext.

        Returns:
            The response from S3 create_multipart_upload.
        """
        encryption_context = kwargs.pop("EncryptionContext", None)
        _validate_encryption_context(encryption_context)

        pipeline = MultipartUploadPipeline(
            cmm=self.config.cmm,
            encryption_algorithm=self.config.encryption_algorithm,
            encryption_context=encryption_context or {},
        )

        # Merge encryption metadata into user-provided Metadata
        user_metadata = dict(kwargs.get("Metadata", {}))
        user_metadata.update(pipeline.metadata)
        kwargs["Metadata"] = user_metadata

        ##= specification/s3-encryption/client.md#optional-api-operations
        ##= type=implementation
        ##% If implemented, CreateMultipartUpload MUST initiate a multipart upload.
        try:
            response = self.wrapped_s3_client.create_multipart_upload(**kwargs)
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to create multipart upload: {e}") from e

        upload_id = response["UploadId"]
        with self._multipart_lock:
            self._multipart_uploads[upload_id] = pipeline
        return response

    ##= specification/s3-encryption/client.md#optional-api-operations
    ##= type=implementation
    ##% UploadPart MUST encrypt each part.
    ##= specification/s3-encryption/client.md#optional-api-operations
    ##= type=implementation
    ##% Each part MUST be encrypted in sequence.
    ##= specification/s3-encryption/client.md#optional-api-operations
    ##= type=implementation
    ##% Each part MUST be encrypted using the same cipher instance for each part.
    def upload_part(self, **kwargs):
        """Encrypt and upload a single part of a multipart upload.

        Parts must be uploaded in sequential order (1, 2, 3, ...).
        The caller MUST set ``IsLastPart=True`` on the final part so the
        GCM authentication tag is appended to the ciphertext.

        Args:
            **kwargs: Arguments for S3 upload_part. Must include UploadId,
                      PartNumber, and Body. Set IsLastPart=True on the
                      final part.

        Returns:
            The response from S3 upload_part (includes ETag).
        """
        upload_id = kwargs.get("UploadId")
        with self._multipart_lock:
            pipeline = self._multipart_uploads.get(upload_id)
        if pipeline is None:
            raise S3EncryptionClientError(
                f"No multipart upload found for UploadId: {upload_id}. "
                "Call create_multipart_upload first."
            )

        part_number = kwargs["PartNumber"]
        is_last = kwargs.pop("IsLastPart", False)
        body = kwargs.get("Body", b"")
        if isinstance(body, str):
            body = body.encode("utf-8")
        elif hasattr(body, "read"):
            body = body.read()

        try:
            ciphertext = pipeline.encrypt_part(part_number, body, is_last=is_last)
        except S3EncryptionClientError:
            raise
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to encrypt part {part_number}: {e}") from e

        kwargs["Body"] = ciphertext
        return self.wrapped_s3_client.upload_part(**kwargs)

    ##= specification/s3-encryption/client.md#optional-api-operations
    ##= type=implementation
    ##% CompleteMultipartUpload MAY be implemented by the S3EC.
    ##% CompleteMultipartUpload MUST complete the multipart upload.
    def complete_multipart_upload(self, **kwargs):
        """Complete the multipart upload.

        The final part must have been uploaded with ``IsLastPart=True``
        before calling this method.

        Args:
            **kwargs: Arguments for S3 complete_multipart_upload.
                      MultipartUpload.Parts must include PartNumber and ETag
                      for each part.

        Returns:
            The response from S3 complete_multipart_upload.
        """
        upload_id = kwargs.get("UploadId")
        with self._multipart_lock:
            pipeline = self._multipart_uploads.get(upload_id)
        if pipeline is None:
            raise S3EncryptionClientError(f"No multipart upload found for UploadId: {upload_id}.")

        if not pipeline.has_final_part_been_seen:
            raise S3EncryptionClientError(
                "Cannot complete multipart upload: the final part has not been uploaded. "
                "Set IsLastPart=True on the last upload_part call."
            )

        try:
            response = self.wrapped_s3_client.complete_multipart_upload(**kwargs)
        except S3EncryptionClientError:
            raise
        except Exception as e:
            raise S3EncryptionClientError(f"Failed to complete multipart upload: {e}") from e
        else:
            with self._multipart_lock:
                self._multipart_uploads.pop(upload_id, None)
            return response

    ##= specification/s3-encryption/client.md#optional-api-operations
    ##= type=implementation
    ##% AbortMultipartUpload MAY be implemented by the S3EC.
    ##% AbortMultipartUpload MUST abort the multipart upload.
    def abort_multipart_upload(self, **kwargs):
        """Abort a multipart upload and clean up cipher state.

        Args:
            **kwargs: Arguments for S3 abort_multipart_upload.

        Returns:
            The response from S3 abort_multipart_upload.
        """
        upload_id = kwargs.get("UploadId")
        with self._multipart_lock:
            self._multipart_uploads.pop(upload_id, None)
        return self.wrapped_s3_client.abort_multipart_upload(**kwargs)

    def upload_file(
        self, filename, bucket, key, multipart_threshold=None, multipart_chunksize=None, **kwargs
    ):
        """Encrypt and upload a file to S3.

        If the file is smaller than the threshold, uses put_object.
        Otherwise, performs an encrypted multipart upload.

        Args:
            filename: Path to the file to upload.
            bucket: Target S3 bucket.
            key: Target S3 object key.
            multipart_threshold: File size threshold for multipart (default 8MB).
            multipart_chunksize: Size of each part (default 8MB).
            **kwargs: Additional arguments (e.g. EncryptionContext, Metadata).
        """
        threshold = (
            _DEFAULT_MULTIPART_THRESHOLD if multipart_threshold is None else multipart_threshold
        )
        chunksize = (
            _DEFAULT_MULTIPART_CHUNKSIZE if multipart_chunksize is None else multipart_chunksize
        )
        if threshold <= 0:
            raise S3EncryptionClientError("multipart_threshold must be a positive integer.")
        if chunksize <= 0:
            raise S3EncryptionClientError("multipart_chunksize must be a positive integer.")
        if chunksize < _MIN_MULTIPART_PART_SIZE:
            raise S3EncryptionClientError(
                f"multipart_chunksize must be at least {_MIN_MULTIPART_PART_SIZE} bytes (5 MB). "
                f"S3 requires all non-final parts to be at least 5 MB."
            )
        file_size = os.path.getsize(filename)

        if file_size < threshold:
            with open(filename, "rb") as f:
                kwargs["Bucket"] = bucket
                kwargs["Key"] = key
                kwargs["Body"] = f.read()
                return self.put_object(**kwargs)

        return self._multipart_upload_from_readable(
            open(filename, "rb"), bucket, key, chunksize, owns_readable=True, **kwargs
        )

    def upload_fileobj(self, fileobj, bucket, key, multipart_chunksize=None, **kwargs):
        """Encrypt and upload a file-like object to S3 via multipart upload.

        The caller retains ownership of fileobj — it will not be closed
        by this method.

        Args:
            fileobj: A file-like object with a read() method.
            bucket: Target S3 bucket.
            key: Target S3 object key.
            multipart_chunksize: Size of each part (default 8MB).
            **kwargs: Additional arguments (e.g. EncryptionContext, Metadata).
        """
        chunksize = (
            _DEFAULT_MULTIPART_CHUNKSIZE if multipart_chunksize is None else multipart_chunksize
        )
        if chunksize <= 0:
            raise S3EncryptionClientError("multipart_chunksize must be a positive integer.")
        if chunksize < _MIN_MULTIPART_PART_SIZE:
            raise S3EncryptionClientError(
                f"multipart_chunksize must be at least {_MIN_MULTIPART_PART_SIZE} bytes (5 MB). "
                f"S3 requires all non-final parts to be at least 5 MB."
            )
        return self._multipart_upload_from_readable(
            fileobj, bucket, key, chunksize, owns_readable=False, **kwargs
        )

    def _multipart_upload_from_readable(
        self, readable, bucket, key, chunksize, *, owns_readable=False, **kwargs
    ):
        """Perform an encrypted multipart upload from a readable source.

        Args:
            readable: File-like object to read from.
            bucket: Target S3 bucket.
            key: Target S3 object key.
            chunksize: Size of each part in bytes.
            owns_readable: If True, close readable when done. If False,
                the caller is responsible for closing it.
            **kwargs: Additional S3 parameters forwarded to create_multipart_upload.
        """
        # EncryptionContext is consumed by our pipeline, not S3
        create_kwargs = {"Bucket": bucket, "Key": key}
        if "EncryptionContext" in kwargs:
            create_kwargs["EncryptionContext"] = kwargs.pop("EncryptionContext")
        if "Metadata" in kwargs:
            create_kwargs["Metadata"] = kwargs.pop("Metadata")
        # Forward remaining kwargs (ACL, ContentType, Tagging, etc.) to create_multipart_upload
        create_kwargs.update(kwargs)

        create_resp = self.create_multipart_upload(**create_kwargs)
        upload_id = create_resp["UploadId"]

        try:
            parts = []
            part_number = 0
            # Read ahead so we can detect the last chunk
            current_chunk = readable.read(chunksize)
            while current_chunk:
                next_chunk = readable.read(chunksize)
                part_number += 1
                is_last = not next_chunk
                resp = self.upload_part(
                    Bucket=bucket,
                    Key=key,
                    UploadId=upload_id,
                    PartNumber=part_number,
                    Body=current_chunk,
                    IsLastPart=is_last,
                )
                parts.append({"PartNumber": part_number, "ETag": resp["ETag"]})
                current_chunk = next_chunk

            return self.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except Exception:
            self.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
            raise
        finally:
            if owns_readable and hasattr(readable, "close"):
                readable.close()
