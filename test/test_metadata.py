# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
import sys
import unittest

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from s3_encryption.metadata import ObjectMetadata


class TestObjectMetadata(unittest.TestCase):
    def test_from_dict(self):
        # Create a metadata dictionary
        metadata_dict = {
            "x-amz-key-v2": "encrypted-key-data",
            "x-amz-wrap-alg": "kms+context",
            "x-amz-iv": "base64-encoded-iv",
            "x-amz-cek-alg": "AES/GCM/NoPadding",
        }

        # Create an ObjectMetadata instance from the dictionary
        metadata = ObjectMetadata.from_dict(metadata_dict)

        # Verify that the fields were populated correctly
        self.assertEqual(metadata.encrypted_data_key_v2, "encrypted-key-data")
        self.assertEqual(metadata.encrypted_data_key_algorithm, "kms+context")
        self.assertEqual(metadata.content_iv, "base64-encoded-iv")
        self.assertEqual(metadata.content_cipher, "AES/GCM/NoPadding")

        # Verify that fields not in the dictionary are None
        self.assertIsNone(metadata.encrypted_data_key_v1)
        self.assertIsNone(metadata.encrypted_data_key_context)
        # Note: content_cipher_tag_length is None because it's not in the input dictionary
        self.assertIsNone(metadata.content_cipher_tag_length)
        self.assertIsNone(metadata.instruction_file)

    def test_to_dict(self):
        # Create an ObjectMetadata instance with some fields set
        metadata = ObjectMetadata(
            encrypted_data_key_v2="encrypted-key-data",
            encrypted_data_key_algorithm="kms+context",
            content_iv="base64-encoded-iv",
            content_cipher="AES/GCM/NoPadding",
        )

        # Convert to dictionary
        metadata_dict = metadata.to_dict()

        # Verify that the dictionary contains the expected keys and values
        self.assertEqual(metadata_dict["x-amz-key-v2"], "encrypted-key-data")
        self.assertEqual(metadata_dict["x-amz-wrap-alg"], "kms+context")
        self.assertEqual(metadata_dict["x-amz-iv"], "base64-encoded-iv")
        self.assertEqual(metadata_dict["x-amz-cek-alg"], "AES/GCM/NoPadding")

        # Verify that fields that are None are not included in the dictionary
        self.assertNotIn("x-amz-key", metadata_dict)
        self.assertNotIn("x-amz-matdesc", metadata_dict)
        # Note: content_cipher_tag_length has a default value of "128"
        self.assertEqual(metadata_dict.get("x-amz-tag-len"), "128")
        self.assertNotIn("x-amz-crypto-instr-file", metadata_dict)

    def test_roundtrip(self):
        # Create a metadata dictionary
        original_dict = {
            "x-amz-key-v2": "encrypted-key-data",
            "x-amz-wrap-alg": "kms+context",
            "x-amz-iv": "base64-encoded-iv",
            "x-amz-cek-alg": "AES/GCM/NoPadding",
        }

        # Convert to ObjectMetadata and back to dictionary
        metadata = ObjectMetadata.from_dict(original_dict)
        result_dict = metadata.to_dict()

        # Remove the tag length field which has a default value
        if "x-amz-tag-len" in result_dict:
            result_dict.pop("x-amz-tag-len")

        # Verify that the result matches the original
        self.assertEqual(result_dict, original_dict)


if __name__ == "__main__":
    unittest.main()
