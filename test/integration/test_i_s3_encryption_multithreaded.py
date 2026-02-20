# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Multi-threaded integration tests for S3 Encryption Client.

These tests verify that the thread-local storage of encryption context
is properly isolated between threads when using a single S3EncryptionClient
instance across multiple threads.
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import boto3

from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig, InstructionFileSetting
from s3_encryption.exceptions import S3EncryptionClientError
from s3_encryption.materials.kms_keyring import KmsKeyring

bucket = os.environ.get("CI_S3_BUCKET", "s3ec-python-github-test-bucket")
region = os.environ.get("CI_AWS_REGION", "us-west-2")
kms_key_id = os.environ.get(
    "CI_KMS_KEY_ALIAS", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Python-Github-KMS-Key"
)


def test_multithreaded_encryption_context_isolation():
    """Test that encryption context is properly isolated between threads.

    This test creates a single S3EncryptionClient instance and uses it
    from multiple threads simultaneously, each with a different encryption
    context. It verifies that:
    1. Each thread can encrypt with its own encryption context
    2. Each thread can decrypt only with the correct encryption context
    3. Thread-local storage doesn't leak between threads
    """
    # Create a single S3EncryptionClient instance to be shared across threads
    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE)

    # Number of threads to test with
    num_threads = 10
    results = {}
    errors = []

    def thread_worker(thread_id):
        """Worker function for each thread."""
        try:
            # Each thread has its own unique encryption context
            encryption_context = {
                "thread_id": str(thread_id),
                "department": f"dept-{thread_id}",
                "project": f"project-{thread_id}",
            }

            # Unique key for this thread
            key = f"multithread-test-{thread_id}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}"
            data = f"Thread {thread_id} test data with unique encryption context"

            # Encrypt with thread-specific encryption context
            s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

            # Decrypt with the SAME encryption context - should succeed
            response = s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext=encryption_context)
            decrypted_data = response["Body"].read().decode("utf-8")

            if decrypted_data != data:
                return {
                    "thread_id": thread_id,
                    "success": False,
                    "error": f"Data mismatch: expected '{data}', got '{decrypted_data}'",
                }

            # Try to decrypt with a DIFFERENT encryption context - should fail
            wrong_context = {
                "thread_id": str(thread_id + 1000),
                "department": "wrong-dept",
                "project": "wrong-project",
            }

            try:
                s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext=wrong_context)
                return {
                    "thread_id": thread_id,
                    "success": False,
                    "error": "Decryption succeeded with wrong encryption context!",
                }
            except S3EncryptionClientError:
                # Expected - decryption should fail with wrong context
                pass

            # Try to decrypt with NO encryption context - should also fail
            try:
                s3ec.get_object(Bucket=bucket, Key=key)
                return {
                    "thread_id": thread_id,
                    "success": False,
                    "error": "Decryption succeeded without encryption context!",
                }
            except S3EncryptionClientError:
                # Expected - decryption should fail without context
                pass

            return {
                "thread_id": thread_id,
                "success": True,
                "key": key,
                "encryption_context": encryption_context,
            }

        except Exception as e:
            return {"thread_id": thread_id, "success": False, "error": str(e)}

    # Execute threads concurrently
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(thread_worker, i) for i in range(num_threads)]

        for future in as_completed(futures):
            result = future.result()
            thread_id = result["thread_id"]
            results[thread_id] = result

            if not result["success"]:
                errors.append(f"Thread {thread_id}: {result['error']}")

    # Verify all threads succeeded
    if errors:
        print("Errors occurred during multi-threaded test:")
        for error in errors:
            print(f"  - {error}")
        raise RuntimeError(f"{len(errors)} thread(s) failed")

    print(f"Success! All {num_threads} threads completed successfully.")
    print("Each thread:")
    print("  - Encrypted with its own unique encryption context")
    print("  - Decrypted successfully with the correct context")
    print("  - Failed to decrypt with wrong context (as expected)")
    print("  - Failed to decrypt without context (as expected)")


def test_multithreaded_rapid_context_switching():
    """Test rapid switching of encryption contexts in the same thread.

    This test verifies that encryption context is properly cleaned up
    between operations within the same thread.
    """
    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE)
    num_iterations = 20
    errors = []

    def rapid_context_worker(thread_id):
        """Worker that rapidly switches between different encryption contexts."""
        try:
            for i in range(num_iterations):
                # Alternate between different encryption contexts
                if i % 3 == 0:
                    encryption_context = {"iteration": str(i), "type": "typeA"}
                elif i % 3 == 1:
                    encryption_context = {"iteration": str(i), "type": "typeB"}
                else:
                    encryption_context = {"iteration": str(i), "type": "typeC"}

                key = (
                    f"rapid-switch-t{thread_id}-i{i}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}"
                )
                data = f"Thread {thread_id} iteration {i}"

                # Encrypt
                s3ec.put_object(
                    Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context
                )

                # Decrypt with correct context
                response = s3ec.get_object(
                    Bucket=bucket, Key=key, EncryptionContext=encryption_context
                )
                decrypted_data = response["Body"].read().decode("utf-8")

                if decrypted_data != data:
                    return {
                        "thread_id": thread_id,
                        "iteration": i,
                        "success": False,
                        "error": f"Data mismatch at iteration {i}",
                    }

            return {"thread_id": thread_id, "success": True}

        except Exception as e:
            return {"thread_id": thread_id, "success": False, "error": str(e)}

    # Run multiple threads doing rapid context switching
    num_threads = 5
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(rapid_context_worker, i) for i in range(num_threads)]

        for future in as_completed(futures):
            result = future.result()
            if not result["success"]:
                errors.append(
                    f"Thread {result['thread_id']}: {result.get('error', 'Unknown error')}"
                )

    if errors:
        print("Errors occurred during rapid context switching test:")
        for error in errors:
            print(f"  - {error}")
        raise RuntimeError(f"{len(errors)} thread(s) failed")

    print(f"Success! {num_threads} threads completed {num_iterations} iterations each.")
    print("Encryption context was properly isolated across rapid context switches.")


def test_multithreaded_mixed_with_and_without_context():
    """Test threads using encryption context mixed with threads not using it.

    This verifies that threads without encryption context don't interfere
    with threads that use encryption context.
    """
    kms_client = boto3.client("kms", region_name=region)
    keyring = KmsKeyring(kms_client, kms_key_id)
    wrapped_client = boto3.client("s3")
    config = S3EncryptionClientConfig(keyring)
    s3ec = S3EncryptionClient(wrapped_client, config, instruction_file_setting=InstructionFileSetting.DISABLE)
    errors = []

    def worker_with_context(thread_id):
        """Worker that uses encryption context."""
        try:
            encryption_context = {"thread_id": str(thread_id), "has_context": "true"}
            key = f"mixed-with-ctx-{thread_id}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}"
            data = f"Thread {thread_id} WITH context"

            s3ec.put_object(Bucket=bucket, Key=key, Body=data, EncryptionContext=encryption_context)

            response = s3ec.get_object(Bucket=bucket, Key=key, EncryptionContext=encryption_context)
            decrypted_data = response["Body"].read().decode("utf-8")

            if decrypted_data != data:
                return {"thread_id": thread_id, "success": False, "error": "Data mismatch"}

            return {"thread_id": thread_id, "success": True, "type": "with_context"}

        except Exception as e:
            return {"thread_id": thread_id, "success": False, "error": str(e)}

    def worker_without_context(thread_id):
        """Worker that does NOT use encryption context."""
        try:
            key = f"mixed-no-ctx-{thread_id}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}"
            data = f"Thread {thread_id} WITHOUT context"

            # No encryption context
            s3ec.put_object(Bucket=bucket, Key=key, Body=data)

            # No encryption context on decrypt either
            response = s3ec.get_object(Bucket=bucket, Key=key)
            decrypted_data = response["Body"].read().decode("utf-8")

            if decrypted_data != data:
                return {"thread_id": thread_id, "success": False, "error": "Data mismatch"}

            return {"thread_id": thread_id, "success": True, "type": "without_context"}

        except Exception as e:
            return {"thread_id": thread_id, "success": False, "error": str(e)}

    # Mix threads with and without encryption context
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []

        # Submit 5 threads with context
        for i in range(5):
            futures.append(executor.submit(worker_with_context, i))

        # Submit 5 threads without context
        for i in range(5, 10):
            futures.append(executor.submit(worker_without_context, i))

        for future in as_completed(futures):
            result = future.result()
            if not result["success"]:
                errors.append(
                    f"Thread {result['thread_id']}: {result.get('error', 'Unknown error')}"
                )

    if errors:
        print("Errors occurred during mixed context test:")
        for error in errors:
            print(f"  - {error}")
        raise RuntimeError(f"{len(errors)} thread(s) failed")

    print("Success! Mixed threads (with and without encryption context) completed successfully.")
    print("Thread-local storage properly isolated context between threads.")
