# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance tests comparing S3EC against plaintext S3 and local encryption + S3 upload.

Each test runs multiple rounds with large objects to get a meaningful signal.
Results are collected via a module-scoped list and written to a JSON file
that the HTML report generator consumes.

Connection warmup is handled once at module level with a small payload so that
TCP/TLS establishment and KMS client init costs don't pollute any benchmark.
"""

import json
import os
import time
from datetime import datetime

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy

from .conftest import BUCKET, KMS_KEY_ID, NUM_ROUNDS, OBJECT_SIZES_MB, REGION, _make_s3ec

PERF_KEY_PREFIX = "perf-test/"
RESULTS_FILE = os.environ.get("PERF_RESULTS_FILE", "perf-results/results.json")

# Collect all benchmark results here
_results: list[dict] = []

ALGORITHM_CONFIGS = [
    pytest.param(
        AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        id="AES_GCM",
    ),
    pytest.param(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        id="KC_GCM",
    ),
]

# Pre-generate payloads once at module level to avoid repeated large allocations
_PAYLOADS: dict[int, bytes] = {}


def _get_payload(size_mb: int) -> bytes:
    if size_mb not in _PAYLOADS:
        chunk = os.urandom(1024)
        _PAYLOADS[size_mb] = (chunk * 1024 * size_mb)[: size_mb * 1024 * 1024]
    return _PAYLOADS[size_mb]


# Small payload used only for connection warmup (1 KB)
_WARMUP_PAYLOAD = b"x" * 1024


def _unique_key(prefix: str) -> str:
    return PERF_KEY_PREFIX + prefix + datetime.now().strftime("%Y%m%d-%H%M%S-%f")


def _record(test_name, size_mb, durations):
    _results.append(
        {
            "test": test_name,
            "size_mb": size_mb,
            "rounds": len(durations),
            "durations_s": durations,
            "mean_s": sum(durations) / len(durations),
            "min_s": min(durations),
            "max_s": max(durations),
        }
    )


def _algo_label(algorithm_suite):
    """Short human-readable label for an algorithm suite."""
    if algorithm_suite == AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
        return "aes_gcm"
    return "kc_gcm"


def _warmup_connection(client, is_plain=False):
    """Warm up TCP/TLS connections with a tiny payload. Called once per client."""
    key = _unique_key("warmup-conn-")
    if is_plain:
        client.put_object(Bucket=BUCKET, Key=key, Body=_WARMUP_PAYLOAD)
        resp = client.get_object(Bucket=BUCKET, Key=key)
    else:
        client.put_object(Bucket=BUCKET, Key=key, Body=_WARMUP_PAYLOAD)
        resp = client.get_object(Bucket=BUCKET, Key=key)
    resp["Body"].read()


# ---------------------------------------------------------------------------
# S3EC put_object vs plain S3 put_object (per algorithm suite)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
@pytest.mark.parametrize("size_mb", OBJECT_SIZES_MB)
def test_s3ec_put_vs_plain_put(plain_s3, size_mb, algorithm_suite, commitment_policy):
    """Compare S3EC put_object latency against plain S3 put_object."""
    label = _algo_label(algorithm_suite)
    payload = _get_payload(size_mb)

    # Benchmark plain S3 put (only record once per size)
    if algorithm_suite == AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
        _warmup_connection(plain_s3, is_plain=True)
        plain_durations = []
        for _ in range(NUM_ROUNDS):
            key = _unique_key(f"plain-put-{size_mb}mb-")
            t0 = time.perf_counter()
            plain_s3.put_object(Bucket=BUCKET, Key=key, Body=payload)
            plain_durations.append(time.perf_counter() - t0)
        _record(f"plain_s3_put_{size_mb}mb", size_mb, plain_durations)

    # Benchmark S3EC put
    s3ec = _make_s3ec(algorithm_suite, commitment_policy)
    _warmup_connection(s3ec)
    s3ec_durations = []
    for _ in range(NUM_ROUNDS):
        key = _unique_key(f"s3ec-put-{label}-{size_mb}mb-")
        t0 = time.perf_counter()
        s3ec.put_object(Bucket=BUCKET, Key=key, Body=payload)
        s3ec_durations.append(time.perf_counter() - t0)
    _record(f"s3ec_put_{label}_{size_mb}mb", size_mb, s3ec_durations)


# ---------------------------------------------------------------------------
# S3EC get_object vs plain S3 get_object (per algorithm suite)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
@pytest.mark.parametrize("size_mb", OBJECT_SIZES_MB)
def test_s3ec_get_vs_plain_get(plain_s3, size_mb, algorithm_suite, commitment_policy):
    """Compare S3EC get_object latency against plain S3 get_object."""
    label = _algo_label(algorithm_suite)
    payload = _get_payload(size_mb)

    # Upload a plain object (only once per size)
    if algorithm_suite == AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
        plain_key = _unique_key(f"plain-get-src-{size_mb}mb-")
        plain_s3.put_object(Bucket=BUCKET, Key=plain_key, Body=payload)

        _warmup_connection(plain_s3, is_plain=True)
        plain_durations = []
        for _ in range(NUM_ROUNDS):
            t0 = time.perf_counter()
            resp = plain_s3.get_object(Bucket=BUCKET, Key=plain_key)
            resp["Body"].read()
            plain_durations.append(time.perf_counter() - t0)
        _record(f"plain_s3_get_{size_mb}mb", size_mb, plain_durations)

    # Upload an encrypted object and benchmark get
    s3ec = _make_s3ec(algorithm_suite, commitment_policy)
    enc_key = _unique_key(f"s3ec-get-src-{label}-{size_mb}mb-")
    s3ec.put_object(Bucket=BUCKET, Key=enc_key, Body=payload)

    _warmup_connection(s3ec)
    s3ec_durations = []
    for _ in range(NUM_ROUNDS):
        t0 = time.perf_counter()
        resp = s3ec.get_object(Bucket=BUCKET, Key=enc_key)
        resp["Body"].read()
        s3ec_durations.append(time.perf_counter() - t0)
    _record(f"s3ec_get_{label}_{size_mb}mb", size_mb, s3ec_durations)


# ---------------------------------------------------------------------------
# S3EC roundtrip vs local encrypt + plain S3 upload (per algorithm suite)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm_suite,commitment_policy", ALGORITHM_CONFIGS)
@pytest.mark.parametrize("size_mb", OBJECT_SIZES_MB)
def test_s3ec_roundtrip_vs_local_crypto(
    plain_s3, kms_client, size_mb, algorithm_suite, commitment_policy
):
    """Compare S3EC roundtrip against manual local AES-GCM encrypt + plain S3 roundtrip."""
    label = _algo_label(algorithm_suite)
    payload = _get_payload(size_mb)

    # S3EC roundtrip
    s3ec = _make_s3ec(algorithm_suite, commitment_policy)
    _warmup_connection(s3ec)
    s3ec_durations = []
    for _ in range(NUM_ROUNDS):
        key = _unique_key(f"s3ec-rt-{label}-{size_mb}mb-")
        t0 = time.perf_counter()
        s3ec.put_object(Bucket=BUCKET, Key=key, Body=payload)
        resp = s3ec.get_object(Bucket=BUCKET, Key=key)
        resp["Body"].read()
        s3ec_durations.append(time.perf_counter() - t0)
    _record(f"s3ec_roundtrip_{label}_{size_mb}mb", size_mb, s3ec_durations)

    # Local crypto + plain S3 roundtrip (only once per size)
    if algorithm_suite == AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
        _warmup_connection(plain_s3, is_plain=True)
        # Warm up KMS connection
        kms_client.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")

        local_durations = []
        for _ in range(NUM_ROUNDS):
            key = _unique_key(f"local-rt-{size_mb}mb-")
            t0 = time.perf_counter()

            dk_resp = kms_client.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")
            data_key = dk_resp["Plaintext"]

            aesgcm = AESGCM(data_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, payload, None)

            plain_s3.put_object(Bucket=BUCKET, Key=key, Body=nonce + ciphertext)

            resp = plain_s3.get_object(Bucket=BUCKET, Key=key)
            blob = resp["Body"].read()
            aesgcm.decrypt(blob[:12], blob[12:], None)

            local_durations.append(time.perf_counter() - t0)
        _record(f"local_crypto_roundtrip_{size_mb}mb", size_mb, local_durations)


# ---------------------------------------------------------------------------
# Write results to JSON at end of module
# ---------------------------------------------------------------------------


def test_zz_write_results():
    """Final test that writes collected results to a JSON file for the HTML report."""
    os.makedirs(os.path.dirname(RESULTS_FILE) or ".", exist_ok=True)
    with open(RESULTS_FILE, "w") as f:
        json.dump(
            {
                "timestamp": datetime.now().isoformat(),
                "config": {
                    "num_rounds": NUM_ROUNDS,
                    "object_sizes_mb": OBJECT_SIZES_MB,
                    "bucket": BUCKET,
                    "region": REGION,
                },
                "results": _results,
            },
            f,
            indent=2,
        )
    print(f"\nPerformance results written to {RESULTS_FILE}")
