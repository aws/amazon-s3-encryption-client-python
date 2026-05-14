# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance tests comparing S3EC against plaintext S3 and local encryption + S3 upload.

Each test runs multiple rounds with large objects to get a meaningful signal.
To control for temporal network variation, all variants within a test are
interleaved: round N of every variant runs back-to-back before moving to
round N+1. This ensures each variant experiences the same network conditions.

Results are collected via a module-scoped list and written to a JSON file
that the HTML report generator consumes.
"""

import json
import os
import random
import time
from datetime import datetime

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from s3_encryption.materials.materials import AlgorithmSuite, CommitmentPolicy

from .conftest import BUCKET, KMS_KEY_ID, NUM_ROUNDS, OBJECT_SIZES_MB, REGION, _make_s3ec

PERF_KEY_PREFIX = "perf-test/"
RESULTS_FILE = os.environ.get("PERF_RESULTS_FILE", "perf-results/results.json")

_results: list[dict] = []

# Pre-generate payloads once at module level
_PAYLOADS: dict[int, bytes] = {}
_WARMUP_PAYLOAD = b"x" * 1024

# Algorithm suite configs
_AES_GCM = (
    AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF,
    CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
)
_KC_GCM = (
    AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
    CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
)


def _get_payload(size_mb: int) -> bytes:
    if size_mb not in _PAYLOADS:
        chunk = os.urandom(1024)
        _PAYLOADS[size_mb] = (chunk * 1024 * size_mb)[: size_mb * 1024 * 1024]
    return _PAYLOADS[size_mb]


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


def _warmup_connection(client):
    """Warm up TCP/TLS connections with a tiny payload."""
    key = _unique_key("warmup-conn-")
    client.put_object(Bucket=BUCKET, Key=key, Body=_WARMUP_PAYLOAD)
    resp = client.get_object(Bucket=BUCKET, Key=key)
    resp["Body"].read()


# ---------------------------------------------------------------------------
# Interleaved put_object benchmark
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size_mb", OBJECT_SIZES_MB)
def test_put_interleaved(plain_s3, size_mb):
    """Interleaved put_object: plain S3, S3EC AES_GCM, S3EC KC_GCM."""
    payload = _get_payload(size_mb)

    s3ec_aes = _make_s3ec(*_AES_GCM)
    s3ec_kc = _make_s3ec(*_KC_GCM)

    # Warm up all connections
    _warmup_connection(plain_s3)
    _warmup_connection(s3ec_aes)
    _warmup_connection(s3ec_kc)

    plain_d, aes_d, kc_d = [], [], []

    # Define the three variants as callables
    def run_plain():
        key = _unique_key(f"plain-put-{size_mb}mb-")
        t0 = time.perf_counter()
        plain_s3.put_object(Bucket=BUCKET, Key=key, Body=payload)
        return time.perf_counter() - t0

    def run_aes():
        key = _unique_key(f"s3ec-put-aes-{size_mb}mb-")
        t0 = time.perf_counter()
        s3ec_aes.put_object(Bucket=BUCKET, Key=key, Body=payload)
        return time.perf_counter() - t0

    def run_kc():
        key = _unique_key(f"s3ec-put-kc-{size_mb}mb-")
        t0 = time.perf_counter()
        s3ec_kc.put_object(Bucket=BUCKET, Key=key, Body=payload)
        return time.perf_counter() - t0

    variants = [(run_plain, plain_d), (run_aes, aes_d), (run_kc, kc_d)]

    for _ in range(NUM_ROUNDS):
        # Shuffle order each round to eliminate positional bias
        random.shuffle(variants)
        for fn, collector in variants:
            collector.append(fn())

    _record(f"plain_s3_put_{size_mb}mb", size_mb, plain_d)
    _record(f"s3ec_put_aes_gcm_{size_mb}mb", size_mb, aes_d)
    _record(f"s3ec_put_kc_gcm_{size_mb}mb", size_mb, kc_d)


# ---------------------------------------------------------------------------
# Interleaved get_object benchmark
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size_mb", OBJECT_SIZES_MB)
def test_get_interleaved(plain_s3, size_mb):
    """Interleaved get_object: plain S3, S3EC AES_GCM, S3EC KC_GCM."""
    payload = _get_payload(size_mb)

    s3ec_aes = _make_s3ec(*_AES_GCM)
    s3ec_kc = _make_s3ec(*_KC_GCM)

    # Upload source objects
    plain_key = _unique_key(f"plain-get-src-{size_mb}mb-")
    plain_s3.put_object(Bucket=BUCKET, Key=plain_key, Body=payload)

    aes_key = _unique_key(f"s3ec-get-src-aes-{size_mb}mb-")
    s3ec_aes.put_object(Bucket=BUCKET, Key=aes_key, Body=payload)

    kc_key = _unique_key(f"s3ec-get-src-kc-{size_mb}mb-")
    s3ec_kc.put_object(Bucket=BUCKET, Key=kc_key, Body=payload)

    # Warm up all connections
    _warmup_connection(plain_s3)
    _warmup_connection(s3ec_aes)
    _warmup_connection(s3ec_kc)

    plain_d, aes_d, kc_d = [], [], []

    def run_plain():
        t0 = time.perf_counter()
        resp = plain_s3.get_object(Bucket=BUCKET, Key=plain_key)
        resp["Body"].read()
        return time.perf_counter() - t0

    def run_aes():
        t0 = time.perf_counter()
        resp = s3ec_aes.get_object(Bucket=BUCKET, Key=aes_key)
        resp["Body"].read()
        return time.perf_counter() - t0

    def run_kc():
        t0 = time.perf_counter()
        resp = s3ec_kc.get_object(Bucket=BUCKET, Key=kc_key)
        resp["Body"].read()
        return time.perf_counter() - t0

    variants = [(run_plain, plain_d), (run_aes, aes_d), (run_kc, kc_d)]

    for _ in range(NUM_ROUNDS):
        random.shuffle(variants)
        for fn, collector in variants:
            collector.append(fn())

    _record(f"plain_s3_get_{size_mb}mb", size_mb, plain_d)
    _record(f"s3ec_get_aes_gcm_{size_mb}mb", size_mb, aes_d)
    _record(f"s3ec_get_kc_gcm_{size_mb}mb", size_mb, kc_d)


# ---------------------------------------------------------------------------
# Interleaved roundtrip benchmark
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size_mb", OBJECT_SIZES_MB)
def test_roundtrip_interleaved(plain_s3, kms_client, size_mb):
    """Interleaved roundtrip: S3EC AES_GCM, S3EC KC_GCM, local crypto + plain S3."""
    payload = _get_payload(size_mb)

    s3ec_aes = _make_s3ec(*_AES_GCM)
    s3ec_kc = _make_s3ec(*_KC_GCM)

    # Warm up all connections
    _warmup_connection(plain_s3)
    _warmup_connection(s3ec_aes)
    _warmup_connection(s3ec_kc)
    kms_client.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")

    aes_d, kc_d, local_d = [], [], []

    def run_aes():
        key = _unique_key(f"s3ec-rt-aes-{size_mb}mb-")
        t0 = time.perf_counter()
        s3ec_aes.put_object(Bucket=BUCKET, Key=key, Body=payload)
        resp = s3ec_aes.get_object(Bucket=BUCKET, Key=key)
        resp["Body"].read()
        return time.perf_counter() - t0

    def run_kc():
        key = _unique_key(f"s3ec-rt-kc-{size_mb}mb-")
        t0 = time.perf_counter()
        s3ec_kc.put_object(Bucket=BUCKET, Key=key, Body=payload)
        resp = s3ec_kc.get_object(Bucket=BUCKET, Key=key)
        resp["Body"].read()
        return time.perf_counter() - t0

    def run_local():
        key = _unique_key(f"local-rt-{size_mb}mb-")
        t0 = time.perf_counter()
        dk_resp = kms_client.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")
        aesgcm = AESGCM(dk_resp["Plaintext"])
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        plain_s3.put_object(Bucket=BUCKET, Key=key, Body=nonce + ciphertext)
        resp = plain_s3.get_object(Bucket=BUCKET, Key=key)
        blob = resp["Body"].read()
        aesgcm.decrypt(blob[:12], blob[12:], None)
        return time.perf_counter() - t0

    variants = [(run_aes, aes_d), (run_kc, kc_d), (run_local, local_d)]

    for _ in range(NUM_ROUNDS):
        random.shuffle(variants)
        for fn, collector in variants:
            collector.append(fn())

    _record(f"s3ec_roundtrip_aes_gcm_{size_mb}mb", size_mb, aes_d)
    _record(f"s3ec_roundtrip_kc_gcm_{size_mb}mb", size_mb, kc_d)
    _record(f"local_crypto_roundtrip_{size_mb}mb", size_mb, local_d)


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
