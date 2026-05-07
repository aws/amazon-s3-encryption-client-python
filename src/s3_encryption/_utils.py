# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Internal utility helpers for the S3 Encryption Client."""


def safe_get_dict(source: dict, key: str) -> dict:
    """Get a dict value from *source*, defaulting to {} if missing or None.

    This avoids the common pitfall where ``d.get(key, {})`` returns None
    when the key exists but its value is explicitly None.
    """
    return source.get(key, {}) or {}
