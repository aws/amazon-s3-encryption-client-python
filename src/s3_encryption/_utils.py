# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Internal utility helpers for the S3 Encryption Client."""

import importlib.metadata

_PACKAGE_VERSION = importlib.metadata.version("amazon-s3-encryption-client-python")
_USER_AGENT_SUFFIX = f"S3ECPy/{_PACKAGE_VERSION}"


def safe_get_dict(source: dict, key: str) -> dict:
    """Get a dict value from *source*, defaulting to {} if missing or None.

    This avoids the common pitfall where ``d.get(key, {})`` returns None
    when the key exists but its value is explicitly None.
    """
    return source.get(key, {}) or {}


def append_user_agent(client, suffix: str):
    """Append a suffix to the User-Agent header of a boto3 client."""
    existing = client.meta.config.user_agent_extra or ""
    sep = " " if existing else ""
    client.meta.config.user_agent_extra = f"{existing}{sep}{suffix}"
