# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Sphinx configuration for Amazon S3 Encryption Client for Python."""

project = "Amazon S3 Encryption Client for Python"
copyright = "Amazon.com, Inc. or its affiliates"
author = "AWS Crypto Tools"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
]

# Napoleon settings for Google-style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = False

# Autodoc settings
autodoc_member_order = "bysource"
autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
}

# Intersphinx mappings
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "boto3": ("https://boto3.amazonaws.com/v1/documentation/api/latest/", None),
}

# Theme
html_theme = "sphinx_rtd_theme"

# Exclude patterns
exclude_patterns = ["_build"]
