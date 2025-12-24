"""Resource parsing utilities for paths and URIs.

Provides safe parsing of file paths and URIs into ResourceInfo objects.
Used by context building for ABAC policy evaluation.

SECURITY: Path parsing does NOT resolve symlinks to prevent TOCTOU attacks.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from mcp_acp_extended.context.provenance import Provenance
from mcp_acp_extended.context.resource import ResourceInfo

__all__ = [
    "parse_path_resource",
    "parse_uri_resource",
]


def parse_path_resource(raw_path: str) -> ResourceInfo:
    """Parse file path into ResourceInfo.

    SECURITY: We do NOT resolve symlinks or call .resolve(). This prevents
    TOCTOU attacks where an attacker creates a symlink pointing to a sensitive
    file. Policy evaluation uses the path as provided by the client - if client
    requests "/tmp/link", policy matches against "/tmp/link", not the target.

    We only normalize the path (collapse . and ..) without following symlinks.

    Args:
        raw_path: Raw file path string.

    Returns:
        ResourceInfo with path details.
    """
    try:
        # Use os.path.normpath to collapse . and .. without resolving symlinks
        # This is safer than .resolve() which follows symlinks
        normalized = os.path.normpath(raw_path)
        norm_path = Path(normalized)

        return ResourceInfo(
            path=normalized,
            filename=norm_path.name,
            extension=norm_path.suffix if norm_path.suffix else None,
            parent_dir=str(norm_path.parent),
            provenance=Provenance.MCP_REQUEST,
        )
    except (ValueError, OSError):
        # Path normalization failed, return as-is
        return ResourceInfo(
            path=raw_path,
            provenance=Provenance.MCP_REQUEST,
        )


def parse_uri_resource(uri: str) -> ResourceInfo:
    """Parse URI into ResourceInfo.

    Args:
        uri: URI string.

    Returns:
        ResourceInfo with URI details.
    """
    try:
        parsed = urlparse(uri)
        result = ResourceInfo(
            uri=uri,
            scheme=parsed.scheme if parsed.scheme else None,
            provenance=Provenance.MCP_REQUEST,
        )

        # If it's a file:// URI, extract path info too
        if parsed.scheme == "file" and parsed.path:
            path = Path(parsed.path)
            return ResourceInfo(
                uri=uri,
                scheme=parsed.scheme,
                path=parsed.path,
                filename=path.name,
                extension=path.suffix if path.suffix else None,
                parent_dir=str(path.parent),
                provenance=Provenance.MCP_REQUEST,
            )

        return result
    except (ValueError, AttributeError):
        return ResourceInfo(uri=uri, provenance=Provenance.MCP_REQUEST)
