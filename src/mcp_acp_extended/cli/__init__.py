"""Command-line interface for mcp-acp-extended.

Provides commands for initializing configuration, starting the proxy server,
and managing configuration.
"""

from .main import cli, main

__all__ = ["cli", "main"]
