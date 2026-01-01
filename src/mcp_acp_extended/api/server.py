"""FastAPI server for the management API and static file serving.

Currently implements:
- Approval cache API (/api/approvals)

Future additions:
- Config management (/api/config)
- Policy management (/api/policy)
- Log viewer (/api/logs)
- Proxy control (/api/control)
- Session management (/api/sessions)
- Static file serving for React UI

Usage:
    The API server is embedded in the proxy process (see proxy.py) to share
    memory with the approval store. It starts automatically on port 8080
    when the proxy runs.

    For standalone development/testing (without shared memory):
        uv run uvicorn mcp_acp_extended.api.server:create_api_app \\
            --factory --host 127.0.0.1 --port 8080

    Note: Standalone mode won't have access to the approval cache since the
    ApprovalStore is only registered when running inside the proxy process.
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import approvals, control


def create_api_app() -> FastAPI:
    """Create the FastAPI application with all routes."""
    app = FastAPI(
        title="MCP-ACP Extended API",
        description="Management API for MCP-ACP Extended proxy",
        version="0.1.0",
    )

    # CORS configuration
    # In production, this API runs on localhost only (same-origin with proxy)
    # For development with separate frontend, allow localhost origins
    cors_origins = os.environ.get(
        "MCP_ACP_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in cors_origins],
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
        max_age=3600,  # Cache preflight for 1 hour
    )

    # Mount API routes
    app.include_router(approvals.router, prefix="/api/approvals", tags=["approvals"])
    app.include_router(control.router, prefix="/api/control", tags=["control"])
    # TODO: Add config, policy, logs, sessions routes

    # TODO: Serve static files (built React app)
    # static_dir = Path(__file__).parent.parent / "web" / "static"
    # if static_dir.exists():
    #     app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")
    #     # SPA fallback route

    return app
