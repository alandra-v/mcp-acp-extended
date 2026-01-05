"""FastAPI server for the management API and static file serving.

Currently implements:
- Cached approvals API (/api/approvals/cached) - previously approved HITL decisions
- Pending approvals API (/api/approvals/pending) - HITL requests waiting for decision
- Proxies API (/api/proxies) - proxy information
- Auth sessions API (/api/auth-sessions) - user authentication bindings
- Control API (/api/control) - policy reload

Security:
- All /api/* endpoints require bearer token authentication
- Host header validation (DNS rebinding protection)
- Origin header validation (CSRF protection)
- Security response headers

Future additions:
- Config management (/api/config)
- Policy management (/api/policy)
- Log viewer (/api/logs)
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
    Also, security middleware is disabled in standalone mode (no token).
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import approvals, control, pending, proxies, sessions
from .security import SecurityMiddleware


def create_api_app(token: str | None = None) -> FastAPI:
    """Create the FastAPI application with all routes.

    Args:
        token: Bearer token for API authentication. If None, security
            middleware is disabled (for standalone dev/testing).

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="MCP-ACP Extended API",
        description="Management API for MCP-ACP Extended proxy",
        version="0.1.0",
    )

    # Security middleware (must be added before CORS)
    # Only enabled when token is provided (proxy mode)
    # Disabled for standalone dev/testing
    if token:
        app.add_middleware(SecurityMiddleware, token=token)

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
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
        max_age=3600,  # Cache preflight for 1 hour
    )

    # Mount API routes
    app.include_router(proxies.router, prefix="/api/proxies", tags=["proxies"])
    app.include_router(sessions.router, prefix="/api/auth-sessions", tags=["auth-sessions"])
    app.include_router(approvals.router, prefix="/api/approvals/cached", tags=["cached-approvals"])
    app.include_router(pending.router, prefix="/api/approvals/pending", tags=["pending-approvals"])
    app.include_router(control.router, prefix="/api/control", tags=["control"])
    # TODO: Add config, policy, logs routes

    # TODO: Serve static files (built React app)
    # static_dir = Path(__file__).parent.parent / "web" / "static"
    # if static_dir.exists():
    #     app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")
    #     # SPA fallback route

    return app
