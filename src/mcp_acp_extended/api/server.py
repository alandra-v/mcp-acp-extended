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
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import approvals


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
        allow_methods=["GET", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
        max_age=3600,  # Cache preflight for 1 hour
    )

    # Mount API routes
    # TODO: Add config, policy, logs, control, sessions routes
    app.include_router(approvals.router, prefix="/api/approvals", tags=["approvals"])

    # TODO: Serve static files (built React app)
    # static_dir = Path(__file__).parent.parent / "web" / "static"
    # if static_dir.exists():
    #     app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")
    #     # SPA fallback route

    return app
