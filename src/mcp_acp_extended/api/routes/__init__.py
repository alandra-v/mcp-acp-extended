"""API route modules.

Route organization:
- approvals: Cached HITL approvals (previously approved decisions)
- pending: Pending HITL approvals (waiting for user decision)
- proxies: Proxy information
- sessions: Auth sessions (user authentication bindings)
- control: Proxy control (status, policy reload)
- policy: Policy management (CRUD)
- auth: Authentication management (login, logout, status)
- config: Configuration management (read, update)
- logs: Log viewer (decisions, operations, auth, system)
"""

from . import approvals, auth, config, control, logs, pending, policy, proxies, sessions

__all__ = [
    "approvals",
    "auth",
    "config",
    "control",
    "logs",
    "pending",
    "policy",
    "proxies",
    "sessions",
]
