"""API route modules.

Route organization:
- approvals: Cached HITL approvals (previously approved decisions)
- pending: Pending HITL approvals (waiting for user decision)
- proxies: Proxy information
- sessions: Auth sessions (user authentication bindings)
- control: Proxy control (status, policy reload)

Future additions:
- config: Configuration management
- policy: Policy management
- logs: Log viewer
"""

from . import approvals, control, pending, proxies, sessions

__all__ = ["approvals", "control", "pending", "proxies", "sessions"]
