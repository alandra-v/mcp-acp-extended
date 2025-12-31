"""API route modules.

Currently implements:
- approvals: Approval cache visibility for debugging

Future additions:
- config: Configuration management
- policy: Policy management
- logs: Log viewer
- control: Proxy control
- sessions: Session management
"""

from . import approvals

__all__ = ["approvals"]
