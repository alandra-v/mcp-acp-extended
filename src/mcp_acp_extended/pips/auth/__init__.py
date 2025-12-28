"""Authentication PIP - OIDC token validation and device health.

This module provides Zero Trust authentication:
- Token validation via Auth0/OIDC
- Token storage (Keychain)
- Device health checks (disk encryption, firewall)
- Session management

Note: Auth audit logging is in telemetry/audit/auth_logger.py
"""
