"""Authentication Policy Information Point.

This module will contain:
- OIDCIdentityProvider: Extracts identity claims from tokens for policy decisions

Authentication primitives (token storage, JWT validation) are in security/auth/.
Device health checks are in security/device.py.
Auth audit logging is in telemetry/audit/auth_logger.py.
"""
