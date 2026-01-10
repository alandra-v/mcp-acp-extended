# API Reference

The Management API provides HTTP endpoints for monitoring, configuration, and HITL approvals. It runs inside the proxy process and is accessible via:

- **Unix Domain Socket (UDS)**: For CLI communication (OS file permissions = authentication)
- **HTTP**: For browser/web UI (token-based authentication)

---

## Authentication

**UDS connections**: Authenticated by OS file permissions (same user only).

**HTTP connections**: Require a session token passed via:
- `Authorization: Bearer <token>` header, or
- `api_token` cookie (HttpOnly in production)

Tokens are issued during device flow authentication or injected into the UI on page load.

---

## Endpoints

### Proxies

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/proxies` | List all running proxies (includes stats) |
| `GET` | `/api/proxies/{proxy_id}` | Get proxy details (includes stats) |

### Sessions

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/auth-sessions` | List active user sessions |

### Approvals (Cached)

Previously approved HITL decisions stored in memory.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/approvals/cached` | List cached HITL approvals |
| `DELETE` | `/api/approvals/cached` | Clear all cached approvals |
| `DELETE` | `/api/approvals/cached/entry?subject_id=X&tool_name=Y&path=Z` | Delete specific cached approval |

### Approvals (Pending)

HITL requests currently waiting for user decision.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/approvals/pending` | SSE stream for pending approvals |
| `GET` | `/api/approvals/pending/list` | List pending approvals (non-SSE) |
| `POST` | `/api/approvals/pending/{id}/approve` | Approve and cache |
| `POST` | `/api/approvals/pending/{id}/allow-once` | Approve without caching |
| `POST` | `/api/approvals/pending/{id}/deny` | Deny pending request |

### Control

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/control/status` | Get proxy status (uptime, policy version) |
| `POST` | `/api/control/reload-policy` | Hot-reload policy from disk |

### Policy

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/policy` | Get current policy with metadata |
| `GET` | `/api/policy/rules` | List all policy rules |
| `POST` | `/api/policy/rules` | Add a new rule |
| `PUT` | `/api/policy/rules/{id}` | Update a rule |
| `DELETE` | `/api/policy/rules/{id}` | Delete a rule |

### Configuration

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/config` | Get current configuration |
| `PUT` | `/api/config` | Update configuration |
| `GET` | `/api/config/compare` | Compare running vs saved config |

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/auth/status` | Get authentication status and user info |
| `POST` | `/api/auth/login` | Start OAuth device flow |
| `GET` | `/api/auth/login/poll?code=X` | Poll for device flow completion |
| `POST` | `/api/auth/logout` | Clear local credentials (keychain) |
| `POST` | `/api/auth/logout-federated` | Get federated logout URL + clear local |
| `POST` | `/api/auth/notify-login` | Notify proxy of CLI login |
| `POST` | `/api/auth/notify-logout` | Notify proxy of CLI logout |
| `GET` | `/api/auth/dev-token` | Get API token (dev mode only) |

### Logs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/logs` | Get log metadata (available files/folders) |
| `GET` | `/api/logs/{folder}/{file}` | Read log file contents |

Query parameters for log reading:
- `offset`: Skip first N lines
- `limit`: Maximum lines to return
- `reverse`: Read from end of file

### Incidents

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/incidents` | Get incident summary (crashes, bootstrap errors) |

---

## SSE Events

The `/api/approvals/pending` endpoint provides Server-Sent Events for real-time updates.

### Event Types

**HITL Lifecycle:**
- `snapshot` - Initial pending approvals on connection
- `cached_snapshot` - Initial cached approvals on connection
- `pending_created` - New approval request
- `pending_resolved` - Approval decided (allow/deny)
- `pending_timeout` - Approval timed out
- `pending_not_found` - Approval already resolved/expired

**Backend Connection:**
- `backend_connected` - Backend available
- `backend_reconnected` - Backend recovered
- `backend_disconnected` - Backend connection lost
- `backend_timeout` - Backend request timeout
- `backend_refused` - Backend connection refused

**Authentication:**
- `auth_login` - User logged in
- `auth_logout` - User logged out
- `auth_session_expiring` - Session expiring soon
- `token_refresh_failed` - Token refresh failed
- `auth_failure` - Authentication error

**Policy:**
- `policy_reloaded` - Policy hot-reloaded
- `policy_reload_failed` - Policy reload error
- `config_change_detected` - Config file changed

**Rate Limiting:**
- `rate_limit_triggered` - Rate limit exceeded
- `rate_limit_approved` - Rate limit override approved
- `rate_limit_denied` - Rate limit override denied

**Cache:**
- `cache_cleared` - Approval cache cleared
- `cache_entry_deleted` - Single cache entry removed

**Live Updates:**
- `stats_updated` - Request statistics changed
- `new_log_entries` - New log entries available

**Critical Events:**
- `critical_shutdown` - Proxy shutting down
- `audit_init_failed` - Audit system failed
- `device_health_failed` - Device health check failed
- `session_hijacking` - Session binding violation
- `audit_tampering` - Audit log tampering detected

### Event Format

```json
{
  "type": "pending_created",
  "severity": "info",
  "timestamp": "2025-01-10T12:00:00.000Z",
  "proxy_id": "abc123:my-server",
  "approval": {
    "id": "def456",
    "tool_name": "read_file",
    "path": "/etc/passwd",
    "subject_id": "user@example.com",
    "timeout_seconds": 60
  }
}
```

---

## Error Responses

All endpoints return standard HTTP status codes:

| Code | Meaning |
|------|---------|
| `200` | Success |
| `201` | Created (for POST creating resources) |
| `204` | No content (for DELETE) |
| `400` | Bad request (invalid parameters) |
| `401` | Unauthorized (missing/invalid token) |
| `404` | Not found |
| `409` | Conflict (duplicate ID) |
| `500` | Internal server error |
| `502` | Bad gateway (upstream error, e.g., OAuth) |
| `503` | Service unavailable (provider not ready) |

Error response format:

```json
{
  "detail": "Error message describing what went wrong"
}
```

---

## See Also

- [Architecture](architecture.md) for system overview
- [Configuration](configuration.md) for config file format
- [Policies](policies.md) for policy rule syntax
