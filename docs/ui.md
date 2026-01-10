# Web UI

## Overview

The proxy is **CLI-first** — it runs fully standalone without any web interface, and all functionality is available through command-line tools. See [Usage](usage.md) for CLI commands.

The web UI is an **optional add-on** for users who prefer a graphical interface for monitoring and approvals. However, it introduces additional attack surface (an HTTP server on port 8765). For security-sensitive environments, disable it entirely.

---

## Disabling the UI

```bash
mcp-acp-extended start --no-ui
```

Or in Claude Desktop config:

```json
{
  "mcpServers": {
    "mcp-acp-extended": {
      "command": "/path/to/mcp-acp-extended",
      "args": ["start", "--no-ui"]
    }
  }
}
```

When disabled:
- No HTTP server runs (port 8765 not opened)
- HITL approvals use native system dialogs (osascript on macOS)
- All functionality remains available via CLI

---

## Accessing the UI

When enabled (the default), the UI starts automatically with the proxy:

```
http://localhost:8765
```

No manual login required — authentication is handled automatically.

---

## Security Model

### Localhost-Only Binding

The API server binds exclusively to `127.0.0.1`. Remote connections are not possible. Host header validation prevents DNS rebinding attacks.

### Authentication

- **Production**: HttpOnly cookie (`api_token`) with `SameSite=Strict`, automatically set on page load
- **Token generation**: 32 bytes of cryptographic randomness (64 hex characters)
- **Token validation**: Constant-time comparison to prevent timing attacks

### CSRF Protection

Multiple layers:
- **SameSite=Strict cookies**: Prevents cross-site cookie submission
- **Origin header validation**: Required for all mutations (POST, PUT, DELETE)
- **Host header validation**: Blocks DNS rebinding attacks

### Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; ...
Cache-Control: no-store
Referrer-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Request Limits

Maximum request size: 1MB

### CLI Access via Unix Domain Socket

CLI commands use a Unix Domain Socket for local communication. Authentication relies on OS file permissions (socket is owner-only, mode 0600), bypassing HTTP authentication while maintaining security.

---

## Features

### Real-time Updates

- SSE (Server-Sent Events) for live approval notifications
- Audio chime when new HITL request arrives
- Error sound for critical events (backend disconnect, auth failures)

### Background Tab Alerts

When the UI is in a background tab:
- Page title updates with pending count (e.g., "🔴 (2) MCP ACP")
- Audio notifications still play

### Fallback Behavior

If the UI is not open when a HITL approval is needed, the proxy falls back to native system dialogs (osascript on macOS). These steal focus and play a system sound.

### Connection Status

A banner displays when the backend disconnects, showing reconnection attempts.

---

## See Also

- [Usage](usage.md) — CLI commands
- [Configuration](configuration.md) — Config file format
- [Logging](logging.md) — Audit logs
