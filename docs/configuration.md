# Configuration

> **Zero Trust by Default**: Authentication is mandatory. Policy `default_action` is always `deny`. The proxy fails fast on configuration errors rather than falling back to insecure defaults.

## How to Configure

Configuration is created via the `mcp-acp-extended init` command:

```bash
# Interactive setup (recommended)
mcp-acp-extended init

# Non-interactive setup
mcp-acp-extended init --non-interactive \
  --oidc-issuer https://your-tenant.auth0.com \
  --oidc-client-id your-client-id \
  --oidc-audience your-api-audience \
  --log-dir ~/.mcp-acp-extended \
  --server-name filesystem \
  --connection-type stdio \
  --command npx \
  --args "-y,@modelcontextprotocol/server-filesystem,/tmp"
```

**Init options**:
- `--oidc-issuer`, `--oidc-client-id`, `--oidc-audience` - Authentication (required)
- `--mtls-cert`, `--mtls-key`, `--mtls-ca` - mTLS for HTTPS backends (optional)
- `--log-dir`, `--log-level` - Logging configuration
- `--server-name`, `--connection-type`, `--command`, `--args`, `--url`, `--timeout` - Backend configuration

To edit existing configuration:

```bash
# Edit via CLI (validates after save)
mcp-acp-extended config edit

# Or edit manually

# View current config
mcp-acp-extended config show

# Show file locations
mcp-acp-extended config path
```

**No hot reload**: Changes require proxy restart.

**Config history**: All configuration changes are logged to `config_history.jsonl` for audit:

| Event | Description |
|-------|-------------|
| `config_created` | Initial creation via `mcp-acp-extended init` |
| `config_loaded` | Loaded at proxy startup |
| `config_updated` | Updated via `mcp-acp-extended config edit` |
| `manual_change_detected` | File modified outside of CLI (detected on next load) |
| `config_validation_failed` | Invalid JSON or schema validation error |

---

## Where Configuration is Stored

Configuration is stored in an OS-specific application directory:

| OS | Location |
|----|----------|
| macOS | `~/Library/Application Support/mcp-acp-extended/` |
| Linux | `~/.config/mcp-acp-extended/` |
| Windows | `C:\Users\<user>\AppData\Roaming\mcp-acp-extended\` |

**Files**:
- `mcp_acp_extended_config.json` - operational settings (auth, logging, backend, proxy)
- `policy.json` - security policies (rules, HITL settings)

**Log directory**: User-specified via `--log-dir` during init (stored separately, recommended: `~/.mcp-acp-extended`)

**File permissions**: Config directory is `0o700` (owner only), config files are `0o600`. Writes are atomic to prevent corruption. See [Security](security.md) for details.

**Bootstrap log**: If config is invalid and `log_dir` is unavailable, errors are written to `bootstrap.jsonl` in the config directory.

---

## What is Configured

### mcp_acp_extended_config.json

```json
{
  "auth": {
    "oidc": {
      "issuer": "https://your-tenant.auth0.com",
      "client_id": "your-client-id",
      "audience": "your-api-audience"
    },
    "mtls": {
      "client_cert_path": "/path/to/client.crt",
      "client_key_path": "/path/to/client.key",
      "ca_bundle_path": "/path/to/ca-bundle.crt"
    }
  },
  "logging": {
    "log_dir": "~/.mcp-acp-extended",
    "log_level": "INFO",
    "include_payloads": true
  },
  "backend": {
    "server_name": "filesystem",
    "transport": null,
    "stdio": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    },
    "http": {
      "url": "http://localhost:3000/mcp",
      "timeout": 30
    }
  },
  "proxy": {
    "name": "mcp-acp-extended"
  }
}
```

### Authentication Settings

| Field | Description |
|-------|-------------|
| `auth.oidc.issuer` | OIDC issuer URL (e.g., `https://tenant.auth0.com`) |
| `auth.oidc.client_id` | Auth0 application client ID |
| `auth.oidc.audience` | API audience for token validation |
| `auth.oidc.scopes` | OAuth scopes (default: `["openid", "profile", "email", "offline_access"]`) |
| `auth.mtls.client_cert_path` | Client certificate path, PEM format (optional, for mTLS backends) |
| `auth.mtls.client_key_path` | Client private key path, PEM format |
| `auth.mtls.ca_bundle_path` | CA bundle for server verification, PEM format |

### Logging Settings

| Field | Description |
|-------|-------------|
| `log_dir` | Base directory for logs |
| `log_level` | `DEBUG` or `INFO`. DEBUG enables wire logs |
| `include_payloads` | Include full payloads in debug logs |

### Backend Settings

| Field | Description |
|-------|-------------|
| `server_name` | Display name for the backend server |
| `transport` | `"stdio"`, `"streamablehttp"`, or `null` (auto-detect) |
| `stdio.command` | Command to spawn backend (e.g., `npx`) |
| `stdio.args` | Arguments for the command |
| `http.url` | Backend Streamable HTTP server URL |
| `http.timeout` | Streamable HTTP connection timeout in seconds (default: 30, min: 1, max: 300) |

### Transport Selection

- `"transport": "stdio"` - Use STDIO only (requires `stdio` config)
- `"transport": "streamablehttp"` - Use Streamable HTTP only (requires `http` config)
- `"transport": null` - Auto-detect: prefers Streamable HTTP if reachable, falls back to STDIO

**Auto-detection logic at runtime**:
1. If transport is explicitly set (`"stdio"` or `"streamablehttp"`):
   - Use specified transport if available
   - **Fail** if specified transport not available (no silent fallback)
2. If transport is `null` (auto-detect):
   - Try Streamable HTTP with retry (3 attempts, ~6s total)
   - If still unreachable → fall back to STDIO

**Startup retry**: HTTP backends are retried with exponential backoff (2s → 4s) to allow starting the proxy before the backend is ready.

**Streamable HTTP preferred**: MCP spec positions it as the modern default.

### policy.json

Security policies are configured separately. See [Policies](policies.md) for full syntax.

```json
{
  "version": "1",
  "default_action": "deny",
  "rules": [
    { "id": "allow-reads", "effect": "allow", "conditions": { "operations": ["read"] } }
  ],
  "hitl": { "timeout_seconds": 30, "approval_ttl_seconds": 600 }
}
```

HITL timeouts: `timeout_seconds` (default: 30, min: 5, max: 300), `approval_ttl_seconds` (default: 600, min: 300, max: 900).

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EDITOR` | — | Editor for `config edit` (checked first) |
| `VISUAL` | — | Fallback editor for `config edit` |
| `MCP_ACP_CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | CORS origins for management API (comma-separated) |

---

## Configuration Validation

- **Syntax**: JSON parsing with clear error messages
- **Schema**: Pydantic validation of all fields and types
- **Permissions**: Config directory `0o700`, files `0o600` (Unix)
- **Atomic writes**: Prevents corruption during saves
- **Symlink protection**: Paths resolved via `realpath()` to prevent bypass attacks

---

## What is NOT Configured

### Environment Variables for Backend

Environment variables cannot be passed to backend processes.

**Why**:
- STDIO: Proxy spawns the process, could pass env vars
- Streamable HTTP: Proxy connects to already-running server, cannot pass env vars
- This asymmetry makes a unified feature misleading
- Env vars often contain secrets, creating audit trail issues

**Workaround**: Set env vars externally when starting Streamable HTTP servers.

### Runtime Overrides

No CLI flags to override config at runtime. All settings come from config files.

### Multiple Backend Servers

Only one backend server is supported. Multi-server support planned for the future.

### Client Transport

Client-to-proxy communication is STDIO only. HTTP client transport not supported (required for ChatGPT integration).

---

## See Also

- [Usage](usage.md) for CLI commands
- [Policies](policies.md) for policy configuration
- [Logging](logging.md) for log file details
- [Security](security.md) for file permissions, atomic writes, audit integrity
