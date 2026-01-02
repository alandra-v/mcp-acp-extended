# Usage

## How It Works

```
MCP Client (Claude Desktop / MCP Inspector)
    │
    │ starts
    ▼
mcp-acp-extended proxy
    │
    │ spawns (STDIO) or connects to (HTTP)
    ▼
MCP Backend Server (filesystem server)
```

The MCP client starts the proxy, and the proxy spawns/connects to the backend server. You don't manually start the proxy when using a client - it starts automatically.

---

## CLI Commands

**Philosophy**: Explicit init required (security best practice), foreground execution only.

---

### `mcp-acp-extended init` - Initialize proxy configuration

```bash
mcp-acp-extended init [OPTIONS]

Options:
  --non-interactive       Skip prompts, require all options via flags
  --force                 Overwrite existing config without prompting

  Logging:
  --log-dir PATH          Log directory (recommended: ~/.mcp-acp-extended)
  --log-level [debug|info] Logging level (default: info). debug enables wire logs.

  Backend:
  --server-name TEXT      Backend server name
  --connection-type [stdio|http|both]  Transport type
  --command TEXT          Backend command for STDIO (e.g., npx)
  --args TEXT             Backend arguments for STDIO (comma-separated)
  --url TEXT              Backend URL for HTTP (e.g., http://localhost:3000/mcp)
  --timeout INT           Connection timeout for HTTP (default: 30, range: 1-300)

  Authentication (required):
  --oidc-issuer URL       OIDC issuer (e.g., https://tenant.auth0.com)
  --oidc-client-id TEXT   OAuth client ID
  --oidc-audience TEXT    API audience for token validation

  mTLS (optional, all three required together):
  --mtls-cert PATH        Client certificate (PEM)
  --mtls-key PATH         Client private key (PEM)
  --mtls-ca PATH          CA bundle (PEM)
```

**Config location** (OS-appropriate):
- macOS: `~/Library/Application Support/mcp-acp-extended/`
- Linux: `~/.config/mcp-acp-extended/`
- Windows: `C:\Users\<user>\AppData\Roaming\mcp-acp-extended\`

Interactive mode prompts for values; non-interactive requires all flags. Use `--force` to overwrite existing config.

---

### `mcp-acp-extended start` - Start the proxy server

```bash
mcp-acp-extended start
```

No options - all settings come from config file. Runs in foreground (Ctrl+C to stop). Normally started by MCP client, not manually.

---

### `mcp-acp-extended config` - Configuration management

#### `mcp-acp-extended config show`

Display current configuration (backend settings, logging, transport, policy summary).

#### `mcp-acp-extended config path`

Show config and policy file locations.

#### `mcp-acp-extended config edit`

Edit config file in `$EDITOR` (falls back to `$VISUAL`, then `vi`). Validates after saving. Policy files must be edited manually - see [Policies](policies.md).

#### `mcp-acp-extended config validate`

Validate configuration file syntax and schema.

```bash
mcp-acp-extended config validate [--path FILE]
```

Returns exit code 0 if valid, 1 if invalid.

---

### `mcp-acp-extended auth` - Authentication

#### `mcp-acp-extended auth login`

Authenticate via OAuth 2.0 Device Flow (browser-based, like `gh auth login`).

```bash
mcp-acp-extended auth login [--no-browser]
```

Use `--no-browser` to display code only. Opens browser, displays verification code, polls for completion (5 min timeout), stores tokens in OS keychain.

#### `mcp-acp-extended auth status`

Check authentication state, token validity, user info, and mTLS certificate status.

```bash
mcp-acp-extended auth status
```

#### `mcp-acp-extended auth logout`

Clear stored credentials from OS keychain.

```bash
mcp-acp-extended auth logout
```

**Options:**
- `--federated`: Also log out of the identity provider (Auth0) in your browser. Useful when switching between different users.

```bash
mcp-acp-extended auth logout --federated
```

Running proxies need restart after logout.

---

### `mcp-acp-extended policy` - Policy Management

#### `mcp-acp-extended policy path`

Show policy file location.

```bash
mcp-acp-extended policy path
```

#### `mcp-acp-extended policy validate`

Validate policy file syntax and schema.

```bash
mcp-acp-extended policy validate [--path FILE]
```

Returns exit code 0 if valid, 1 if invalid.

#### `mcp-acp-extended policy reload`

Reload policy in running proxy without restart.

```bash
mcp-acp-extended policy reload
```

Validates and applies the current `policy.json`. Requires proxy to be running. Clears cached HITL approvals on reload.

Returns exit code 0 if successful, 1 if failed (validation error, proxy not running).

---

### Help & Version

```bash
mcp-acp-extended -v, --version
mcp-acp-extended -h, --help
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (config/policy invalid, missing files, validation failure) |
| 10 | Audit log failure (log directory not writable) |
| 12 | Identity verification failure (JWKS endpoint unreachable) |
| 13 | Authentication error (not authenticated, token expired) |
| 14 | Device health check failed (FileVault/SIP not enabled on macOS) |

---

## Claude Desktop Integration

### Step 1: Locate and open config file

```bash
# macOS
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### Step 2: Update configuration

**Instead of using the planned backend server directly:**
**Only configure the proxy:**

```json
{
  "mcpServers": {
    "mcp-acp-extended": {
      "command": "/full/path/to/mcp-acp-extended",
      "args": ["start"]
    }
  }
}
```
**And configure the backend server in the proxy config.**

**Finding the full path:**

```bash
# If installed in a venv
/path/to/your/venv/bin/mcp-acp-extended

# Find it with 'which' (if in PATH)
which mcp-acp-extended
```

The proxy must be initialized first (`mcp-acp-extended init`). The backend server is configured in the proxy config, not here.

### Step 3: Save and restart Claude Desktop

```bash
# Save in nano: Ctrl+X, then Y, then Enter

# Restart Claude Desktop
killall Claude
# Then relaunch Claude Desktop
```

---

## ChatGPT (Not Supported)

ChatGPT requires MCP servers to communicate via HTTPS with authentication. Currently, the proxy only supports STDIO for client communication, so ChatGPT is not supported.

Future versions may add HTTPS client transport.

---

## Example Workflows

### First-time setup

```bash
# 1. Initialize configuration (interactive wizard)
mcp-acp-extended init

# 2. Authenticate (required - Zero Trust)
mcp-acp-extended auth login

# 3. Test proxy manually
mcp-acp-extended start
```

### Non-interactive setup (for scripting)

```bash
# HTTP transport (remote server)
mcp-acp-extended init --non-interactive \
  --log-dir ~/.mcp-acp-extended \
  --server-name filesystem \
  --connection-type http \
  --url http://localhost:3000/mcp \
  --oidc-issuer https://your-tenant.auth0.com \
  --oidc-client-id YOUR_CLIENT_ID \
  --oidc-audience https://your-api.example.com
```

---

## See Also

- [Configuration](configuration.md) for config file format
- [Policies](policies.md) for policy rules and syntax
- [Logging](logging.md) for log file details
