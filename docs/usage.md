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
  --log-dir PATH          Log directory (recommended: ~/.mcp-acp-extended)
  --log-level [debug|info] Logging level (default: info). debug enables wire logs.
  --server-name TEXT      Backend server name
  --connection-type [stdio|http|both]  Transport type (stdio=local, http=remote, both=auto-detect)
  --command TEXT          Backend command for STDIO (e.g., npx)
  --args TEXT             Backend arguments for STDIO (comma-separated)
  --url TEXT              Backend URL for HTTP (e.g., http://localhost:3000/mcp)
  --timeout INT           Connection timeout for HTTP (default: 30s)
  --force                 Overwrite existing config without prompting
```

**Config location** (OS-appropriate):
- macOS: `~/Library/Application Support/mcp-acp-extended/`
- Linux: `~/.config/mcp-acp-extended/`
- Windows: `C:\Users\<user>\AppData\Roaming\mcp-acp-extended\`

**Behavior**:
- **Interactive mode** (default): Prompts for required values
- **Non-interactive mode**: Requires all options via flags, fails if missing
- **Already initialized** (without --force): Prompts to confirm overwrite
- **With --force**: Overwrites existing config without prompting
- Creates log directory with secure permissions (chmod 700)

---

### `mcp-acp-extended start` - Start the proxy server

```bash
mcp-acp-extended start
```

No options - all settings come from config file created by `init`.

**Behavior**:
- Runs in foreground (stop with Ctrl+C)
- If not initialized, prints error and suggests `mcp-acp-extended init`
- Loads config from OS-appropriate location
- Validates config on startup
- Prints startup banner with configuration summary
- Normally started by MCP client (e.g., Claude Desktop), not manually

---

### `mcp-acp-extended config` - Configuration management

#### `mcp-acp-extended config show`

Display current configuration (backend settings, logging, transport, policy summary).

#### `mcp-acp-extended config path`

Show config and policy file locations.

#### `mcp-acp-extended config edit`

Edit the **config file** (not policy) in your editor.

**Behavior**:
- Opens config in `$EDITOR` (falls back to `$VISUAL`, then `vi`)
- Validates with Pydantic after saving
- Re-edit loop on validation failure (fix or abort)
- Creates `.json.bak` backup before save, removes on success
- Logs `config_updated` event to config history

**Note**: Policy files must be edited manually - see [Policies](policies.md).

---

### Help & Version

```bash
mcp-acp-extended -v, --version
mcp-acp-extended -h, --help
```

---

## Claude Desktop Integration

### Step 1: Locate and open config file

```bash
# macOS
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### Step 2: Update configuration

**If using filesystem server directly (before proxy):**

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/allowed/dir"
      ]
    }
  }
}
```

**Change to use the proxy (after proxy setup):**

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

## MCP Inspector

For testing with [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
# Initialize proxy first
mcp-acp-extended init

# Run inspector with the proxy
npx @modelcontextprotocol/inspector mcp-acp-extended start
```

---

## Example Workflows

### First-time setup

```bash
# 1. Initialize (interactive)
mcp-acp-extended init

# 2. View config location
mcp-acp-extended config path

# 3. Test proxy manually
mcp-acp-extended start
```

### Non-interactive setup (for scripting)

```bash
# STDIO transport (local command)
mcp-acp-extended init --non-interactive \
  --log-dir ~/.mcp-acp-extended \
  --server-name filesystem \
  --connection-type stdio \
  --command npx \
  --args "-y,@modelcontextprotocol/server-filesystem,/tmp"

# HTTP transport (remote server)
mcp-acp-extended init --non-interactive \
  --log-dir ~/.mcp-acp-extended \
  --server-name filesystem \
  --connection-type http \
  --url http://localhost:3000/mcp

# Both transports (auto-detect: prefers HTTP, falls back to STDIO)
mcp-acp-extended init --non-interactive \
  --log-dir ~/.mcp-acp-extended \
  --server-name filesystem \
  --connection-type both \
  --command npx \
  --args "-y,@modelcontextprotocol/server-filesystem,/tmp" \
  --url http://localhost:3000/mcp
```

### Debugging

```bash
# View logs (path depends on --log-dir from init)
tail -f ~/.mcp-acp-extended/mcp_acp_extended_logs/debug/client_wire.jsonl | jq '.'

# View audit operations
cat ~/.mcp-acp-extended/mcp_acp_extended_logs/audit/operations.jsonl | jq '.'

# View policy decisions
cat ~/.mcp-acp-extended/mcp_acp_extended_logs/audit/decisions.jsonl | jq '.'
```

### Edit policies

Policies are edited manually in the policy file:

```bash
# Find policy file location
mcp-acp-extended config path

# Edit policy file
$EDITOR ~/Library/Application\ Support/mcp-acp-extended/policy.json

# Restart proxy to apply changes
```

---

## See Also

- [Configuration](configuration.md) for config file format
- [Policies](policies.md) for policy rules and syntax
- [Logging](logging.md) for log file details
