# Installation

## Prerequisites

- **Python 3.11+**
- **pip** or **uv** package manager
- **Node.js 18+** (for MCP servers)

## Install from Source

```bash
git clone https://github.com/alandra-v/mcp-acp-extended.git
cd mcp-acp-extended

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .
```

<!--
## Install from PyPI

When released as a package:

```bash
# Using pip
pip install mcp-acp-extended

# Using uv (as a CLI tool)
uv tool install mcp-acp-extended
```

## Upgrade

```bash
# Using pip
pip install --upgrade mcp-acp-extended

# Using uv
uv tool upgrade mcp-acp-extended
```
-->

## Verify Installation

```bash
# Make sure venv is activated
source venv/bin/activate

mcp-acp-extended --version
# mcp-acp-extended 0.1.0
```

## MCP Backend Servers

The proxy requires an MCP server to connect to. Tested servers:

### @modelcontextprotocol/server-filesystem (Official)

STDIO transport only.

```bash
# Runs via npx (no install required)
npx -y @modelcontextprotocol/server-filesystem /path/to/allowed/dir
```

See: [github.com/modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)

### cyanheads/filesystem-mcp-server

Supports both STDIO and HTTP transports.

```bash
# Install globally
npm install -g @cyanheads/filesystem-mcp-server

# Or run via npx
npx -y @cyanheads/filesystem-mcp-server
```

See: [github.com/cyanheads/filesystem-mcp-server](https://github.com/cyanheads/filesystem-mcp-server)

## Next Steps

After installation, initialize the proxy configuration:

```bash
# Initialize configuration (interactive)
mcp-acp-extended init

# Start the proxy
mcp-acp-extended start
```

See [Usage](usage.md) for detailed setup instructions.
