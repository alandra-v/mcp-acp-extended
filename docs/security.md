# Security

## Overview

This proxy implements a Zero Trust security model: all operations are denied by default, every request is evaluated independently, and all errors result in denial. The proxy enforces policy at the MCP protocol layer, providing access control, audit logging, and human oversight for AI tool operations.

For the full Zero Trust architecture and PEP/PDP design, see [Architecture](architecture.md).

---

## Protection Capabilities

### MCP and Agentic AI Threats

| Threat | How the Proxy Helps | Stage 1 Status |
|--------|---------------------|----------------|
| **Tool poisoning** (malicious tool descriptions, metadata, or responses inducing unsafe actions) | Policy gating blocks tool invocations before reaching backend; side effects mapping enables blocking dangerous tool categories by capability | Partially mitigated (no response validation or description sanitization) |
| **Confused-deputy attacks** (clients/servers tricked into misusing authority, insufficient consent scoping) | Per-request policy evaluation (no cached trust); HITL requires explicit user consent for sensitive operations; no automatic token forwarding | Partially mitigated (no scoped tokens or per-session credential binding) |
| **Cross-tool contamination** (benign tools chained into exfiltration pathways) | Policy rules can restrict by tool name, path pattern, and side effects; single-server architecture limits cross-server chaining | Minimally mitigated (no flow control or taint tracking) |
| **Credential theft and misuse** (token impersonation, privilege escalation) | Local identity only; no tokens stored or forwarded | Not addressed (no session validation or anti-replay; planned for Stage 2+) |
| **Expanded attack surface** (agent integrations multiply entry points) | Default-deny policy restricts callable tools; protected paths block access to proxy internals | Partially mitigated |
| **Accountability gaps** (unclear attribution for autonomous agent actions) | Immutable audit trail with subject ID, request ID, session ID on every operation and decision | Addressed |
| **Supply-chain risks** (dependencies on models, libraries, APIs) | Dependencies documented; update guidance provided | Awareness only (no SCA integration) |

---

## Limitations and Out of Scope

### What This Proxy Does NOT Protect Against

| Limitation | Explanation | Recommendation |
|-----------|-------------|----------------|
| **Prompt injection** | The proxy operates at the MCP protocol layer, not the prompt layer. It cannot see or filter prompts sent to the model. | Use prompt-level defenses in your LLM application |
| **Model behavior** | Cannot guarantee the model will behave benignly or follow instructions correctly. | Implement application-level guardrails |
| **Out-of-band channels** | Only the MCP channel is proxied. Data exfiltration via other means (network, clipboard if tool allowed) is not detected. | Restrict network access at OS/firewall level |
| **Backend server vulnerabilities** | The proxy enforces policy on requests, but cannot protect against vulnerabilities in the backend MCP server itself. | Keep backend servers updated; use trusted servers |
| **Rate limiting / DoS** | No built-in rate limiting yet. An attacker could flood with requests. | Implement rate limiting at infrastructure level |
| **Memory exhaustion** | No limits on response sizes yet. Large responses could exhaust memory. | Monitor resource usage; set OS-level limits |

### Dependencies Disclaimer

This proxy depends on third-party libraries including FastMCP, Pydantic, httpx, and others. These dependencies may contain security vulnerabilities. Dependencies are defined in `pyproject.toml`.

**Recommendations:**
- Regularly update dependencies: `uv sync --upgrade` or `pip install --upgrade`
- Monitor security advisories (GitHub Dependabot, Snyk, or `pip-audit`)
- Pin dependency versions in production (`uv.lock`) and test updates before deploying

---

## Startup Security

### Configuration Validation

Before accepting any requests, the proxy validates all configuration:

- **Pydantic schema validation**: Configuration (`mcp_acp_extended_config.json`) and policy (`policy.json`) files are validated against strict Pydantic models. This catches:
  - Invalid JSON syntax
  - Missing required fields
  - Invalid field types (e.g., string where number expected)
  - Invalid enum values (e.g., unknown transport type)
  - Policy rules with empty conditions (would match everything)
- **File permissions**: Config files use `0o600` (owner read/write only). Directories use `0o700` (owner only).
- **Atomic writes**: Config and policy files are written atomically (write to temp file, fsync, rename) to prevent corruption on crash or power loss.

### Audit Writability Verification

At startup, the proxy verifies it can write to audit log files before accepting any requests. If audit logs are not writable, the proxy refuses to start.

### Bootstrap Log

When configuration validation fails, normal logging is unavailable (the `log_dir` setting cannot be read from invalid config). In this case, errors are logged to a bootstrap log in a predictable location:

- **Location**: `<config_dir>/bootstrap.jsonl`
- **Purpose**: Ensures validation failures are always recorded even when config is corrupt
- **Contents**: Timestamp, error type, error message

### Protected Paths Initialization

At startup, the proxy resolves protected directories using `os.path.realpath()`:

- **Config directory**: Contains policy, config, and emergency audit files
- **Log directory**: Contains all audit and system logs

This resolution happens once at startup, preventing symlink-based bypass attempts. These paths are then checked before policy evaluation for every request.

### Startup Failure Handling

If startup fails due to configuration or validation errors:

1. Error logged to bootstrap log (config_dir)
2. Error logged to config_history.jsonl or policy_history.jsonl as `*_validation_failed` event
3. Proxy exits with non-zero status
4. Human-readable error message printed to stderr

---

## Runtime Security

### Access Control

**Policy Check Priority**: Every request is evaluated in this order (first match wins):

1. **Protected paths** - config/log directories blocked unconditionally (cannot be overridden)
2. **Discovery bypass** - `initialize`, `tools/list`, etc. allowed for protocol function
3. **Policy rules** - user-defined rules evaluated with combining algorithm (HITL > DENY > ALLOW)
4. **Default action** - DENY if no rules match

**Policy Enforcement**: Every non-discovery request is evaluated against policy rules. See [Policies](policies.md) for rule syntax, combining algorithm, and HITL configuration.

**Protected Paths**: The config and log directories cannot be accessed by MCP tools, regardless of policy rules. This prevents backend servers from:

- Modifying policy files to grant themselves more access
- Tampering with audit logs to hide malicious activity
- Reading configuration to discover security settings
- Deleting emergency audit files

This check happens before policy evaluation:

1. Request path is normalized
2. Checked against protected directories (resolved at startup with `realpath()`)
3. If match: immediately denied
4. If no match: proceeds to policy evaluation

This is a built-in protection that cannot be overridden by user policy.

**Discovery Method Bypass**: Certain MCP methods bypass policy evaluation entirely because they are required for the protocol to function and do not modify state:

- `initialize`, `ping` - connection setup
- `tools/list`, `resources/list`, `prompts/list`, `resources/templates/list` - capability discovery
- `notifications/*` - async notifications

These are logged with `final_rule: "discovery_bypass"` for audit trail.

**Important exclusion**: `prompts/get` is NOT in the bypass list because it returns actual prompt content, which may contain secrets or sensitive instructions. Unlike `prompts/list` (which only returns metadata), `prompts/get` fetches the full prompt template and must be subject to policy evaluation.

**Provenance Tracking**: Every security-relevant fact carries its source, enabling future trust-based policies:

```
TOKEN/MTLS     -> Cryptographically verified (Stage 2+)
DIRECTORY      -> From identity directory lookup
PROXY_CONFIG   -> From local config file (operator-controlled)
MCP_METHOD     -> From MCP method name (protocol-defined)
MCP_REQUEST    -> From request arguments (client-provided)
DERIVED        -> Computed from other facts
CLIENT_HINT    -> Client self-reported (untrusted)
```

Currently tracked but not used for policy decisions. Infrastructure for future trust-level requirements (e.g., require TOKEN provenance for sensitive operations).

### Audit and Logging Security

**Immutable Audit Trail**: Audit logging cannot be disabled. Every operation and policy decision is recorded to:

- `audit/operations.jsonl` - what was requested and outcome
- `audit/decisions.jsonl` - policy evaluation details and HITL outcomes

**Fail-Closed Integrity Monitoring**: Two layers of protection ensure audit log integrity:

**1. Per-Write Checks (FailClosedAuditHandler)**: Verifies file integrity before every write:
- At startup: records file's device ID and inode
- Before each write: stats file and compares device/inode
- On mismatch: triggers emergency shutdown

**2. Background Monitoring (AuditHealthMonitor)**: Periodic checks during idle periods:
- Runs every 30 seconds as a background task
- Verifies both `operations.jsonl` and `decisions.jsonl`
- Detects tampering even when no requests are being processed
- Defense in depth: catches issues the per-write handler might miss during idle periods

Together, these detect:
- File deletion (even while file descriptor is open - "ghost inode" on Unix)
- File replacement (different inode)
- File moved and recreated
- Permission changes

**Fallback Chain**: If primary audit logging fails, the proxy attempts fallback logging before shutdown:

1. **Primary**: `audit/operations.jsonl` or `audit/decisions.jsonl`
2. **Fallback 1**: `system/system.jsonl`
3. **Fallback 2**: `<config_dir>/emergency_audit.jsonl` (survives log_dir deletion)

After any fallback, the proxy must shut down because the primary audit trail is compromised.

**Log Security Measures**:

| Measure | Purpose |
|---------|---------|
| Pydantic strict models | Log events validated with `extra="forbid"`; rejects unknown fields and malformed entries |
| Log injection prevention | Newlines and carriage returns escaped in logged strings; prevents fake JSONL entries via malicious filenames |
| Append-only mode | Logs opened with `mode="a"`; new entries appended, existing content preserved |
| Directory permissions (0o700) | Prevent unauthorized access to log directories |
| File permissions (umask) | Log files created with system umask (not explicit 0o600) |
| Never log content | Only hashes and sizes logged; prevents secrets in logs |
| Content redaction | Sensitive argument values replaced with `[REDACTED - N bytes]` |
| fsync on writes | Ensures data reaches disk |
| Integrity verification | Detects file tampering or deletion via inode checks |
| Fallback chain | Emergency logging survives primary log deletion |
| Protected by policy | MCP tools cannot access log directory regardless of policy rules |
| Correlation IDs | request_id and session_id link related events |

**Not implemented** (potential future hardening):
- Sequence numbers for entry ordering verification
- Hash chain linking entries for tamper detection
- CLI verification command to check log integrity
- Documentation for OS-level protections (e.g., `chattr +a` on Linux)

**Path Normalization Strategies**: Three different strategies are used for different security purposes:

| Context | Method | Why |
|---------|--------|-----|
| Policy evaluation | `os.path.normpath()` | Matches client intent; prevents TOCTOU symlink attacks |
| Protected paths | `os.path.realpath()` | Resolves symlinks once at startup; prevents bypass |
| Audit logging | `Path.resolve()` | Shows canonical path for forensic accuracy |

**Why normpath for policy (TOCTOU prevention)**:

- Attacker creates `/tmp/innocent -> /etc/shadow`
- Policy allows `/tmp/**`, denies `/etc/**`
- With `.resolve()`: path becomes `/etc/shadow` at check time, but symlink could change before backend uses it
- With `.normpath()`: policy matches `/tmp/innocent` (what client requested)

Principle: Policy paths are identifiers, not filesystem references. Policy matches what the client requested, not what it might resolve to.

**Config and Policy History Logs**: Changes to configuration and policy are tracked in versioned history logs:

- `system/config_history.jsonl` - config lifecycle events
- `system/policy_history.jsonl` - policy lifecycle events

Events tracked:
- `*_created` - initial creation via CLI
- `*_loaded` - loaded at proxy startup
- `*_updated` - updated via CLI
- `manual_change_detected` - file modified outside CLI (detected via checksum)
- `*_validation_failed` - invalid JSON or schema

Each event includes version number, checksum, and snapshot for forensic analysis.

### HITL Security Design

**Synchronous Blocking**: HITL approval uses synchronous `subprocess.run()`, not async. This is a deliberate security choice - blocking the request pipeline ensures the operation cannot proceed until approval completes. Async would risk race conditions where the operation might execute before approval finishes.

**AppleScript Injection Prevention**: User-provided values displayed in HITL dialogs are escaped to prevent injection:
- Control characters (`\n`, `\r`, `\t`) replaced with spaces - prevents dialog rendering exploits
- Backslashes escaped before quotes - order matters for correct escaping
- Double quotes escaped - prevents breaking out of string literals

**Timeout Behavior**: HITL timeout defaults to DENY (fail-safe). The default timeout is 30 seconds with a minimum of 5 seconds (ensures user has time to read the prompt).

### Error Handling

Every error condition defaults to DENY (fail-closed):

| Scenario | Behavior |
|----------|----------|
| Context build error | DENY |
| Policy evaluation error | DENY |
| HITL timeout | DENY |
| HITL dialog error | DENY |
| AppleScript parse error | DENY |
| Unsupported platform for HITL | DENY (with warning log) |
| No matching policy rule | DENY (default_action) |
| Protected path access | DENY |
| Audit log write failure | DENY + shutdown |

**Backend Disconnection**: Transport-level errors (BrokenPipeError, ConnectionError, httpx errors) are detected and logged as `backend_disconnected` events to system.jsonl. The proxy cannot continue serving requests after backend disconnection.

---

## Shutdown Security

### Audit Integrity Failure Detection

Shutdown is triggered when audit integrity is compromised:

- Audit log file deleted
- Audit log file replaced (different inode)
- Audit log becomes unwritable
- Write to audit log fails

### Shutdown Sequence

1. `FailClosedAuditHandler.emit()` detects integrity failure
2. Sets `is_compromised = True` flag
3. Attempts to log event via fallback chain
4. Writes breadcrumb file with failure details
5. Spawns background thread for delayed exit (500ms allows error response to reach client)
6. Returns error to client (`-32603 INTERNAL_ERROR`)
7. Background thread calls `os._exit()` with appropriate exit code

### Breadcrumb File

On audit failure, a breadcrumb file is written for post-incident analysis:

- **Location**: `<log_dir>/.last_crash`
- **Contents**: timestamp, failure type, list of missing/compromised files
- **Files checked**: `audit/`, `audit/operations.jsonl`, `audit/decisions.jsonl`, `system/`, `system/system.jsonl`, `system/config_history.jsonl`, `system/policy_history.jsonl`

### Exit Codes

| Code | Meaning | Triggered By |
|------|---------|--------------|
| 10 | Audit log integrity failure | File deletion, replacement, or write failure |
| 11 | Policy enforcement failure | Reserved for future use |
| 12 | Identity verification failure | Reserved for future use |

### Post-Shutdown Client Behavior

After shutdown, MCP clients may auto-restart the proxy. The restarted proxy receives requests without proper initialization, causing `-32602 Invalid request parameters` errors. This is expected behavior - users must manually reconnect their MCP client.

---

## See Also

- [Architecture](architecture.md) - Zero Trust principles, PEP/PDP separation, request flow
- [Policies](policies.md) - Policy syntax, HITL configuration, combining algorithm
- [Logging](logging.md) - Log structure, formats, correlation IDs
