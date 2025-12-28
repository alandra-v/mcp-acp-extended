# Logging

## Primary goals

Logging supports the Zero Trust security model with three primary goals:

1. **Audit trail**: Complete record of who accessed what, when, and with what outcome
2. **Policy enforcement monitoring**: Every policy decision is logged for compliance and debugging
3. **Incident response & forensics**: Sufficient detail to reconstruct events during security investigations

**Fail-closed on log failure**: If audit logging fails (e.g., disk full, file deleted), the proxy shuts down rather than operate without an audit trail. This is a core Zero Trust requirement. See [Security](security.md) for details on audit log integrity protection.

---

## Log Structure

```
~/.mcp-acp-extended/mcp_acp_extended_logs/
├── debug/           # Wire-level debug logs (DEBUG level only)
│   ├── client_wire.jsonl   # Client<->Proxy communication
│   └── backend_wire.jsonl  # Proxy<->Backend communication
├── system/          # System/operational events
│   ├── system.jsonl        # Operational logs, errors, backend disconnections
│   ├── config_history.jsonl # Configuration changes (versioned)
│   └── policy_history.jsonl # Policy changes (versioned)
├── audit/           # Security audit logs (ALWAYS enabled)
│   ├── operations.jsonl    # MCP operation audit trail
│   └── decisions.jsonl     # Policy evaluation decisions + HITL outcomes
└── metrics/         # Performance metrics (future)

# Bootstrap log (in config directory, not log directory)
<config_dir>/bootstrap.jsonl  # Validation failures before log_dir available
```

---

## Configuration

Log directory is specified via `--log-dir` during `mcp-acp-extended init` (recommended: `~/.mcp-acp-extended`).

**Log level options:**
- `info` (default): Audit and system logs
- `debug`: Enables wire-level debug logs with full request/response payloads

See [Configuration](configuration.md) for full CLI options.

---

## Audit Logs (`audit/`)

Security audit trail - **ALWAYS enabled, cannot be disabled**.

### operations.jsonl

Each log entry follows the **Kipling method (5W1H)**: Who (subject), What (method, tool), When (timestamp), Where (backend, path), Why (policy decision), How (arguments, transport).

| Field | Description |
|-------|-------------|
| `time` | ISO 8601 timestamp |
| `session_id`, `request_id` | Correlation IDs |
| `method` | MCP method (e.g., `tools/call`) |
| `status` | `Success` or `Failure` |
| `error_code` | MCP/JSON-RPC error code (on failure) |
| `message` | Human-readable description |
| `subject` | User identity (`subject_id`, `subject_claims`) |
| `client_id` | MCP client application name |
| `backend_id` | Backend server identifier |
| `transport` | Backend transport (`stdio` or `streamablehttp`) |
| `tool_name` | Tool name (for `tools/call`) |
| `file_path`, `file_extension` | File info (for file operations) |
| `arguments_summary` | Redacted args: `body_hash`, `payload_length` |
| `config_version` | Active configuration version |
| `duration` | Operation duration in ms |
| `response_summary` | Response metadata: `size_bytes`, `body_hash` |

### decisions.jsonl

Every policy evaluation decision, including HITL outcomes.

| Field | Description |
|-------|-------------|
| `time` | ISO 8601 timestamp |
| `decision` | `allow`, `deny`, or `hitl` |
| `final_rule` | Rule ID that determined outcome (or `default`, `discovery_bypass`) |
| `matched_rules` | All rules that matched |
| `mcp_method`, `tool_name` | Request method and tool |
| `path`, `uri`, `scheme` | Resource context (file path or URI) |
| `request_id`, `backend_id`, `policy_version` | Correlation and context (required) |
| `session_id` | Session ID (optional, may not exist during `initialize`) |
| `subject_id` | User identity (optional until auth implemented) |
| `side_effects` | Action classification |
| `duration_ms` | Policy evaluation time |
| `hitl_outcome` | `user_allowed`, `user_denied`, `timeout` (if HITL) |
| `hitl_response_time_ms` | User response time (if HITL) |

---

## Debug Logs (`debug/`)

Wire-level MCP communication with full request/response payloads.

**Only enabled when `log_level=debug`** - disabled by default for privacy.

- `client_wire.jsonl`: Client ↔ Proxy communication
- `backend_wire.jsonl`: Proxy ↔ Backend communication

Event types: `client_request`, `proxy_response`, `proxy_error`, `proxy_request`, `backend_response`, `backend_error`

---

## System Logs (`system/`)

Operational events - **only WARNING, ERROR, CRITICAL levels are logged to file** (INFO goes to console only).

### system.jsonl

Operational issues and errors.

| Field | Description |
|-------|-------------|
| `time` | ISO 8601 timestamp |
| `level` | `WARNING`, `ERROR`, or `CRITICAL` |
| `event` | Event type (e.g., `startup_failed`, `backend_disconnected`) |
| `message` | Human-readable description |
| `component` | Source component (e.g., `proxy`, `backend_client`) |
| `session_id`, `request_id`, `backend_id` | Correlation IDs (if applicable) |
| `config_version` | Active configuration version |
| `error_type`, `error_message` | Exception details |
| `stacktrace` | Optional traceback |
| `details` | Additional structured data (e.g., `retry_count`, `timeout_ms`) |

**Note**: This schema allows additional fields (`extra="allow"`).

### config_history.jsonl

Configuration change audit trail.

Events: `config_created`, `config_loaded`, `config_updated`, `manual_change_detected`, `config_validation_failed`

| Field | Description |
|-------|-------------|
| `config_version`, `previous_version` | Version tracking |
| `change_type` | `initial_load`, `cli_update`, `manual_edit`, `startup_load`, `validation_error` |
| `component`, `source` | Where change originated |
| `checksum` | SHA256 for integrity verification |
| `snapshot` | Full config content (for creation/changes, skipped for loads) |
| `error_type`, `error_message` | For validation failures |

### policy_history.jsonl

Policy change audit trail.

Events: `policy_created`, `policy_loaded`, `policy_updated`, `manual_change_detected`, `policy_validation_failed`

| Field | Description |
|-------|-------------|
| `policy_version`, `previous_version` | Version tracking |
| `change_type` | `initial_creation`, `startup_load`, `rule_update`, `manual_edit`, `validation_error` |
| `component`, `source` | Where change originated |
| `checksum` | SHA256 for integrity verification |
| `snapshot` | Full policy content (for creation/changes, skipped for loads) |
| `error_type`, `error_message` | For validation failures |

---

## Bootstrap Log

Location: `<config_dir>/bootstrap.jsonl` (e.g., `~/Library/Application Support/mcp-acp-extended/bootstrap.jsonl`)

Captures startup failures when the user's `log_dir` cannot be read from an invalid config. This ensures errors are never lost, even during misconfiguration.

---

## Metrics (Future)

Performance metrics logging is planned but not yet implemented.

---

## Log Format

- **JSONL**: One JSON object per line
- **ISO 8601 timestamps**: Milliseconds precision, UTC (e.g., `2025-12-03T10:30:45.123Z`)

---

## Correlation IDs

### Current Implementation

- `request_id`: Per request/response pair
- `session_id`: Per client connection

### Future Capabilities (Not Implemented)

- `connection_id`: Track multiple concurrent connections
- `span_id`, `parent_span_id`: OpenTelemetry tracing
- `user_id`, `roles`: From OAuth token claims

---

## Schema Design

Log schemas are inspired by [OCSF (Open Cybersecurity Schema Framework)](https://schema.ocsf.io/) and security logging best practices:

| Log Type | Inspiration |
|----------|-------------|
| `operations.jsonl` | OCSF API Activity class (6003) - Application Activity Category |
| `decisions.jsonl` | OCSF Authorization class (3003) - Identity & Access Management Category |
| `system.jsonl` | OCSF Process Activity class (1007) and Application Error class (6008) - System Activity Category and Application Activity Category |
| `config_history.jsonl` | OWASP, NIST SP 800-92/800-128, CIS Control 8 |
| `policy_history.jsonl` | OWASP, NIST SP 800-92/800-128, CIS Control 8 |
| `auth.jsonl` (future) | OCSF Authentication class (3002) and Authorize Session class (3003) - Identity & Access Management Category |


See `docs/logging_specs/` for Pydantic models, JSON schemas, and detailed documentation.

---

## SIEM Readiness

The logging design is SIEM-ready:

| Feature | Status |
|---------|--------|
| Structured format (JSONL) | ✅ Machine-readable, easily parsed |
| OCSF-inspired schemas | ✅ Industry standard, 120+ vendor support |
| ISO 8601 timestamps | ✅ Standardized, sortable, timezone-aware |
| Correlation IDs | ✅ Cross-event correlation via session_id, request_id |
| Consistent field names | ✅ Unified queries across log types |
| Log level filtering | ✅ WARNING+ only, reduces noise |
| Payload redaction | ✅ Hashes preserve forensic value without PII |

**For full SIEM integration:**
- Add log forwarder (syslog/HTTP/S3)
- Full OCSF compliance (currently "inspired by", not fully compliant)
- Log enrichment (device info, geo data, threat intel context)

---

## Security

**Payload redaction**: Arguments are never logged in full - only SHA256 hash and byte length. Full payloads only in debug logs.

**Audit log integrity**: Log files are protected by two layers of monitoring:
1. **Per-write checks**: Before every write, file identity (device ID + inode) is verified
2. **Background monitoring**: AuditHealthMonitor checks every 30 seconds, even during idle periods

On integrity failure, the proxy shuts down. See [Security](security.md) for details.

**Atomic writes**: Config and policy history use atomic writes to prevent corruption. See [Configuration](configuration.md).

---

## See Also

- [Security](security.md) for audit log integrity and fail-closed behavior
- [Configuration](configuration.md) for log directory settings
