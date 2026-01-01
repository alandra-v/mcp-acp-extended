# Architecture

## Project Overview

**mcp-acp-extended** is a Zero Trust Access Control Proxy for the Model Context Protocol (MCP). It sits between MCP clients (like Claude Desktop) and MCP servers (like filesystem servers), providing comprehensive security, logging, and human oversight.

```
                                          ┌───────────┐
                                          │   PIPs    │
                                          │ (OIDC,    │
                                          │  Device)  │
                                          └───────────┘
                                                ▲
                                                │ 3. query
                                                │
┌──────────┐  1. request   ┌────────────────────┼───────────────┐  6. request   ┌──────────┐
│  Client  │──────────────▶│              Proxy │               │──────────────▶│  Server  │
│          │◀──────────────│                    │               │◀──────────────│          │
└──────────┘  6. response  │  ┌───────┐    ┌────┴──────┐        │  6. response  └──────────┘
                           │  │       │ 2. │           │        │
                           │  │  PEP  │───▶│    PDP    │        │
                           │  │       │◀───│  (Policy  │        │
                           │  │       │ 5. │   Engine) │        │
                           │  └───────┘    └───────────┘        │
                           │                                    │
                           │  ┌───────────┐    ┌───────────┐    │
                           │  │ Audit Log │    │System Log │    │
                           │  └───────────┘    └───────────┘    │
                           └────────────────────────────────────┘
```

**Architecture Pattern**: PEP/PDP separation (Policy Enforcement Point / Policy Decision Point)

**Philosophy**: Default-deny, explicit policies, audit everything, modular and extensible

---

## Request Flow

**Request processing steps:**

```
1. Client sends MCP request -> Proxy (STDIO)
2. DoS rate limiter: Check global request rate
3. Logging middleware: Log client_request
4. Enforcement middleware:
   a. Build DecisionContext (user, session, operation, resource)
   b. Check per-tool rate limits (triggers HITL if exceeded)
   c. Call PolicyEngine.evaluate(context) -> Decision
   d. If ALLOW: forward to backend
   e. If DENY: return error, log denial
   f. If HITL: prompt user -> ALLOW or DENY
5. Backend logging: Log proxy_request
6. Backend processes request
7. Backend logging: Log backend_response
8. Logging middleware: Log proxy_response
9. Client receives response
```

### Middleware Stack

Middleware executes outer-to-inner on requests, inner-to-outer on responses:

```
Request:  Client → DoS → Context → Audit → ClientLogger → Enforcement → Backend
Response: Client ← DoS ← Context ← Audit ← ClientLogger ← Enforcement ← Backend
```

| Middleware | Purpose |
|------------|---------|
| DoS (outermost) | Token bucket rate limiting (10 req/s, 50 burst) - prevents request flooding |
| Context | Sets request_id, session_id, tool_context for correlation |
| Audit | Logs all operations to `operations.jsonl` (always enabled) |
| ClientLogger | Debug wire logging to `client_wire.jsonl` (if debug enabled) |
| Enforcement (innermost) | Policy evaluation, HITL, per-tool rate limiting, blocks before backend |

**Two rate limiters:**
- **DoS rate limiter** (outermost): Global token bucket, catches flooding before any processing
- **Per-tool rate limiter** (in Enforcement): Per-session, per-tool tracking (30 calls/60s triggers HITL)

Policy decisions use ABAC (Attribute-Based Access Control) with subject, action, resource, and environment attributes. See [Policies](policies.md) for attribute details.

For detailed sequence diagrams, see [Request Flow Diagrams](request_flow_diagrams.md).

---

## Zero Trust Tenets (NIST SP 800-207)

The proxy implements Zero Trust Architecture based on the seven tenets defined in [NIST SP 800-207](https://doi.org/10.6028/NIST.SP.800-207):

| # | NIST Tenet | Implementation |
|---|------------|----------------|
| 1 | "All data sources and computing services are considered resources." | MCP operations (tools/call, resources/read, prompts/get) require policy evaluation; discovery methods allowed for protocol function (see `constants.py`) |
| 2 | "All communication is secured regardless of network location." | STDIO (local process); Streamable HTTP with optional mTLS |
| 3 | "Access to individual enterprise resources is granted on a per-session basis." | Policy evaluated every request; identity cached 60s for performance; HITL approvals cached to reduce dialog fatigue |
| 4 | "Access to resources is determined by dynamic policy—including the observable state of client identity, application/service, and the requesting asset—and may include other behavioral and environmental attributes." | ABAC policy engine evaluates subject, action, resource, environment attributes per request |
| 5 | "The enterprise monitors and measures the integrity and security posture of all owned and associated assets." | Audit log integrity monitoring (30s interval) with fail-closed shutdown; device posture checks (FileVault, SIP) with 5-min interval |
| 6 | "All resource authentication and authorization are dynamic and strictly enforced before access is allowed." | Policy enforced before forwarding; OIDC token validated with 60-second cache for performance |
| 7 | "The enterprise collects as much information as possible about the current state of assets, network infrastructure and communications and uses it to improve its security posture." | Comprehensive audit logging (operations, decisions, config/policy history) for forensics and analysis |

**Additional design principles:**
- **Fail-closed**: All errors result in DENY (context build failure, policy error, HITL timeout)
- **Human oversight**: HITL for sensitive operations as policy-defined escalation
- **Least privilege**: Path-scoped policies, default-deny

### Modularity

| Component | Mechanism | Status |
|-----------|-----------|--------|
| Identity | `IdentityProvider` protocol | ✅ Pluggable (local → OAuth → mTLS) |
| Transport | FastMCP transport abstraction | ✅ STDIO, streamable HTTP |
| Middleware | FastMCP middleware stack | ✅ Composable ordering |
| Configuration | Version field, Pydantic models | ✅ Schema evolution supported |
| Policy engine | Class-based, no protocol yet | Future 3rd party integration |
| Logging | Pydantic models, JSONL format | ✅ Extensible (SystemEvent allows extra fields) |


---

## Separation of Concerns

Modules are organized by domain with related responsibilities grouped together:

```
src/mcp_acp_extended/
├── proxy.py                    # Main entry point, orchestration
├── config.py                   # Configuration models (Pydantic)
├── constants.py                # Shared constants
├── exceptions.py               # Custom exceptions
├── api/                        # Management API server
│   ├── server.py               # FastAPI app creation
│   └── routes/                 # API endpoints
│       ├── control.py          # /api/control/* (status, reload-policy)
│       ├── approvals.py        # /api/approvals/* (HITL approval management)
│       └── ...
├── cli/                        # CLI package (Click-based)
│   ├── main.py                 # CLI group definition
│   ├── prompts.py              # Interactive prompt helpers
│   ├── startup_alerts.py       # Startup alert display
│   └── commands/               # Subcommand modules
│       ├── init.py, start.py, config.py, auth.py, policy.py
├── context/                    # ABAC context building
│   ├── context.py              # DecisionContext model + build_decision_context()
│   ├── subject.py              # Subject attributes (user identity)
│   ├── action.py               # Action attributes (MCP method, intent)
│   ├── resource.py             # Resource attributes (tool, file, server)
│   ├── environment.py          # Environment attributes (timestamp, IDs)
│   ├── provenance.py           # Provenance tracking (TOKEN, PROXY_CONFIG, etc.)
│   ├── parsing.py              # Path/URI parsing utilities
│   └── tool_side_effects.py    # Tool side effects mapping
├── pdp/                        # Policy Decision Point
│   ├── policy.py               # PolicyConfig, PolicyRule, RuleConditions
│   ├── matcher.py              # Pattern matching (glob, regex)
│   ├── engine.py               # PolicyEngine.evaluate()
│   └── decision.py             # Decision enum (ALLOW/DENY/HITL)
├── pep/                        # Policy Enforcement Point
│   ├── middleware.py           # PolicyEnforcementMiddleware
│   ├── context_middleware.py   # ContextMiddleware (request context lifecycle)
│   ├── hitl.py                 # HITLHandler (macOS osascript dialogs)
│   ├── applescript.py          # AppleScript utilities
│   ├── approval_store.py       # HITL approval caching
│   ├── rate_handler.py         # Rate limit breach handling
│   └── reloader.py             # Hot policy reload
├── pips/                       # Policy Information Points
│   └── auth/                   # Authentication PIP
│       ├── oidc_provider.py    # OIDCIdentityProvider (JWKS, token validation)
│       ├── claims.py           # Token claims processing
│       └── session.py          # Session management
├── security/
│   ├── identity.py             # IdentityProvider protocol
│   ├── shutdown.py             # ShutdownCoordinator
│   ├── rate_limiter.py         # Per-session rate tracking
│   ├── mtls.py                 # mTLS configuration
│   ├── sanitizer.py            # Input sanitization
│   ├── tool_sanitizer.py       # Tool description sanitization
│   ├── auth/                   # JWT validation
│   │   └── jwt_validator.py
│   ├── posture/                # Device health checks
│   │   └── device.py           # FileVault, SIP checks
│   └── integrity/              # Audit log integrity
│       ├── audit_handler.py    # FailClosedAuditHandler (inode verification)
│       ├── audit_monitor.py    # AuditHealthMonitor (background checks)
│       └── emergency_audit.py  # Fallback chain logging
├── telemetry/                  # All logging functionality
│   ├── audit/                  # Security audit logging (ALWAYS enabled)
│   │   ├── operation_logger.py, decision_logger.py, auth_logger.py
│   ├── debug/                  # Wire-level debug logging (DEBUG level only)
│   │   ├── client_logger.py, backend_logger.py
│   ├── system/                 # System/operational logging
│   │   └── system_logger.py
│   └── models/                 # Pydantic models for log events
│       ├── wire.py, system.py, audit.py, decision.py
└── utils/                      # General utilities
    ├── file_helpers.py, transport.py
    ├── config/, policy/, history_logging/, logging/
```

---

## Context vs PIP

**`context/`** builds decision context from **local information**:
- Request data (MCP method, arguments, tool name)
- Proxy configuration (server ID, protected directories)
- Tool side effects mapping

**`pips/`** queries **external attribute sources** at decision time:

| PIP | What it provides | Status |
|-----|------------------|--------|
| OIDC Identity Provider | User ID, scopes, token claims from JWT | ✅ Implemented |
| Device Posture | FileVault, SIP status | ✅ Implemented |
| Tool Registry | Verified side effects, risk tiers | Future |
| Threat Intel Feed | Known bad IPs, risk scores | Future |

Both modules contribute to the DecisionContext - `context/` provides locally-derived attributes, `pips/` provides externally-sourced attributes with higher trust (e.g., TOKEN provenance from IdP).

The `DecisionContext` flows through the system for policy evaluation, logging, and user interaction. See [Policies](policies.md) for attribute details.

**Design principle**: Context is used for **matching**, not autonomous decision-making. The PolicyEngine matches attributes against rules - it does not analyze context to infer intent.

---

## Error Handling

### Backend Errors

MCP errors from backend servers are forwarded to clients unchanged. These are already properly formatted MCP error responses with standard MCP error codes.

### Proxy-Level Errors

Transport failures (backend disconnect, timeout) and internal proxy errors surface as raw exceptions rather than MCP error codes. This is a conscious trade-off:

- **Rare occurrence**: These errors are edge cases, not normal operation
- **Diagnostic value**: Raw error messages (e.g., `BrokenPipeError`, `ConnectionError`) provide useful context
- **Complexity vs benefit**: Adding `ErrorHandlingMiddleware` would add complexity for minimal benefit

If clients need consistent MCP error surfaces, FastMCP's `ErrorHandlingMiddleware` can be added as the outermost middleware to transform proxy errors to MCP format.

---

## Future

### Evolution Stages

**Stage 1: Single Tenant Zero Trust Proxy**
- Single user (local identity)
- Single session, single backend server
- STDIO and Streamable HTTP transports

**Stage 2 (Current): Authentication & Authorization**
- OAuth authentication (Auth0 IdP)
- User ID, roles, groups from JWT tokens
- Enhanced device posture tracking

**Stage 3: Multi-server**
- Multiple backend servers with per-server policies
- mTLS for proxy<->backend authentication
- Cross-server data flow tracking


### Planned Capabilities

| Capability | Description |
|------------|-------------|
| Client-side protections | Sanitize responses before returning to client |
| Heuristic HITL | Risk scoring to trigger HITL based on behavioral patterns |
| Anomaly detection | Behavioral analysis based on request patterns |
| Content inspection | Secret/PII detection in request/response payloads |
| Cross-server rules | Lateral movement detection across multiple backends |
| Trust-level policies | Require TOKEN provenance for sensitive operations |

---

## See Also

- [Security](security.md) for security design decisions
- [Logging](logging.md) for telemetry architecture
- [Policies](policies.md) for policy evaluation
- [Request Flow Diagrams](request_flow_diagrams.md) for detailed sequence diagrams of lifecycle and operation phases
