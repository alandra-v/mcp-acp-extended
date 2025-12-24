# Architecture

## Project Overview

**mcp-acp-extended** is a Zero Trust Access Control Proxy for the Model Context Protocol (MCP). It sits between MCP clients (like Claude Desktop) and MCP servers (like filesystem servers), providing comprehensive security, logging, and human oversight.

```
                                          ┌───────────┐
                                          │   PIPs    │
                                          │(Identity, │
                                          │ EDR, etc) │
                                          │ (Future)  │
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

**Philosophy**: Default-deny, explicit policies, audit everything, scalable and modular for multi-stage evolution

---

## Request Flow

**Request processing steps:**

```
1. Client sends MCP request -> Proxy (STDIO)
2. Logging middleware: Log client_request
3. Enforcement middleware:
   a. Build DecisionContext (user, session, operation, resource)
   b. (Future) Server-side protections: rate limiting, input validation
   c. Call PolicyEngine.evaluate(context) -> Decision
   d. If ALLOW: forward to backend
   e. If DENY: return error, log denial
   f. If HITL: prompt user -> ALLOW or DENY
4. Backend logging: Log proxy_request
5. Backend processes request
6. Backend logging: Log backend_response
7. (Future) Client-side protections: response filtering
8. Logging middleware: Log proxy_response
9. Client receives response
```

### Middleware Stack

Middleware executes outer-to-inner on requests, inner-to-outer on responses:

```
Request:  Client → Context → Audit → ClientLogger → Enforcement → Backend
Response: Client ← Context ← Audit ← ClientLogger ← Enforcement ← Backend
```

| Middleware | Purpose |
|------------|---------|
| Context (outer) | Sets request_id, session_id, tool_context for correlation |
| Audit | Logs all operations to `operations.jsonl` (always enabled) |
| ClientLogger | Debug wire logging to `client_wire.jsonl` (if debug enabled) |
| Enforcement (inner) | Policy evaluation, HITL, blocks before backend |

Policy decisions use ABAC (Attribute-Based Access Control) with subject, action, resource, and environment attributes. See [Policies](policies.md) for attribute details.

---

## Zero Trust Tenets (NIST SP 800-207)

The proxy implements Zero Trust Architecture based on the seven tenets defined in [NIST SP 800-207](https://doi.org/10.6028/NIST.SP.800-207):

| # | NIST Tenet | Implementation |
|---|------------|----------------|
| 1 | "All data sources and computing services are considered resources." | Every MCP tool, resource, and prompt is a protected resource requiring policy evaluation |
| 2 | "All communication is secured regardless of network location." | STDIO (local process); Streamable HTTP (future: mTLS) |
| 3 | "Access to individual enterprise resources is granted on a per-session basis." | Every request evaluated independently; no cached trust or "always allow" |
| 4 | "Access to resources is determined by dynamic policy—including the observable state of client identity, application/service, and the requesting asset—and may include other behavioral and environmental attributes." | ABAC policy engine evaluates subject, action, resource, environment attributes per request |
| 5 | "The enterprise monitors and measures the integrity and security posture of all owned and associated assets." | Audit log integrity monitoring with fail-closed shutdown; asset posture monitoring not yet implemented |
| 6 | "All resource authentication and authorization are dynamic and strictly enforced before access is allowed." | PolicyEnforcementMiddleware enforces policy before forwarding; current auth is local identity only |
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
├── proxy.py                    # Main entry point, orchestration only
├── config.py                   # Configuration models (Pydantic)
├── constants.py                # Shared constants (paths, transports, tool side effects)
├── exceptions.py               # Custom exceptions (AuditFailure, PermissionDeniedError)
├── cli/                        # CLI package (Click-based)
│   ├── __init__.py             # Re-exports main()
│   ├── main.py                 # CLI group definition
│   ├── prompts.py              # Interactive prompt helpers
│   └── commands/               # Subcommand modules
│       ├── init.py             # init command
│       ├── start.py            # start command
│       └── config.py           # config show/path/edit
├── context/                    # ABAC context building
│   ├── context.py              # DecisionContext model + build_decision_context()
│   ├── subject.py              # Subject attributes (user identity)
│   ├── action.py               # Action attributes (MCP method, intent)
│   ├── resource.py             # Resource attributes (tool, file, server)
│   ├── environment.py          # Environment attributes (timestamp, IDs)
│   ├── provenance.py           # Provenance tracking (TOKEN, PROXY_CONFIG, etc.)
│   ├── parsing.py              # Path/URI parsing utilities
│   ├── approval.py             # HITL/step-up state (skeleton)
│   ├── data.py                 # Data inspection (skeleton)
│   ├── route.py                # Routing context (skeleton)
│   └── tool_registry.py        # Tool side effects (skeleton)
├── pdp/                        # Policy Decision Point
│   ├── policy.py               # PolicyConfig, PolicyRule, RuleConditions
│   ├── matcher.py              # Pattern matching (glob, regex)
│   ├── engine.py               # PolicyEngine.evaluate()
│   └── decision.py             # Decision enum (ALLOW/DENY/HITL)
├── pep/                        # Policy Enforcement Point
│   ├── middleware.py           # PolicyEnforcementMiddleware
│   ├── context_middleware.py   # ContextMiddleware (request context lifecycle)
│   ├── hitl.py                 # HITLHandler (macOS osascript dialogs)
│   └── applescript.py          # AppleScript utilities
├── security/
│   ├── identity.py             # IdentityProvider protocol + LocalIdentityProvider
│   ├── shutdown.py             # ShutdownCoordinator
│   └── integrity/              # Audit log integrity monitoring
│       ├── audit_handler.py    # FailClosedAuditHandler (inode verification)
│       ├── audit_monitor.py    # AuditHealthMonitor (NOT WIRED UP - future use)
│       └── emergency_audit.py  # Fallback chain logging
├── telemetry/                  # All logging functionality
│   ├── audit/                  # Security audit logging (ALWAYS enabled)
│   │   └── operation_logger.py # AuditLoggingMiddleware
│   ├── debug/                  # Wire-level debug logging (DEBUG level only)
│   │   ├── client_logger.py
│   │   ├── backend_logger.py
│   │   └── logging_proxy_client.py
│   ├── system/                 # System/operational logging
│   │   └── system_logger.py
│   └── models/                 # Pydantic models for log events
│       ├── wire.py             # Wire log models (debug/)
│       ├── system.py           # System log models (system/, config_history, policy_history)
│       ├── audit.py            # Audit log models (OperationEvent + supporting types)
│       └── decision.py         # Decision event model (DecisionEvent)
└── utils/                      # General utilities only
    ├── file_helpers.py         # App dir, checksum, permissions, versioning
    ├── transport.py            # Backend transport creation, health checks
    ├── config/                 # Configuration helpers
    │   └── config_helpers.py   # Path helpers, log paths, directory setup
    ├── policy/                 # Policy file helpers
    │   └── policy_helpers.py   # Policy I/O, checksum, default policy creation
    ├── history_logging/        # History logging (config + policy)
    │   ├── config_logger.py
    │   └── policy_logger.py
    └── logging/                # Logging utilities
        ├── logger_setup.py     # JSONL logger setup (standard + fail-closed)
        ├── logging_context.py  # ContextVars for correlation IDs
        ├── extractors.py       # Metadata extraction (tool, file, client info)
        ├── iso_formatter.py    # ISO 8601 formatter
        └── logging_helpers.py  # Sanitization, error categorization, summaries
```

---

## Context vs PIP

**`context/`** builds decision context from **local information**:
- Request data (MCP method, arguments, tool name)
- Proxy configuration (server ID, protected directories)
- Local identity (currently: environment username)

**`pip/`** (planned) will query **external attribute sources** at decision time:

| Future PIP | What it provides |
|------------|------------------|
| Identity Provider (IdP) | OIDC claims, group memberships, roles |
| Tool Registry | Verified side effects, risk tiers |
| Server Registry | Which servers a user can access |
| Asset Database | Device posture, software inventory |
| Threat Intel Feed | Known bad IPs, risk scores |
| Resource Classifier | Data sensitivity labels |

Both modules contribute to the DecisionContext - `context/` provides locally-derived attributes, `pip/` will provide externally-sourced attributes with higher trust (e.g., TOKEN provenance from IdP).

The `DecisionContext` flows through the system for policy evaluation, logging, and user interaction. See [Policies](policies.md) for attribute details and policy writing.

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

**Stage 1 (Current): Single Tenant Zero Trust Proxy**
- Single user (local identity)
- Single session, single backend server
- STDIO and Streamable HTTP transports

**Stage 2: Authentication & Authorization**
- OAuth authentication (Auth0 IdP)
- User ID, roles, groups from JWT tokens
- Enhanced device posture tracking

**Stage 3: Multi-server + mTLS**
- Multiple backend servers with per-server policies
- mTLS for proxy<->backend authentication
- Cross-server data flow tracking


### Planned Capabilities

| Capability | Context Component | Description |
|------------|-------------------|-------------|
| Server-side protections | Request validation | Rate limiting, input validation |
| Client-side protections | Response filtering | Sanitize responses before client |
| Heuristic HITL | All attributes | Risk scoring to trigger HITL |
| Anomaly detection | `environment.timestamp` | Behavioral analysis |
| Content inspection | `data.*` | Secret/PII detection |
| Approval expiry | `approval.age_s` | Re-prompt after timeout |
| Cross-server rules | `route.*` | Lateral movement detection |
| Trust-level policies | `*.provenance` | Require TOKEN provenance for sensitive ops |

---

## See Also

- [Security](security.md) for security design decisions
- [Logging](logging.md) for telemetry architecture
- [Policies](policies.md) for policy evaluation
