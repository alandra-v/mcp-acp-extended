# UI Implementation Progress

## Overview

Web UI for mcp-acp-extended proxy management. Single-proxy first, multi-proxy ready.

**Architecture**: Proxy is source of truth for all state. Manager (Phase 2) is optional UI gateway that queries proxy and routes commands.

---

## Phase 1: Backend Infrastructure

**Status: COMPLETE**

State classes live in proxy process. Proxy owns all state (approvals, sessions, pending).

- [x] **State classes** (`manager/state.py`)
  - [x] `ProxyInfo` - frozen dataclass (id, backend_id, status, started_at, pid, api_port, uptime_seconds)
  - [x] `ProxyState` - aggregates all proxy state for API exposure
    - Wraps `ApprovalStore` for cached approvals
    - Wraps `SessionManager` via `get_all_sessions()` public accessor
    - Manages pending approvals with SSE broadcast
  - [x] `PendingApprovalInfo` - frozen dataclass for API responses (immutable, serializable)
  - [x] `PendingApprovalRequest` - internal async waiter (wraps info + asyncio.Event)
  - [x] `CachedApprovalSummary` - NamedTuple for structured cache data

- [x] **API routes** (all in `api/routes/`)
  - [x] `proxies.py` - `/api/proxies`, `/api/proxies/{id}`
  - [x] `sessions.py` - `/api/auth-sessions`
  - [x] `approvals.py` - `/api/approvals/cached` (GET/DELETE)
  - [x] `pending.py` - `/api/approvals/pending` (SSE + list + approve/deny)
  - [x] `control.py` - `/api/control/status`, `/api/control/reload-policy`

- [x] **Wire up in proxy** (`proxy.py`)
  - [x] Create `ProxyState` in lifespan with approval_store + session_manager
  - [x] Attach to `api_app.state.proxy_state`

- [x] **Best practices applied**
  - [x] All routes in `api/routes/`, state classes in `manager/`
  - [x] Shared route helpers in `api/deps.py` (FastAPI convention)
  - [x] Separated API model (PendingApprovalInfo) from internal waiter (PendingApprovalRequest)
  - [x] Added `SessionManager.get_all_sessions()` public accessor
  - [x] Bounded SSE queues to maxsize=100 (memory safety)
  - [x] SSE connect/disconnect logging for observability
  - [x] Fixed type annotations (cast, AsyncIterator, NamedTuple)

**Route organization**:
| Package | Routes | Purpose |
|---------|--------|---------|
| `api/routes/approvals.py` | `/api/approvals/cached` | Cached HITL approvals (debug) |
| `api/routes/pending.py` | `/api/approvals/pending/*` | Pending HITL approvals (SSE + actions) |
| `api/routes/proxies.py` | `/api/proxies/*` | Proxy info |
| `api/routes/sessions.py` | `/api/auth-sessions` | Auth sessions |
| `api/routes/control.py` | `/api/control/*` | Status and policy reload |

**Terminology**:
- **Cached approvals** = Previously approved HITL decisions (reduces dialog fatigue)
- **Pending approvals** = HITL requests waiting for user decision
- **Auth sessions** = User authentication bindings (JWT → session), not proxy lifecycle

**Deliverable**: `curl http://127.0.0.1:8080/api/proxies` returns real proxy data. ✓

---

## Phase 2: Security Middleware

**Status: COMPLETE**

Implement security from ui-security.md.

### Required

- [x] **Token generation** (`api/security.py`)
  - [x] Generate random bearer token on startup (32 bytes, hex encoded)
  - [x] Write to `~/.mcp-acp-extended/manager.json` with port
  - [x] Delete file on shutdown

- [x] **Token validation middleware**
  - [x] Extract `Authorization: Bearer <token>` header
  - [x] Constant-time comparison (`hmac.compare_digest`)
  - [x] Return 401 if missing/invalid

- [x] **Host header validation**
  - [x] Allow only: `localhost`, `127.0.0.1`, `[::1]`
  - [x] Return 403 if invalid

- [x] **Origin header validation**
  - [x] Allow only localhost origins
  - [x] Reject if present and not allowed
  - [x] Require Origin for mutation requests (POST/PUT/DELETE)

- [x] **SSE authentication**
  - [x] Same-origin requests (no Origin header) → allow SSE without token
  - [x] Cross-origin (dev mode) → accept token in query param for SSE only
  - [x] Never accept query param token for mutations

### Recommended

- [x] **Response security headers**
  - [x] `X-Content-Type-Options: nosniff`
  - [x] `X-Frame-Options: DENY`
  - [x] `Content-Security-Policy: default-src 'self'`
  - [x] `Cache-Control: no-store`
  - [x] `Referrer-Policy: same-origin`
  - [x] `Permissions-Policy: camera=(), microphone=(), geolocation=()`

- [x] **Request limits**
  - [x] Max request size: 1MB

### Enterprise Hardening (Future)

- [ ] Rate limiting - deferred (enterprise compliance)
- [ ] Failed auth lockout - deferred (enterprise compliance)

**Deliverable**: API rejects unauthorized requests, prevents DNS rebinding. ✓

---

## Phase 3: Core API Endpoints

**Status: Partially Complete** (P0 done via Phase 1)

### P0: Critical - DONE

- [x] `GET /api/proxies` - list proxies
- [x] `GET /api/proxies/{id}` - proxy details
- [x] `GET /api/auth-sessions` - list auth sessions
- [x] `GET /api/approvals/cached` - list cached approvals
- [x] `DELETE /api/approvals/cached` - clear all cached approvals
- [x] `DELETE /api/approvals/cached/entry` - delete single cached approval
- [x] `GET /api/approvals/pending` (SSE) - stream pending HITL requests
- [x] `POST /api/approvals/{id}/approve` - approve pending
- [x] `POST /api/approvals/{id}/deny` - deny pending

### P1: Important - TODO

- [ ] **Config endpoints** (`GET/PUT /api/config`)
- [ ] **Policy endpoints** (`GET/PUT /api/policy`, `POST /api/policy/reload`)
- [ ] **Log endpoints** (`GET /api/logs`, `GET /api/logs/stream` SSE)
- [ ] **Auth endpoint** (`GET /api/auth/status`, login, logout, logout federated)

---

## Phase 4: HITL Integration

**Status: Infrastructure Ready, Integration Pending**

### Done (via Phase 1)

- [x] `ProxyState.create_pending()` - create pending approval
- [x] `ProxyState.resolve_pending()` - resolve with allow/deny
- [x] `ProxyState.get_pending_approvals()` - list pending
- [x] `ProxyState.subscribe()/unsubscribe()` - SSE tracking
- [x] `ProxyState.is_ui_connected` - check if UI connected
- [x] `ProxyState.wait_for_decision()` - async wait for resolution
- [x] SSE broadcast of pending/resolved/timeout events
- [x] Approval endpoints (approve/deny)

### TODO

- [ ] **Modify HITL handler** (`pep/hitl.py`)
  - [ ] Check `is_ui_connected` before creating pending
  - [ ] If UI connected: use `wait_for_decision()`
  - [ ] If timeout or no UI: fall back to osascript
  - [ ] Never show both simultaneously

- [ ] **Integration test**: trigger HITL, approve in browser

**Deliverable**: Browser approvals work, osascript fallback when UI closed.

---

## Phase 5-7: React Integration, Editors, Polish

**Status: Not Started**

See full details in sections below.

---

## Future: Proxy Lifecycle Management (Multi-Backend)

**Status: Deferred** (requires multi-proxy Manager architecture)

Manage proxy processes from the UI. Only applicable when running multiple backend proxies.

### Endpoints (not yet implemented)

- [ ] `POST /api/proxies/{id}/start` - start a proxy
- [ ] `POST /api/proxies/{id}/stop` - stop a proxy
- [ ] `POST /api/proxies/{id}/restart` - restart a proxy
- [ ] `DELETE /api/proxies/{id}` - remove proxy from registry

### Prerequisites

- Multi-proxy Manager process (separate from proxy workers)
- Worker registration/heartbeat protocol
- Process spawning/supervision

### Notes

- In single-proxy mode, stopping the proxy kills the CLI process and UI
- Proxy lifecycle is currently managed by the MCP client (e.g., Claude Desktop)
- This feature makes sense when Manager can spawn/supervise multiple backend proxies

---

## Dependencies

```
Phase 1 (Backend) ──► Phase 2 (Security) ──► Phase 3 (Endpoints) ──► Phase 4 (HITL)
     ✓                       ✓                  P0 ✓, P1 TODO         infra ✓
                                                     NEXT                 │
                                                                          ▼
                                                                    Phase 5 (React)
                                                                          │
                                                                          ▼
                                                                    Phase 6 (Editors)
                                                                          │
                                                                          ▼
                                                                    Phase 7 (Polish)
```

---

## Completion Criteria

- [x] API returns real proxy/session/approval data
- [x] Security middleware prevents unauthorized access
- [ ] Web-based HITL approvals work
- [ ] osascript fallback when UI not connected
- [ ] Config/Policy editable from browser
- [ ] Auth status visible in UI
- [ ] Build pipeline produces shippable static files
