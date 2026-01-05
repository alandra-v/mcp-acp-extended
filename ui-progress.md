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
  - [x] Attach to `api_app.state`: proxy_state, config, policy_reloader, approval_store, identity_provider

**Deliverable**: `curl http://127.0.0.1:8765/api/proxies` returns real proxy data. ✓

---

## Phase 2: Security Middleware

**Status: COMPLETE**

Implement security from ui-security.md.

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

- [x] **Response security headers**
  - [x] `X-Content-Type-Options: nosniff`
  - [x] `X-Frame-Options: DENY`
  - [x] `Content-Security-Policy: default-src 'self'`
  - [x] `Cache-Control: no-store`
  - [x] `Referrer-Policy: same-origin`
  - [x] `Permissions-Policy: camera=(), microphone=(), geolocation=()`

- [x] **Request limits**
  - [x] Max request size: 1MB

**Deliverable**: API rejects unauthorized requests, prevents DNS rebinding. ✓

---

## Phase 3: Core API Endpoints

**Status: COMPLETE**

- [x] `GET /api/proxies` - list proxies
- [x] `GET /api/proxies/{id}` - proxy details
- [x] `GET /api/auth-sessions` - list auth sessions
- [x] `GET /api/approvals/cached` - list cached approvals
- [x] `DELETE /api/approvals/cached` - clear all cached approvals
- [x] `DELETE /api/approvals/cached/entry` - delete single cached approval
- [x] `GET /api/approvals/pending` (SSE) - stream pending HITL requests
- [x] `POST /api/approvals/{id}/approve` - approve pending
- [x] `POST /api/approvals/{id}/deny` - deny pending

- [x] **Policy endpoints** (`api/routes/policy.py`)
  - [x] `GET /api/policy` - read policy with metadata
  - [x] `GET /api/policy/rules` - list rules
  - [x] `POST /api/policy/rules` - add rule (auto-reload)
  - [x] `PUT /api/policy/rules/{id}` - update rule (auto-reload)
  - [x] `DELETE /api/policy/rules/{id}` - delete rule (auto-reload)
- [x] **Auth endpoints** (`api/routes/auth.py`)
  - [x] `GET /api/auth/status` - auth status + user info + provider
  - [x] `POST /api/auth/login` - start device flow
  - [x] `GET /api/auth/login/poll` - poll for completion
  - [x] `POST /api/auth/logout` - local logout (keychain)
  - [x] `POST /api/auth/logout-federated` - federated logout URL
- [x] **Config endpoints** (`api/routes/config.py`)
  - [x] `GET /api/config` - read config (redacted)
  - [x] `PUT /api/config` - update config (validated, restart required)
- [x] **Log endpoints** (`api/routes/logs.py`)
  - [x] `GET /api/logs/decisions` - policy decisions
  - [x] `GET /api/logs/operations` - operation audit
  - [x] `GET /api/logs/auth` - auth events
  - [x] `GET /api/logs/system` - system logs

---

## Phase 4: HITL Integration

**Status: COMPLETE**

- [x] `ProxyState.create_pending()` - create pending approval
- [x] `ProxyState.resolve_pending()` - resolve with allow/deny
- [x] `ProxyState.get_pending_approvals()` - list pending
- [x] `ProxyState.subscribe()/unsubscribe()` - SSE tracking
- [x] `ProxyState.is_ui_connected` - check if UI connected
- [x] `ProxyState.wait_for_decision()` - async wait for resolution
- [x] SSE broadcast of pending/resolved/timeout events
- [x] Approval endpoints (approve/deny)

- [x] **HITL handler integration** (`pep/hitl.py`)
  - [x] `HITLHandler.set_proxy_state()` - wire ProxyState after creation
  - [x] `HITLHandler._request_approval_via_ui()` - web UI flow
  - [x] Check `is_ui_connected` before creating pending
  - [x] If UI connected: use `create_pending()` + `wait_for_decision()`
  - [x] If timeout or no UI: fall back to osascript
  - [x] Never show both simultaneously

**Deliverable**: Browser approvals work, osascript fallback when UI closed. ✓

---

## Phase 5: React UI

**Status: COMPLETE**

Full React UI with real-time data.

### Pages Implemented

- [x] **Proxies page** (`/`)
  - [x] Stats row with filter cards (All, Active, Inactive, Pending)
  - [x] Proxy grid showing all registered proxies
  - [x] Click proxy to navigate to detail page
  - [x] Pending approvals drawer (slide-in from right)

- [x] **Proxy detail page** (`/proxy/:id`)
  - [x] Breadcrumb navigation
  - [x] Sidebar with section navigation (Overview, Logs, Policy, Config)
  - [x] Stats section with metrics
  - [x] Approvals section (pending for this proxy)
  - [x] Activity section (recent decisions)

- [x] **Global logs page** (`/logs`)
  - [x] Page header matching Proxies page style
  - [x] Placeholder for log viewer (coming soon)

- [x] **Auth page** (`/auth`)
  - [x] Auth status display (authenticated/not authenticated)
  - [x] Provider info (Auth0, etc.)
  - [x] Storage backend info
  - [x] User details when authenticated (Subject ID, Email, Token Expires, Refresh Token)
  - [x] Login/Logout/Federated Logout actions

### Components Implemented

- [x] **Layout components**
  - [x] Header with nav links and auth dropdown
  - [x] Footer with version info
  - [x] Layout wrapper

- [x] **Auth dropdown** (in Header)
  - [x] Status indicator (green/red dot)
  - [x] Login dialog with device flow
  - [x] Logout and federated logout options
  - [x] Disabled states when not applicable

- [x] **Proxy components**
  - [x] StatsRow with filter cards
  - [x] ProxyGrid with proxy cards
  - [x] ProxyCard with status indicator
  - [x] PendingDrawer for approval queue

- [x] **Detail components**
  - [x] DetailSidebar with section navigation
  - [x] StatsSection with metrics
  - [x] ApprovalsSection with approve/deny
  - [x] ActivitySection with recent logs

- [x] **shadcn/ui components**
  - [x] Button, Card, Badge
  - [x] DropdownMenu
  - [x] Dialog
  - [x] Sheet (drawer)

### Hooks Implemented

- [x] `useProxies` - fetch proxy list
- [x] `usePendingApprovals` - SSE subscription for pending + approve/deny
- [x] `useLogs` - fetch log entries
- [x] `useAuth` - auth status + login/logout

### API Client

- [x] Base client with token injection
- [x] Proxy endpoints
- [x] Approval endpoints
- [x] Auth endpoints
- [x] Log endpoints

### Styling

- [x] Tailwind CSS with custom theme
- [x] OKLCH color palette from ui-aesthetics.md
- [x] Figtree (display), Nunito (text), JetBrains Mono (mono)
- [x] CSS variables for dynamic theming
- [x] Smooth transitions and hover effects

---

## Phase 6: Production Build

**Status: COMPLETE**

- [x] Vite build outputs to `src/mcp_acp_extended/web/static/`
- [x] FastAPI serves static files
- [x] SPA fallback for client-side routing
- [x] Token injection via server-side template
- [x] Auto-open browser on proxy start (if not already running)
- [x] `--no-ui` flag to disable auto-open

---

## Phase 7: Polish & Refinements

**Status: IN PROGRESS**

- [x] Clean Ctrl+C shutdown (no traceback spam)
- [x] Suppress uvicorn error logging on shutdown
- [x] Login dialog message matches Auth0 prompt
- [x] Federated logout disabled when not authenticated
- [x] Global Logs title font matches Proxies page
- [x] Stop/Restart buttons removed from proxy detail (Phase 2 feature)
- [x] Auth page shows provider info
- [ ] Log viewer implementation
- [ ] Policy editor implementation
- [ ] Config editor implementation
