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
  - [x] ApprovalsSection with approve/deny/approveOnce
  - [x] CachedSection with cached approvals and clear
  - [x] ActivitySection with recent logs

- [x] **Error handling**
  - [x] ErrorBoundary wrapping entire app
  - [x] Inline error banners in pages (ProxiesPage, AuthPage)

- [x] **shadcn/ui components**
  - [x] Button, Card, Badge
  - [x] DropdownMenu
  - [x] Dialog
  - [x] Sheet (drawer)

### Context Providers

- [x] `PendingApprovalsContext` - global SSE subscription, pending state, title updates
  - Single SSE connection shared across all pages
  - Document title shows `🔴 (N) MCP ACP` when pending > 0
  - Audio chime notification on new pending approval
  - approve/approveOnce/deny actions

### Hooks Implemented

- [x] `useProxies` - fetch proxy list with error state
- [x] `usePendingApprovals` - (legacy, use context instead)
- [x] `useLogs` - fetch log entries by type
- [x] `useAuth` - auth status + login/logout/refresh + SSE state sync
- [x] `useCachedApprovals` - polling for cached approvals with TTL
- [x] `useDeviceFlow` - OAuth device flow for login dialog
- [x] `useNotificationSound` - Web Audio API approval chime
- [x] `useErrorSound` - Web Audio API error sound for critical events

### API Client

- [x] Base client with token injection (captured once, cleared from window)
- [x] Fetch with exponential backoff retry
- [x] SSE subscription helper with token query param for dev mode
- [x] JSON parsing error handling
- [x] Proxy endpoints
- [x] Approval endpoints (approve, approveOnce, deny)
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

**Status: COMPLETE**

- [x] Clean Ctrl+C shutdown (no traceback spam)
- [x] Suppress uvicorn error logging on shutdown
- [x] Login dialog message matches Auth0 prompt
- [x] Federated logout disabled when not authenticated
- [x] Global Logs title font matches Proxies page
- [x] Stop/Restart buttons removed from proxy detail (Phase 2 feature)
- [x] Auth page shows provider info
- [x] Favicon with correct permissions
- [x] Dynamic static file serving (no server restart needed after rebuild)

---

## Phase 8: Robustness & Code Quality

**Status: COMPLETE**

- [x] **Error handling**
  - [x] ErrorBoundary catches React errors gracefully
  - [x] Inline error banners in ProxiesPage and AuthPage
  - [x] API client wraps JSON parsing in try/catch

- [x] **Memory safety**
  - [x] `useCachedApprovals` uses `mountedRef` to prevent state updates after unmount
  - [x] Proper cleanup in useEffect hooks

- [x] **State management**
  - [x] `PendingApprovalsContext` for global pending state
  - [x] Single SSE connection across all pages
  - [x] Document title updates globally

- [x] **List rendering**
  - [x] Stable keys using `request_id` in CachedSection
  - [x] Improved keys in ActivitySection

- [x] **Audio resources**
  - [x] `closeAudioContext()` function for cleanup

---

## Phase 9: Real-time Notifications & SSE System Events

**Status: COMPLETE**

Comprehensive toast notifications and SSE event handling for all system events.

- [x] **Sonner toast integration** (`components/ui/sonner.tsx`)
  - [x] Replaced console logging with user-visible toasts
  - [x] Severity-based styling (info, success, warning, error, critical)
  - [x] Critical events persist until dismissed (`duration: Infinity`)
  - [x] Error sound plays on error/critical events

- [x] **SSE system events** (`PendingApprovalsContext`)
  - [x] Backend connection events (connected, reconnected, disconnected, timeout, refused)
  - [x] TLS/mTLS events (tls_error, mtls_failed, cert_validation_failed)
  - [x] Auth events (auth_login, auth_logout, session_expiring, token_refresh_failed)
  - [x] Policy events (policy_reloaded, policy_reload_failed, policy_rollback)
  - [x] Rate limiting events (rate_limit_triggered, approved, denied)
  - [x] Cache events (cache_cleared, cache_entry_deleted)
  - [x] Critical events (critical_shutdown, audit failures, device health, session hijacking)
  - [x] Default messages for all event types

- [x] **Auth state sync via SSE**
  - [x] `useAuth` listens for `auth-state-changed` custom event
  - [x] Auto-refresh auth status on login/logout/token_refresh_failed
  - [x] Success toasts handled by SSE events (no duplicates from API calls)

- [x] **Error sound** (`hooks/useErrorSound.ts`)
  - [x] Web Audio API generated error sound
  - [x] Plays on error and critical severity events
  - [x] Separate from approval chime

- [x] **Toast spam prevention**
  - [x] `errorCountRef` tracks connection errors, shows toast only on first error
  - [x] `isShutdownRef` prevents reconnection attempts after proxy shutdown
  - [x] Graceful handling when proxy goes offline (no spam on repeated failures)

- [x] **Individual cached approval deletion**
  - [x] Delete button on each cached approval in CachedSection
  - [x] `DELETE /api/approvals/cached/entry` endpoint
  - [x] SSE `cache_entry_deleted` event broadcast

---

## Future Work

### Error Handling & Resilience

- [x] ~~**Background data fetch errors**~~ (Completed in Phase 9)
  - [x] ~~Retry with backoff for failed proxy/session fetches~~
  - [x] ~~Visual indicator when data is stale~~
  - [x] ~~Reconnection logic for SSE disconnects~~

- [x] ~~**Proxy shutdown scenarios**~~ (Completed in Phase 9)
  - [x] ~~Graceful handling when proxy goes offline~~
  - [x] ~~Clear UI state when proxy unavailable~~
  - [x] ~~Reconnection when proxy comes back~~

- [x] ~~**Health checks**~~ (Completed in Phase 9)
  - [x] ~~health check error toasts~~
  - [x] ~~Warning when proxy unreachable~~

- [x] ~~**Log display in UI**~~ (Completed in Phase 9)
  - [x] ~~Toast or banner for critical errors~~

### Pages & Features

- [ ] **Global Logs page** (`/logs`)
  - [ ] Log type tabs (decisions, operations, auth, system)
  - [ ] Filtering and maybesearch
  - [ ] Virtual scroll for large logs
  - [ ] Live streaming option

- [ ] **Proxies page stats**
  - [ ] Request counts (today, all-time)
  - [ ] Latency metrics

- [ ] **Proxy detail - Overview**
  - [ ] Recent activity with full log details
  - [ ] Click-to-expand log entries
  - [ ] Real-time updates

- [ ] **Proxy detail - Stats**
  - [ ] Request volume charts
  - [ ] Latency distribution?

- [ ] **Proxy detail - Logs**
  - [ ] Full log viewer for this proxy
  - [ ] Filter by type, time range , request id or session id, event type

- [ ] **Proxy detail - Config**
  - [ ] View current configuration
  - [ ] Edit configuration (with validation)
  - [ ] Restart required indicator

- [ ] **Proxy detail - Policy**
  - [ ] View policy rules
  - [ ] Add/edit/delete rules
  - [ ] Policy validation
  - [ ] Auto-reload on save?
