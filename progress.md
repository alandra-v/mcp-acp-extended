# mcp-acp-extended Implementation Progress

## Stage 2: OIDC Authentication & Enhanced Context
Single user with OIDC identity, single server, enhanced context attributes, basic web UI

---

## Phase 1: OIDC Authentication Setup

- [ ] **1. Configure Auth0 for development**
  - Create Auth0 tenant and application (Regular Web Application)
  - Configure callback URL: `http://localhost:8000/auth/callback`
  - Set up API audience for token validation
  - Document config_url, client_id, client_secret, audience

- [ ] **2. Integrate FastMCP Auth0Provider**
  - Use built-in `Auth0Provider` from `fastmcp.server.auth.providers.auth0`
  - New `OIDCConfig` model in `config.py`: config_url, client_id, client_secret, audience, base_url
  - Conditional auth setup in `proxy.py`: pass `auth=Auth0Provider(...)` to FastMCP
  - Fallback to no auth when OIDC not configured (Stage 1 behavior)

- [ ] **3. Implement OIDCIdentityProvider**
  - New provider in `security/auth/providers/oidc_provider.py`
  - Implements existing `IdentityProvider` protocol
  - Extract claims from FastMCP's validated token context: sub, iss, aud, scope, iat, groups
  - No manual token validation needed (FastMCP handles JWKS, expiry, signature)

- [ ] **4. Update Subject model for OIDC claims**
  - Extend `Subject` in `context/subject.py`: issuer, audience, scopes, groups, token_age_s
  - Update `build_decision_context()` to populate from `OIDCIdentityProvider`
  - Backwards compatible (all new fields optional)

- [ ] **5. Update CLI init for OIDC configuration**
  - New `--auth` flag: `none` (default) | `oidc`
  - Interactive prompts for OIDC settings when selected
  - Non-interactive flags: `--oidc-config-url`, `--oidc-client-id`, etc.
  - `config show` displays OIDC configuration (secrets masked)


## Phase 2: Context Enhancements

- [ ] **6. Implement approval context**
  - Populate `Approval` model in `context/approval.py`
  - Track HITL approvals in `HITLHandler`: timestamp, scope, approver
  - **Stage 2 scope**: Track approvals, don't use for policy yet
  - **Deferred**: Approval expiry, step-up auth policies

- [ ] **7. Implement data inspection context**
  - Populate `DataInspection` model in `context/data.py`
  - Simple regex-based detection for secrets and PII patterns
  - **Stage 2 scope**: Detection and logging only, no policy blocking
  - **Deferred**: Advanced detection libraries, policy conditions

- [ ] **8. Implement tool registry**
  - `ToolRegistry` class in `context/tool_registry.py`
  - Load side effects from `tool_registry.json` (user-configurable)
  - Fallback to built-in `TOOL_SIDE_EFFECTS` if file missing
  - Glob pattern support for tool names


## Phase 3: Policy Enhancements

- [ ] **9. Add subject-based policy conditions**
  - New conditions in `pdp/policy.py`: issuer, audience, scopes, groups
  - `scopes`/`groups` use ANY logic (user has at least one)
  - Update `PolicyEngine._matches_rule()` to evaluate subject conditions

- [ ] **10. Implement hot reload via SIGHUP**
  - Add `SIGHUP` handler in `proxy.py`
  - **Policy reload**: Load, validate, atomic swap
  - **Config reload (limited)**: Only `hitl.timeout_seconds`, `logging.log_level`
  - **Not reloadable**: backend.*, logging.log_dir, oidc.* (log warning)
  - Keep old config/policy on validation failure


## Phase 4: CLI Enhancements

- [ ] **11. Add policy validate command**
  - `mcp-acp-extended policy validate [--file PATH]`
  - Validates policy.json against Pydantic schema
  - Exit code 0 on valid, 1 on invalid

- [ ] **12. Add config/policy diff commands**
  - `mcp-acp-extended config show --diff` - diff from last loaded version
  - `mcp-acp-extended policy show --diff` - same for policy

- [ ] **13. Add reload command**
  - `mcp-acp-extended reload` - sends SIGHUP to running proxy
  - Update `start` command to write pidfile

## Phase 5: Logging Enhancements

- [ ] **14. Add OIDC claims to audit logs**
  - Update `OperationEvent`: `subject_issuer`, `subject_groups`
  - Update `DecisionEvent`: same fields in context_summary
  - Add auth.jsonl for authentication events

- [ ] **15. Add data inspection flags to audit logs**
  - Update `OperationEvent`: `contains_secrets_suspected`, `contains_pii_suspected`

- [ ] **16. Implement log rotation awareness**
  - Detect when log file is rotated (inode change)
  - Graceful handling: reopen file, continue logging
  - Distinguish rotation vs deletion (don't trigger fail-closed for rotation)

## Phase 6: Web UI (React + shadcn)

- [ ] **17. Set up FastAPI backend (embedded)**
  - FastAPI app in `api/server.py`, mounted on proxy process
  - CORS configuration for React dev server (localhost:5173)
  - Health endpoint: `GET /api/health`
  - Serve static files from `web/dist/` in production
  - **Deferred**: OIDC authentication for API endpoints

- [ ] **18. Implement log viewer API**
  - `GET /api/logs/operations`, `/decisions`, `/system` - paginated
  - Query params: `limit`, `offset`, `start_time`, `end_time`

- [ ] **19. Implement HITL queue API**
  - `GET /api/hitl/pending` - list pending approval requests
  - `POST /api/hitl/{request_id}/approve` and `/deny`
  - WebSocket: `WS /api/hitl/stream` - real-time updates
  - **Note**: Requires refactoring HITLHandler for web-based approval

- [ ] **20. Implement status API**
  - `GET /api/status` - proxy status, uptime, backend connection
  - `GET /api/config` - current config (secrets masked)
  - `GET /api/policy` - current policy

- [ ] **21. Set up React + Vite + shadcn project**
  - Initialize `web/` with Vite React TypeScript template
  - Install and configure Tailwind CSS
  - Install shadcn/ui and add base components (Button, Card, Table, Dialog)
  - Set up Vite proxy for `/api` during development
  - Configure production build output to `web/dist/`

- [ ] **22. Implement React pages**
  - Dashboard: Proxy status, recent activity summary
  - Logs viewer: Filterable log table with auto-refresh
  - HITL queue: Pending approvals with approve/deny buttons
  - Config view: Read-only config/policy display
  - Use React Query for API data fetching

- [ ] **23. Add UI start to CLI**
  - `mcp-acp-extended start --ui-port 8080`
  - Default: UI enabled
  - Serves `web/dist/` static files via FastAPI

## Phase 7: Testing & Documentationms extraction, policy evaluation

- [ ] **24. E2E testing with Auth0**
  - Manual testing with real Auth0 tenant
  - Test with MCP Inspector and Claude Desktop
  - Document in `docs/manual-e2e-testing.md`

- [ ] **25. Update documentation**
  - Update `docs/configuration.md`, `docs/policies.md`, `docs/security.md`
  - New `docs/authentication.md` for OIDC setup guide
  - New `docs/web-ui.md` for UI usage and development

---

## Stage 2 Completion Criteria

- [ ] OIDC authentication working with Auth0
- [ ] Subject claims available in policy conditions
- [ ] Hot reload for policy/config via SIGHUP
- [ ] Approval and data inspection context tracked
- [ ] Tool registry configurable via file
- [ ] Policy validate CLI command
- [ ] React web UI for logs and HITL
- [ ] Documentation updated
- [ ] E2E testing with Auth0 complete
