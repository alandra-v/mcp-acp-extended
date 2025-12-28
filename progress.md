# mcp-acp-extended Implementation Progress

## Stage 2: Zero Trust Authentication & Enhanced Context
Full Zero Trust authentication with OIDC, mTLS, device health checks, and enhanced context attributes.

**Design Document:** [docs/design/authentication_implementation.md](docs/design/authentication_implementation.md)

---

## Phase 1: Logging Infrastructure & Auth Audit

- [x] **1. Add startup validation for audit logs** *(existing)*
  - Check write permissions before proxy starts ✓
  - Verify directory structure exists (create if needed) ✓
  - ~~Validate file integrity for existing logs~~ *(skipped - only validates writability)*
  - Fail fast if audit logging cannot be guaranteed ✓

- [x] **2. Integrate AuditHealthMonitor properly**
  - Start monitor as background task on proxy startup ✓ (via FastMCP lifespan)
  - Register audit log paths (operations, decisions) ✓ *(auth.jsonl in Task #3)*
  - Clean shutdown: cancel task, await completion ✓
  - Handle monitor crash → trigger fail-closed shutdown ✓
  - Tested: file replacement detected within 30s ✓

- [ ] **3. Create auth audit logger**
  - New file: `src/mcp_acp_extended/pip/auth/auth_logger.py`
  - Log to `audit/auth.jsonl` with fail-closed handler
  - Events: `token_validated`, `token_invalid`, `session_started`, `session_ended`, `device_health_passed/failed`
  - Add `get_auth_log_path()` to config helpers

---

## Phase 2: Configuration Schema

- [ ] **4. Add auth configuration models**
  - New models in `config.py`: `OIDCConfig`, `MTLSConfig`, `DeviceHealthConfig`, `AuthConfig`
  - NO disable options - all Zero Trust features mandatory
  - Add `AuthenticationError`, `DeviceHealthError` to exceptions.py

- [ ] **5. Add new dependencies**
  - `pyproject.toml`: Add `PyJWT>=2.8.0`, `cryptography>=41.0.0`, `keyring>=24.0.0`

---

## Phase 3: Token Storage & JWT Validation

- [ ] **6. Implement token storage**
  - New file: `src/mcp_acp_extended/pip/auth/token_storage.py`
  - `KeychainStorage` (primary) using `keyring` library
  - `EncryptedFileStorage` (fallback) using Fernet
  - `StoredToken` model with access_token, refresh_token, expires_at

- [ ] **7. Implement JWT validator**
  - New file: `src/mcp_acp_extended/pip/auth/jwt_validator.py`
  - Validate JWT signature using JWKS from Auth0
  - Verify issuer, audience, expiration
  - Cache JWKS for performance

---

## Phase 4: Device Authorization Flow

- [ ] **8. Implement OAuth Device Flow (RFC 8628)**
  - New file: `src/mcp_acp_extended/pip/auth/device_flow.py`
  - Request device code from Auth0
  - Display user_code and verification_uri
  - Poll token endpoint until user completes authentication
  - Store tokens in Keychain

---

## Phase 5: OIDC Identity Provider

- [ ] **9. Implement OIDCIdentityProvider**
  - New file: `src/mcp_acp_extended/pip/auth/oidc_provider.py`
  - Implements `IdentityProvider` protocol
  - Load token from Keychain, validate per-request (60s cache)
  - Auto-refresh expired tokens
  - Extract claims → populate Subject with TOKEN provenance

- [ ] **10. Update identity provider factory**
  - Modify `security/identity.py`: `create_identity_provider()` returns OIDC provider when auth configured

---

## Phase 6: Device Health Checks

- [ ] **11. Implement device health checker**
  - New file: `src/mcp_acp_extended/pip/device/health.py`
  - Check disk encryption: FileVault (macOS), BitLocker (Windows), LUKS (Linux)
  - Check firewall: macOS Application Firewall, Windows Firewall
  - Platform-aware implementation using subprocess

---

## Phase 7: Session Management

- [ ] **12. Implement session binding**
  - New file: `src/mcp_acp_extended/pip/auth/session.py`
  - Cryptographically secure session IDs (`secrets.token_urlsafe(32)`)
  - Sessions bound to subject_id per MCP spec
  - Session format: `{user_id}:{session_id}`

---

## Phase 8: mTLS Transport

- [ ] **13. Add mTLS support to transport**
  - Modify `utils/transport.py`
  - Create SSL context with client cert, client key, CA bundle
  - Integrate with httpx for HTTP backends

---

## Phase 9: Integration

- [ ] **14. Integrate auth into proxy startup**
  - Modify `proxy.py`: Load token → validate → device health → create provider
  - Show osascript popup on auth failure (reuse HITL infrastructure)

- [ ] **15. Add auth CLI commands**
  - New file: `cli/commands/auth.py`
  - `auth login` - Device Flow, store token
  - `auth logout` - Clear stored tokens
  - `auth status` - Show token validity, user info

- [ ] **16. Update init command for auth config**
  - Modify `cli/commands/init.py`
  - Add prompts for Auth0 issuer, client_id, audience
  - Add prompts for mTLS certificate paths

- [ ] **17. Update start command**
  - Modify `cli/commands/start.py`
  - Check auth before starting proxy

---

## Phase 10: Testing & Documentation

- [ ] **18. Add unit tests**
  - `tests/pip/auth/test_device_flow.py`
  - `tests/pip/auth/test_jwt_validator.py`
  - `tests/pip/auth/test_token_storage.py`
  - `tests/pip/auth/test_oidc_provider.py`
  - `tests/pip/device/test_health.py`

- [ ] **19. Update documentation**
  - New `docs/authentication.md` - Complete auth setup guide
  - Update `docs/logging.md` - Add auth.jsonl documentation
  - Update `docs/configuration.md` - Auth config section
  - Update `docs/security.md` - Zero Trust authentication

- [ ] **20. E2E testing with Auth0**
  - Manual testing with real Auth0 tenant
  - Test full flow: init → auth login → start → use → token refresh
  - Document in `docs/manual-e2e-testing.md`

---

## Future Phases (Context Enhancements, Policy, Web UI)

These phases remain unchanged from original plan - see below.

---

## Phase 11: Context Enhancements

- [ ] **21. Implement approval context**
  - Populate `Approval` model in `context/approval.py`
  - Track HITL approvals: timestamp, scope, approver

- [ ] **22. Implement data inspection context**
  - Populate `DataInspection` model in `context/data.py`
  - Simple regex-based detection for secrets and PII patterns

- [ ] **23. Implement tool registry**
  - `ToolRegistry` class in `context/tool_registry.py`
  - Load side effects from `tool_registry.json`

- [ ] **24. Add environment context conditions**
  - Add `environment.mcp_client_name` as policy condition
  - Add `environment.timestamp` / time windows as conditions
  - Support time-based access restrictions

- [ ] **25. Enhance provenance tracking**
  - Add explicit `side_effects_confidence` field: `verified`, `mapped`, `guessed`, `unknown`
    | Confidence | Meaning                                 | Source                                |
    |------------|-----------------------------------------|---------------------------------------|
    | verified   | Cryptographically signed by tool author | Future: tool registry with signatures |
    | mapped     | Admin manually configured               | TOOL_SIDE_EFFECTS or registry file    |
    | guessed    | Inferred from tool name heuristics      | infer_operation()                     |
    | unknown    | No information available                | Tool not in any mapping               |
  - Make provenance conditionable in policies

---

## Phase 12: Policy Enhancements

- [ ] **26. Add list support for conditions (OR logic)**
  - Allow arrays in condition values (any match = pass)
  - No NOT logic (Zero Trust principle - explicit allow only)

- [ ] **27. Add trace/explanation to decision logs**
  - Log WHY a decision was made, not just which rule matched
  - Include evaluation trace showing condition checks

- [ ] **28. Add policy IDs with content hash**
  - Auto-generate policy ID from content hash
  - Enable policy versioning and change detection

- [ ] **29. Add subject-based policy conditions**
  - New conditions: issuer, audience, scopes, groups
  - Update `PolicyEngine._matches_rule()`

- [ ] **30. Add multiple path support for policies**
  - Support source and destination paths in single rule
  - Enable data flow policies (e.g., "from X to Y")

- [ ] **31. Add provenance-based policy conditions**
  - Condition on `side_effects_confidence` levels
  - Allow stricter policies for `guessed`/`unknown` provenance

- [ ] **32. Implement hot reload via SIGHUP**
  - Policy reload: Load, validate, atomic swap
  - Config reload (limited): hitl.timeout_seconds, logging.log_level

---

## Phase 13: CLI Enhancements

- [ ] **33. Add policy and config validate commands**
  - `mcp-acp-extended policy validate`
  - `mcp-acp-extended config validate`

- [ ] **34. Add config export command**
  - `mcp-acp-extended config export --claude` - Export Claude Desktop client config snippet

---

## Phase 14: Web UI (React + shadcn)

- [ ] **35. Set up FastAPI backend (embedded)**
  - FastAPI app in `api/server.py`
  - Health, logs, HITL, status endpoints

- [ ] **36. Set up React + Vite + shadcn project**
  - Dashboard, logs viewer, HITL queue, config view

- [ ] **37. Add UI start to CLI**
  - `mcp-acp-extended start --ui-port 8080`

---

## Stage 2 Completion Criteria

- [ ] Startup validation for audit logs (permissions, directory, integrity)
- [ ] AuditHealthMonitor integrated with proxy lifecycle
- [ ] Zero Trust authentication working with Auth0 (Device Flow)
- [ ] mTLS for HTTP backend connections
- [ ] Device health checks (disk encryption, firewall)
- [ ] Per-request token validation with caching
- [ ] Session binding to user identity
- [ ] Auth event audit logging (auth.jsonl)
- [ ] Subject claims available in policy conditions
- [ ] Policy conditions support OR logic (list values)
- [ ] Decision logs include trace/explanation (WHY not just WHAT)
- [ ] Policy IDs with content hash for versioning
- [ ] Environment conditions (mcp_client_name, time windows)
- [ ] Provenance-based policy conditions (side_effects_confidence)
- [ ] Multiple path support for data flow policies
- [ ] Hot reload for policy/config via SIGHUP
- [ ] React web UI for logs and HITL
- [ ] Documentation updated
- [ ] E2E testing complete
