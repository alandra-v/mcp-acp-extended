### Authentication events

The authentication log schema records Zero Trust authentication events for the proxy. Each entry captures token validation outcomes, session lifecycle events, and device health check results. Based on OCSF Authentication (3002) and Authorize Session (3003) classes, adapted for MCP. By correlating each event with the session and identity, the auth log enables security auditing, compliance verification, and forensic analysis.

## Core
time — ISO 8601 timestamp (added by formatter during serialization)
event_type — "token_validated" | "token_invalid" | "token_refreshed" | "token_refresh_failed" | "session_started" | "session_ended" | "device_health_passed" | "device_health_failed"
status — "Success" | "Failure"

## Correlation
session_id — optional, MCP session ID (may not exist during startup)
request_id — optional, JSON-RPC request ID (for per-request token validation)

## Identity
subject — optional SubjectIdentity object (null if token couldn't be parsed)
subject.subject_id — OIDC 'sub' claim
subject.subject_claims — optional dict of selected safe claims (e.g. preferred_username, email)

## OIDC/OAuth details
oidc — optional OIDCInfo object
oidc.issuer — OIDC 'iss' claim (e.g. "https://your-tenant.auth0.com")
oidc.provider — optional friendly name (e.g. "google", "auth0")
oidc.client_id — optional upstream client_id
oidc.audience — optional list of audiences
oidc.scopes — optional list of granted scopes
oidc.token_type — optional, "access" | "id" | "proxy"
oidc.token_exp — optional ISO 8601 expiration time
oidc.token_iat — optional ISO 8601 issued-at time
oidc.token_expired — optional boolean, whether token was expired at validation

## Device health (for device_health_passed/failed events)
device_checks — optional DeviceHealthChecks object
device_checks.disk_encryption — "pass" | "fail" | "unknown" (FileVault on macOS)
device_checks.device_integrity — "pass" | "fail" | "unknown" (SIP enabled on macOS)

Result meanings:
- pass: Check succeeded, device is compliant
- fail: Check succeeded, device is NOT compliant
- unknown: Could not determine status (treated as unhealthy for Zero Trust)

## Context
method — optional MCP method (for per-request validation)
message — optional human-readable status message

## Errors (for failure events)
error_type — optional error class name (e.g. "TokenExpiredError", "InvalidSignatureError")
error_message — optional detailed error message

## Session end (for session_ended event)
end_reason — optional, "normal" | "timeout" | "error" | "auth_expired"

## Extra details
details — optional dict of additional structured data
