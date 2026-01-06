// TypeScript types matching backend Pydantic models

export interface ProxyStats {
  requests_total: number
  requests_allowed: number
  requests_denied: number
  requests_hitl: number
}

export interface Proxy {
  id: string
  backend_id: string
  status: 'running' | 'stopped' | 'error'
  started_at: string
  pid: number
  api_port: number
  uptime_seconds: number
  command: string | null
  args: string[] | null
  url: string | null
  stats: ProxyStats
}

export interface PendingApproval {
  id: string
  proxy_id: string
  tool_name: string
  path: string | null
  subject_id: string
  created_at: string
  timeout_seconds: number
  request_id: string
  can_cache: boolean
  cache_ttl_seconds: number | null
}

export interface CachedApproval {
  subject_id: string
  tool_name: string
  path: string | null
  request_id: string
  age_seconds: number
  ttl_seconds: number
  expires_in_seconds: number
}

export interface CachedApprovalsResponse {
  count: number
  ttl_seconds: number
  approvals: CachedApproval[]
}

export interface ProxyStatus {
  running: boolean
  uptime_seconds: number
  policy_version: string | null
  policy_rules_count: number
  last_reload_at: string | null
  reload_count: number
}

export interface LogEntry {
  timestamp: string
  [key: string]: unknown
}

export interface LogsResponse {
  entries: LogEntry[]
  total_returned: number
  log_file: string
  has_more: boolean
}

// Severity levels for toast styling
export type EventSeverity = 'success' | 'warning' | 'error' | 'critical' | 'info'

// Base fields for system events
interface SSESystemEventBase {
  severity?: EventSeverity
  message?: string
  details?: string
  proxy_id?: string
  timestamp?: string
  error_type?: string
}

// HITL Approval Events (discriminated union)
export interface SSESnapshotEvent {
  type: 'snapshot'
  approvals: PendingApproval[]
}

export interface SSEPendingCreatedEvent {
  type: 'pending_created'
  approval: PendingApproval
}

export interface SSEPendingResolvedEvent {
  type: 'pending_resolved'
  approval_id: string
  decision: 'allow' | 'deny'
}

export interface SSEPendingTimeoutEvent {
  type: 'pending_timeout'
  approval_id: string
}

export interface SSEPendingNotFoundEvent extends SSESystemEventBase {
  type: 'pending_not_found'
  approval_id?: string
}

// Policy Events
export interface SSEPolicyReloadedEvent extends SSESystemEventBase {
  type: 'policy_reloaded'
  old_rules_count?: number
  new_rules_count?: number
  approvals_cleared?: number
  policy_version?: string
}

export interface SSEPolicyRollbackEvent extends SSESystemEventBase {
  type: 'policy_rollback'
}

export interface SSEPolicyErrorEvent extends SSESystemEventBase {
  type: 'policy_reload_failed' | 'policy_file_not_found' | 'config_change_detected'
}

// Rate Limiting Events
export interface SSERateLimitEvent extends SSESystemEventBase {
  type: 'rate_limit_triggered' | 'rate_limit_approved' | 'rate_limit_denied'
  tool_name?: string
  count?: number
  threshold?: number
}

// Cache Events
export interface SSECacheEvent extends SSESystemEventBase {
  type: 'cache_cleared' | 'cache_entry_deleted'
  count?: number
}

// Backend Connection Events
export interface SSEBackendEvent extends SSESystemEventBase {
  type: 'backend_connected' | 'backend_reconnected' | 'backend_disconnected' | 'backend_timeout' | 'backend_refused'
  method?: string
}

// TLS Events
export interface SSETLSEvent extends SSESystemEventBase {
  type: 'tls_error' | 'mtls_failed' | 'cert_validation_failed'
}

// Auth Events
export interface SSEAuthEvent extends SSESystemEventBase {
  type: 'auth_login' | 'auth_logout' | 'auth_session_expiring' | 'token_refresh_failed' | 'token_validation_failed' | 'auth_failure'
}

// Request Processing Events
export interface SSERequestEvent extends SSESystemEventBase {
  type: 'request_error' | 'hitl_parse_failed' | 'tool_sanitization_failed'
}

// Critical Events
export interface SSECriticalEvent extends SSESystemEventBase {
  type: 'critical_shutdown' | 'audit_init_failed' | 'device_health_failed' | 'session_hijacking' | 'audit_tampering' | 'audit_missing' | 'audit_permission_denied' | 'health_degraded' | 'health_monitor_failed'
}

// Live Update Events
export interface SSEStatsUpdatedEvent extends SSESystemEventBase {
  type: 'stats_updated'
  stats: ProxyStats
}

export interface SSENewLogEntriesEvent extends SSESystemEventBase {
  type: 'new_log_entries'
  count?: number
}

// Discriminated union of all SSE event types
export type SSEEvent =
  | SSESnapshotEvent
  | SSEPendingCreatedEvent
  | SSEPendingResolvedEvent
  | SSEPendingTimeoutEvent
  | SSEPendingNotFoundEvent
  | SSEPolicyReloadedEvent
  | SSEPolicyRollbackEvent
  | SSEPolicyErrorEvent
  | SSERateLimitEvent
  | SSECacheEvent
  | SSEBackendEvent
  | SSETLSEvent
  | SSEAuthEvent
  | SSERequestEvent
  | SSECriticalEvent
  | SSEStatsUpdatedEvent
  | SSENewLogEntriesEvent

// Type helper to extract event type strings
export type SSEEventType = SSEEvent['type']

// API Error
export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    message?: string
  ) {
    super(message || `API Error: ${status} ${statusText}`)
    this.name = 'ApiError'
  }
}
