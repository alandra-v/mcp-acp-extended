// TypeScript types matching backend Pydantic models

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

// SSE Event types
export type SSEEventType =
  // Existing HITL events
  | 'snapshot'
  | 'pending_created'
  | 'pending_resolved'
  | 'pending_timeout'
  | 'pending_not_found'
  // Backend connection
  | 'backend_connected'
  | 'backend_reconnected'
  | 'backend_disconnected'
  | 'backend_timeout'
  | 'backend_refused'
  // TLS/mTLS
  | 'tls_error'
  | 'mtls_failed'
  | 'cert_validation_failed'
  // Authentication
  | 'auth_login'
  | 'auth_logout'
  | 'auth_session_expiring'
  | 'token_refresh_failed'
  | 'token_validation_failed'
  | 'auth_failure'
  // Policy
  | 'policy_reloaded'
  | 'policy_reload_failed'
  | 'policy_file_not_found'
  | 'policy_rollback'
  | 'config_change_detected'
  // Rate limiting
  | 'rate_limit_triggered'
  | 'rate_limit_approved'
  | 'rate_limit_denied'
  // Cache
  | 'cache_cleared'
  | 'cache_entry_deleted'
  // Request processing
  | 'request_error'
  | 'hitl_parse_failed'
  | 'tool_sanitization_failed'
  // Critical events (proxy shutdown)
  | 'critical_shutdown'
  | 'audit_init_failed'
  | 'device_health_failed'
  | 'session_hijacking'
  | 'audit_tampering'
  | 'audit_missing'
  | 'audit_permission_denied'
  | 'health_degraded'
  | 'health_monitor_failed'

// Severity levels for toast styling
export type EventSeverity = 'success' | 'warning' | 'error' | 'critical' | 'info'

export interface SSEEvent {
  type: SSEEventType
  // HITL-specific fields
  approvals?: PendingApproval[]
  approval?: PendingApproval
  approval_id?: string
  decision?: 'allow' | 'deny'
  // System event fields
  severity?: EventSeverity
  message?: string
  details?: string
  proxy_id?: string
  timestamp?: string
  // Policy events
  old_rules_count?: number
  new_rules_count?: number
  approvals_cleared?: number
  policy_version?: string
  error_type?: string
  count?: number
}

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
