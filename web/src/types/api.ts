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
  | 'snapshot'
  | 'pending_created'
  | 'pending_resolved'
  | 'pending_timeout'

export interface SSEEvent {
  type: SSEEventType
  approvals?: PendingApproval[]
  approval?: PendingApproval
  approval_id?: string
  decision?: 'allow' | 'deny'
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
