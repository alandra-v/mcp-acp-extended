import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react'
import { subscribeToPendingApprovals, approveRequest, approveOnceRequest, denyRequest } from '@/api/approvals'
import { toast } from '@/components/ui/sonner'
import { playApprovalChime } from '@/hooks/useNotificationSound'
import { playErrorSound } from '@/hooks/useErrorSound'
import type { PendingApproval, SSEEvent, SSEEventType } from '@/types/api'

const ORIGINAL_TITLE = 'MCP ACP'

// Default messages for system events
const DEFAULT_MESSAGES: Partial<Record<SSEEventType, string>> = {
  // Backend connection
  backend_connected: 'Backend connected',
  backend_reconnected: 'Backend reconnected',
  backend_disconnected: 'Backend connection lost',
  backend_timeout: 'Backend connection timeout',
  backend_refused: 'Backend connection refused',
  // TLS/mTLS
  tls_error: 'SSL/TLS certificate error',
  mtls_failed: 'mTLS handshake failed',
  cert_validation_failed: 'Server certificate validation failed',
  // Authentication
  auth_session_expiring: 'Session expiring soon',
  token_refresh_failed: 'Session expired',
  token_validation_failed: 'Token validation failed',
  auth_failure: 'Authentication failed',
  // Policy
  policy_reloaded: 'Policy reloaded',
  policy_reload_failed: 'Policy reload failed',
  policy_file_not_found: 'Policy file not found',
  policy_rollback: 'Policy rolled back',
  config_change_detected: 'Config change detected',
  // Rate limiting
  rate_limit_triggered: 'Rate limit exceeded',
  rate_limit_approved: 'Rate limit breach approved',
  rate_limit_denied: 'Rate limit breach denied',
  // Cache
  cache_cleared: 'Approval cache cleared',
  cache_entry_deleted: 'Cached approval deleted',
  // Request processing
  request_error: 'Request processing error',
  hitl_parse_failed: 'HITL request parse failed',
  tool_sanitization_failed: 'Tool sanitization failed',
  pending_not_found: 'Approval not found (may have timed out)',
  // Critical events
  critical_shutdown: 'Proxy shutting down',
  audit_init_failed: 'Audit log initialization failed',
  device_health_failed: 'Device health check failed',
  session_hijacking: 'Session binding violation detected',
  audit_tampering: 'Audit log tampering detected',
  audit_missing: 'Audit log file missing',
  audit_permission_denied: 'Audit log permission denied',
  health_degraded: 'Device health degraded',
  health_monitor_failed: 'Health monitor failed',
}

function showSystemToast(event: SSEEvent) {
  const message = event.message || DEFAULT_MESSAGES[event.type] || event.type
  const severity = event.severity || 'info'

  switch (severity) {
    case 'success':
      toast.success(message)
      break
    case 'warning':
      toast.warning(message)
      break
    case 'error':
      toast.error(message)
      playErrorSound()
      break
    case 'critical':
      // Critical events don't auto-dismiss and play error sound
      toast.error(message, { duration: Infinity })
      playErrorSound()
      break
    case 'info':
    default:
      toast.info(message)
  }
}

interface PendingApprovalsContextValue {
  pending: PendingApproval[]
  connected: boolean
  error: Error | null
  approve: (id: string) => Promise<void>
  approveOnce: (id: string) => Promise<void>
  deny: (id: string) => Promise<void>
}

const PendingApprovalsContext = createContext<PendingApprovalsContextValue | null>(null)

export function PendingApprovalsProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingApproval[]>([])
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  // Update document title when pending count changes
  useEffect(() => {
    if (pending.length > 0) {
      document.title = `🔴 (${pending.length}) ${ORIGINAL_TITLE}`
    } else {
      document.title = ORIGINAL_TITLE
    }
  }, [pending.length])

  useEffect(() => {
    const handleEvent = (event: SSEEvent) => {
      switch (event.type) {
        // HITL-specific events
        case 'snapshot':
          setPending(event.approvals || [])
          setConnected(true)
          break
        case 'pending_created':
          if (event.approval) {
            setPending((prev) => [...prev, event.approval!])
            playApprovalChime()
          }
          break
        case 'pending_resolved':
          if (event.approval_id) {
            setPending((prev) => prev.filter((p) => p.id !== event.approval_id))
          }
          break
        case 'pending_timeout':
          if (event.approval_id) {
            setPending((prev) => prev.filter((p) => p.id !== event.approval_id))
            toast.warning('Approval request timed out')
          }
          break

        // System events with severity - show toast
        default:
          if (event.severity) {
            showSystemToast(event)
          }
          break
      }
    }

    const handleError = () => {
      setConnected(false)
      setError(new Error('SSE connection lost'))
      toast.error('Connection lost')
      playErrorSound()
    }

    const es = subscribeToPendingApprovals(handleEvent, handleError)

    return () => {
      es.close()
    }
  }, [])

  const approve = useCallback(async (id: string) => {
    try {
      await approveRequest(id)
      toast.success('Request approved')
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to approve'))
      // Error toast handled via SSE pending_not_found event
    }
  }, [])

  const approveOnce = useCallback(async (id: string) => {
    try {
      await approveOnceRequest(id)
      toast.success('Request approved (once)')
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to approve once'))
      // Error toast handled via SSE pending_not_found event
    }
  }, [])

  const deny = useCallback(async (id: string) => {
    try {
      await denyRequest(id)
      toast.success('Request denied')
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to deny'))
      // Error toast handled via SSE pending_not_found event
    }
  }, [])

  return (
    <PendingApprovalsContext.Provider value={{ pending, connected, error, approve, approveOnce, deny }}>
      {children}
    </PendingApprovalsContext.Provider>
  )
}

export function usePendingApprovalsContext() {
  const context = useContext(PendingApprovalsContext)
  if (!context) {
    throw new Error('usePendingApprovalsContext must be used within PendingApprovalsProvider')
  }
  return context
}
