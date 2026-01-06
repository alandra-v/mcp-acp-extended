import { createContext, useContext, useState, useEffect, useCallback, useRef, type ReactNode } from 'react'
import { subscribeToPendingApprovals, approveRequest, denyRequest } from '@/api/approvals'
import { playApprovalChime } from '@/hooks/useNotificationSound'
import type { PendingApproval, SSEEvent } from '@/types/api'

const ORIGINAL_TITLE = 'MCP ACP'

interface PendingApprovalsContextValue {
  pending: PendingApproval[]
  connected: boolean
  error: Error | null
  approve: (id: string) => Promise<void>
  deny: (id: string) => Promise<void>
}

const PendingApprovalsContext = createContext<PendingApprovalsContextValue | null>(null)

export function PendingApprovalsProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingApproval[]>([])
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const isFirstSnapshot = useRef(true)

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
        case 'snapshot':
          setPending(event.approvals || [])
          setConnected(true)
          isFirstSnapshot.current = false
          break
        case 'pending_created':
          if (event.approval) {
            setPending((prev) => [...prev, event.approval!])
            playApprovalChime()
          }
          break
        case 'pending_resolved':
        case 'pending_timeout':
          if (event.approval_id) {
            setPending((prev) => prev.filter((p) => p.id !== event.approval_id))
          }
          break
      }
    }

    const handleError = () => {
      setConnected(false)
      setError(new Error('SSE connection lost'))
    }

    const es = subscribeToPendingApprovals(handleEvent, handleError)

    return () => {
      es.close()
    }
  }, [])

  const approve = useCallback(async (id: string) => {
    try {
      await approveRequest(id)
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to approve'))
    }
  }, [])

  const deny = useCallback(async (id: string) => {
    try {
      await denyRequest(id)
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to deny'))
    }
  }, [])

  return (
    <PendingApprovalsContext.Provider value={{ pending, connected, error, approve, deny }}>
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
