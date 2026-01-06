import { createContext, useContext, useState, useEffect, useCallback, useRef, type ReactNode } from 'react'
import { toast } from 'sonner'
import { subscribeToPendingApprovals, approveRequest, approveOnceRequest, denyRequest } from '@/api/approvals'
import { playApprovalChime } from '@/hooks/useNotificationSound'
import { playErrorSound } from '@/hooks/useErrorSound'
import type { PendingApproval, SSEEvent } from '@/types/api'

const ORIGINAL_TITLE = 'MCP ACP'

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
      toast.error('Failed to approve request')
      playErrorSound()
    }
  }, [])

  const approveOnce = useCallback(async (id: string) => {
    try {
      await approveOnceRequest(id)
      toast.success('Request approved (once)')
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to approve once'))
      toast.error('Failed to approve request')
      playErrorSound()
    }
  }, [])

  const deny = useCallback(async (id: string) => {
    try {
      await denyRequest(id)
      toast.success('Request denied')
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to deny'))
      toast.error('Failed to deny request')
      playErrorSound()
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
