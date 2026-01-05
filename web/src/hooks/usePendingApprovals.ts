import { useState, useEffect, useCallback } from 'react'
import { subscribeToPendingApprovals, approveRequest, denyRequest } from '@/api/approvals'
import type { PendingApproval, SSEEvent } from '@/types/api'

export function usePendingApprovals() {
  const [pending, setPending] = useState<PendingApproval[]>([])
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    const handleEvent = (event: SSEEvent) => {
      switch (event.type) {
        case 'snapshot':
          setPending(event.approvals || [])
          setConnected(true)
          break
        case 'pending_created':
          if (event.approval) {
            setPending((prev) => [...prev, event.approval!])
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
      // Will be removed via SSE event
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to approve'))
    }
  }, [])

  const deny = useCallback(async (id: string) => {
    try {
      await denyRequest(id)
      // Will be removed via SSE event
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to deny'))
    }
  }, [])

  return { pending, connected, error, approve, deny }
}
