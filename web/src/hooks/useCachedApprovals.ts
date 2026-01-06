import { useState, useEffect, useCallback, useRef } from 'react'
import { toast } from '@/components/ui/sonner'
import { getCachedApprovals, clearCachedApprovals, deleteCachedApproval } from '@/api/approvals'
import { playErrorSound } from '@/hooks/useErrorSound'
import type { CachedApproval } from '@/types/api'

interface UseCachedApprovalsReturn {
  cached: CachedApproval[]
  ttlSeconds: number
  loading: boolean
  error: Error | null
  clear: () => Promise<void>
  deleteEntry: (subjectId: string, toolName: string, path: string | null) => Promise<void>
  refresh: () => Promise<void>
}

export function useCachedApprovals(): UseCachedApprovalsReturn {
  const [cached, setCached] = useState<CachedApproval[]>([])
  const [ttlSeconds, setTtlSeconds] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const mountedRef = useRef(true)

  const fetchCached = useCallback(async () => {
    try {
      setLoading(true)
      const data = await getCachedApprovals()
      // Only update state if still mounted
      if (mountedRef.current) {
        setCached(data.approvals)
        setTtlSeconds(data.ttl_seconds)
        setError(null)
      }
    } catch (e) {
      if (mountedRef.current) {
        setError(e instanceof Error ? e : new Error('Failed to fetch cached approvals'))
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false)
      }
    }
  }, [])

  const clear = useCallback(async () => {
    try {
      await clearCachedApprovals()
      if (mountedRef.current) {
        setCached([])
      }
      // Note: Success toast comes from SSE event (cache_cleared)
    } catch (e) {
      if (mountedRef.current) {
        setError(e instanceof Error ? e : new Error('Failed to clear cache'))
      }
      toast.error('Failed to clear cache')
      playErrorSound()
    }
  }, [])

  const deleteEntry = useCallback(async (subjectId: string, toolName: string, path: string | null) => {
    try {
      await deleteCachedApproval(subjectId, toolName, path)
      if (mountedRef.current) {
        setCached((prev) => prev.filter(
          (c) => !(c.subject_id === subjectId && c.tool_name === toolName && c.path === path)
        ))
      }
      // Note: Success toast comes from SSE event (cache_entry_deleted)
    } catch (e) {
      if (mountedRef.current) {
        setError(e instanceof Error ? e : new Error('Failed to delete cached approval'))
      }
      toast.error('Failed to delete cached approval')
      playErrorSound()
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    fetchCached()

    // Refresh every 10 seconds
    const interval = setInterval(fetchCached, 10000)
    return () => {
      mountedRef.current = false
      clearInterval(interval)
    }
  }, [fetchCached])

  return { cached, ttlSeconds, loading, error, clear, deleteEntry, refresh: fetchCached }
}
