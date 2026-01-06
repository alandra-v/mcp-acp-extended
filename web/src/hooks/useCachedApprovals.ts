import { useState, useEffect, useCallback, useRef } from 'react'
import { getCachedApprovals, clearCachedApprovals } from '@/api/approvals'
import type { CachedApproval } from '@/types/api'

interface UseCachedApprovalsReturn {
  cached: CachedApproval[]
  ttlSeconds: number
  loading: boolean
  error: Error | null
  clear: () => Promise<void>
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
    } catch (e) {
      if (mountedRef.current) {
        setError(e instanceof Error ? e : new Error('Failed to clear cache'))
      }
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

  return { cached, ttlSeconds, loading, error, clear, refresh: fetchCached }
}
