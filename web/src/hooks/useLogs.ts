import { useState, useEffect, useCallback, useRef } from 'react'
import { getLogs, type LogType } from '@/api/logs'
import type { LogEntry } from '@/types/api'

export function useLogs(type: LogType, initialLimit = 50) {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const [hasMore, setHasMore] = useState(false)

  // Use ref for offset to avoid stale closure issues
  const offsetRef = useRef(0)

  const fetchLogs = useCallback(async (reset = false) => {
    try {
      setLoading(true)
      const currentOffset = reset ? 0 : offsetRef.current
      const data = await getLogs(type, initialLimit, currentOffset)

      if (reset) {
        setLogs(data.entries)
        offsetRef.current = initialLimit
      } else {
        setLogs((prev) => [...prev, ...data.entries])
        offsetRef.current += initialLimit
      }

      setHasMore(data.has_more)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to fetch logs'))
    } finally {
      setLoading(false)
    }
  }, [type, initialLimit])

  useEffect(() => {
    offsetRef.current = 0
    fetchLogs(true)
  }, [type, fetchLogs])

  const loadMore = useCallback(() => {
    if (!loading && hasMore) {
      fetchLogs(false)
    }
  }, [loading, hasMore, fetchLogs])

  const refresh = useCallback(() => {
    fetchLogs(true)
  }, [fetchLogs])

  return { logs, loading, error, hasMore, loadMore, refresh }
}
