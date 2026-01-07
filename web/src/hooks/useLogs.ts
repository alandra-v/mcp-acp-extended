import { useState, useEffect, useCallback, useRef } from 'react'
import { getLogs, type LogType, type LogFilters } from '@/api/logs'
import { toast } from '@/components/ui/sonner'
import type { LogEntry } from '@/types/api'

export interface UseLogsResult {
  logs: LogEntry[]
  loading: boolean
  hasMore: boolean
  totalScanned: number
  loadMore: () => void
  refresh: () => void
}

/**
 * Hook for fetching and paginating logs with filtering support.
 * Uses cursor-based pagination with the `before` parameter.
 */
export function useLogs(
  type: LogType,
  filters: Omit<LogFilters, 'before' | 'limit'> = {},
  pageSize = 50
): UseLogsResult {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [hasMore, setHasMore] = useState(false)
  const [totalScanned, setTotalScanned] = useState(0)

  // Track the oldest timestamp for cursor pagination
  const cursorRef = useRef<string | undefined>(undefined)

  // Serialize filters for dependency comparison
  const filtersKey = JSON.stringify(filters)

  const fetchLogs = useCallback(async (reset = false) => {
    try {
      setLoading(true)

      const before = reset ? undefined : cursorRef.current
      const data = await getLogs(type, {
        ...filters,
        limit: pageSize,
        before,
      })

      if (reset) {
        setLogs(data.entries)
      } else {
        setLogs((prev) => [...prev, ...data.entries])
      }

      // Update cursor to oldest entry's timestamp for next page
      if (data.entries.length > 0) {
        const oldestEntry = data.entries[data.entries.length - 1]
        cursorRef.current = oldestEntry.time || oldestEntry.timestamp
      }

      setHasMore(data.has_more)
      setTotalScanned((prev) => reset ? data.total_scanned : prev + data.total_scanned)
    } catch (e) {
      const err = e instanceof Error ? e : new Error('Failed to fetch logs')

      // Show toast for log loading failures
      // Check for 404 on debug logs (not available unless DEBUG level)
      const isDebugLog = type === 'client_wire' || type === 'backend_wire'
      const is404 = err.message.includes('404') || err.message.includes('not found')

      if (isDebugLog && is404) {
        toast.warning('Debug logs not available. Set log_level to DEBUG in config.')
      } else {
        toast.error('Failed to load logs')
      }
    } finally {
      setLoading(false)
    }
  }, [type, filtersKey, pageSize]) // eslint-disable-line react-hooks/exhaustive-deps

  // Reset and fetch when type or filters change
  useEffect(() => {
    cursorRef.current = undefined
    setTotalScanned(0)
    fetchLogs(true)
  }, [type, filtersKey, fetchLogs]) // eslint-disable-line react-hooks/exhaustive-deps

  // Listen for SSE new-log-entries event to auto-refresh
  useEffect(() => {
    const handleNewLogEntries = () => {
      cursorRef.current = undefined
      fetchLogs(true)
    }
    window.addEventListener('new-log-entries', handleNewLogEntries)
    return () => {
      window.removeEventListener('new-log-entries', handleNewLogEntries)
    }
  }, [fetchLogs])

  const loadMore = useCallback(() => {
    if (!loading && hasMore) {
      fetchLogs(false)
    }
  }, [loading, hasMore, fetchLogs])

  const refresh = useCallback(() => {
    cursorRef.current = undefined
    setTotalScanned(0)
    fetchLogs(true)
  }, [fetchLogs])

  return { logs, loading, hasMore, totalScanned, loadMore, refresh }
}
