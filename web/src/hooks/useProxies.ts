import { useState, useEffect, useCallback } from 'react'
import { getProxies, getProxyStatus } from '@/api/proxies'
import type { Proxy, ProxyStatus } from '@/types/api'

export function useProxies() {
  const [proxies, setProxies] = useState<Proxy[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchProxies = useCallback(async () => {
    try {
      setLoading(true)
      const data = await getProxies()
      setProxies(data)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to fetch proxies'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchProxies()
  }, [fetchProxies])

  return { proxies, loading, error, refetch: fetchProxies }
}

export function useProxyStatus() {
  const [status, setStatus] = useState<ProxyStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetchStatus = useCallback(async () => {
    try {
      setLoading(true)
      const data = await getProxyStatus()
      setStatus(data)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e : new Error('Failed to fetch status'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStatus()
  }, [fetchStatus])

  return { status, loading, error, refetch: fetchStatus }
}
