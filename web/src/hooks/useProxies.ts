import { useState, useEffect, useCallback, useRef } from 'react'
import { getProxies, getProxyStatus } from '@/api/proxies'
import { toast } from '@/components/ui/sonner'
import type { Proxy, ProxyStatus } from '@/types/api'

export interface UseProxiesResult {
  proxies: Proxy[]
  loading: boolean
  refetch: () => Promise<void>
}

export function useProxies(): UseProxiesResult {
  const [proxies, setProxies] = useState<Proxy[]>([])
  const [loading, setLoading] = useState(true)
  const hasShownErrorRef = useRef(false)

  const fetchProxies = useCallback(async () => {
    try {
      setLoading(true)
      const data = await getProxies()
      setProxies(data)
      hasShownErrorRef.current = false
    } catch {
      if (!hasShownErrorRef.current) {
        toast.error('Failed to load proxies')
        hasShownErrorRef.current = true
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchProxies()
  }, [fetchProxies])

  return { proxies, loading, refetch: fetchProxies }
}

export interface UseProxyStatusResult {
  status: ProxyStatus | null
  loading: boolean
  refetch: () => Promise<void>
}

export function useProxyStatus(): UseProxyStatusResult {
  const [status, setStatus] = useState<ProxyStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const hasShownErrorRef = useRef(false)

  const fetchStatus = useCallback(async () => {
    try {
      setLoading(true)
      const data = await getProxyStatus()
      setStatus(data)
      hasShownErrorRef.current = false
    } catch {
      if (!hasShownErrorRef.current) {
        toast.error('Failed to load proxy status')
        hasShownErrorRef.current = true
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStatus()
  }, [fetchStatus])

  return { status, loading, refetch: fetchStatus }
}
