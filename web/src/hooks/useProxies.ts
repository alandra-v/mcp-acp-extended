import { useState, useEffect, useCallback, useRef } from 'react'
import { getProxies } from '@/api/proxies'
import { toast } from '@/components/ui/sonner'
import type { Proxy } from '@/types/api'

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
