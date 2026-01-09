import { useState, useEffect, useCallback, useRef } from 'react'
import { getConfig, updateConfig, ConfigResponse, ConfigUpdateRequest } from '@/api/config'
import { toast } from '@/components/ui/sonner'

export interface UseConfigResult {
  config: ConfigResponse | null
  loading: boolean
  saving: boolean
  error: string | null
  save: (updates: ConfigUpdateRequest) => Promise<boolean>
  refresh: () => Promise<void>
}

/**
 * Hook for fetching and updating proxy configuration.
 *
 * Returns:
 * - config: The current configuration (null while loading)
 * - loading: True while fetching config
 * - saving: True while saving updates
 * - error: Error message if fetch failed
 * - save: Function to save updates (returns true on success)
 * - refresh: Function to re-fetch config
 */
export function useConfig(): UseConfigResult {
  const [config, setConfig] = useState<ConfigResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const mountedRef = useRef(true)

  const fetchConfig = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await getConfig()
      if (mountedRef.current) {
        setConfig(data)
      }
    } catch (e) {
      if (mountedRef.current) {
        const msg = e instanceof Error ? e.message : 'Failed to load config'
        setError(msg)
        toast.error(msg)
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false)
      }
    }
  }, [])

  const save = useCallback(async (updates: ConfigUpdateRequest): Promise<boolean> => {
    setSaving(true)
    try {
      const result = await updateConfig(updates)
      if (mountedRef.current) {
        setConfig(result.config)
        toast.success(result.message)
      }
      return true
    } catch (e) {
      if (mountedRef.current) {
        // Try to extract error detail from API response
        let msg = 'Failed to save config'
        if (e instanceof Error) {
          // API errors include the detail in the message
          msg = e.message
        }
        toast.error(msg)
      }
      return false
    } finally {
      if (mountedRef.current) {
        setSaving(false)
      }
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    fetchConfig()
    return () => {
      mountedRef.current = false
    }
  }, [fetchConfig])

  return {
    config,
    loading,
    saving,
    error,
    save,
    refresh: fetchConfig,
  }
}
