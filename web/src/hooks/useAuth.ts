import { useState, useEffect, useCallback } from 'react'
import { toast } from '@/components/ui/sonner'
import {
  getAuthStatus,
  logout as apiLogout,
  logoutFederated as apiLogoutFederated,
  type AuthStatus,
} from '@/api/auth'
import { playErrorSound } from '@/hooks/useErrorSound'

interface UseAuthReturn {
  status: AuthStatus | null
  loading: boolean
  loggingOut: boolean
  error: string | null
  logout: () => Promise<void>
  logoutFederated: () => Promise<void>
  refresh: () => Promise<void>
}

export function useAuth(): UseAuthReturn {
  const [status, setStatus] = useState<AuthStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [loggingOut, setLoggingOut] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchStatus = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await getAuthStatus()
      setStatus(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get auth status')
      // Set unauthenticated on error
      setStatus({
        authenticated: false,
        subject_id: null,
        email: null,
        name: null,
        token_expires_in_hours: null,
        has_refresh_token: null,
        storage_backend: null,
        provider: null,
      })
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStatus()
  }, [fetchStatus])

  // Listen for SSE auth state changes (auth_login, auth_logout, token_refresh_failed)
  useEffect(() => {
    const handleAuthChange = () => {
      fetchStatus()
    }
    window.addEventListener('auth-state-changed', handleAuthChange)
    return () => {
      window.removeEventListener('auth-state-changed', handleAuthChange)
    }
  }, [fetchStatus])

  const logout = useCallback(async () => {
    try {
      setLoggingOut(true)
      setError(null)
      await apiLogout()
      await fetchStatus()
      toast.success('Logged out')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Logout failed')
      toast.error('Logout failed')
      playErrorSound()
    } finally {
      setLoggingOut(false)
    }
  }, [fetchStatus])

  const logoutFederated = useCallback(async () => {
    try {
      setLoggingOut(true)
      setError(null)
      const response = await apiLogoutFederated()
      // Open logout URL in new window/tab
      window.open(response.logout_url, '_blank')
      await fetchStatus()
      toast.success('Logged out')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Federated logout failed')
      toast.error('Logout failed')
      playErrorSound()
    } finally {
      setLoggingOut(false)
    }
  }, [fetchStatus])

  return {
    status,
    loading,
    loggingOut,
    error,
    logout,
    logoutFederated,
    refresh: fetchStatus,
  }
}
