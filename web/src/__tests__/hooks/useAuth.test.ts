/**
 * Unit tests for useAuth hook.
 *
 * Tests authentication state management, logout, and refresh.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useAuth } from '@/hooks/useAuth'
import * as authApi from '@/api/auth'

// Mock the API module
vi.mock('@/api/auth', () => ({
  getAuthStatus: vi.fn(),
  logout: vi.fn(),
  logoutFederated: vi.fn(),
}))

// Mock toast
vi.mock('@/components/ui/sonner', () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
  },
}))

// Mock error sound
vi.mock('@/hooks/useErrorSound', () => ({
  playErrorSound: vi.fn(),
}))

describe('useAuth', () => {
  const mockAuthStatus: authApi.AuthStatus = {
    authenticated: true,
    subject_id: 'user-123',
    email: 'user@example.com',
    name: 'Test User',
    token_expires_in_hours: 24,
    has_refresh_token: true,
    storage_backend: 'file',
    provider: 'auth0',
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('initial fetch', () => {
    it('fetches auth status on mount', async () => {
      vi.mocked(authApi.getAuthStatus).mockResolvedValue(mockAuthStatus)

      const { result } = renderHook(() => useAuth())

      expect(result.current.loading).toBe(true)

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(authApi.getAuthStatus).toHaveBeenCalledTimes(1)
      expect(result.current.status).toEqual(mockAuthStatus)
    })

    it('sets unauthenticated status on error', async () => {
      vi.mocked(authApi.getAuthStatus).mockRejectedValue(new Error('Network error'))

      const { result } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.status?.authenticated).toBe(false)
      expect(result.current.error).toBe('Network error')
    })

    it('sets generic error message for non-Error objects', async () => {
      vi.mocked(authApi.getAuthStatus).mockRejectedValue('Unknown error')

      const { result } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.error).toBe('Failed to get auth status')
    })
  })

  describe('logout', () => {
    it('calls logout API and refreshes status', async () => {
      vi.mocked(authApi.getAuthStatus).mockResolvedValue(mockAuthStatus)
      vi.mocked(authApi.logout).mockResolvedValue({ status: 'ok', message: 'Logged out' })

      const { result } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      await act(async () => {
        await result.current.logout()
      })

      expect(authApi.logout).toHaveBeenCalled()
      expect(authApi.getAuthStatus).toHaveBeenCalledTimes(2) // Initial + after logout
    })

    it('sets loggingOut state during logout', async () => {
      vi.mocked(authApi.getAuthStatus).mockResolvedValue(mockAuthStatus)
      vi.mocked(authApi.logout).mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve({ status: 'ok', message: '' }), 100))
      )

      const { result } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      let logoutPromise: Promise<void>
      act(() => {
        logoutPromise = result.current.logout()
      })

      expect(result.current.loggingOut).toBe(true)

      await act(async () => {
        await logoutPromise
      })

      expect(result.current.loggingOut).toBe(false)
    })

    it('sets error on logout failure', async () => {
      const { toast } = await import('@/components/ui/sonner')
      const { playErrorSound } = await import('@/hooks/useErrorSound')

      vi.mocked(authApi.getAuthStatus).mockResolvedValue(mockAuthStatus)
      vi.mocked(authApi.logout).mockRejectedValue(new Error('Logout failed'))

      const { result } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      await act(async () => {
        await result.current.logout()
      })

      expect(result.current.error).toBe('Logout failed')
      expect(toast.error).toHaveBeenCalledWith('Logout failed')
      expect(playErrorSound).toHaveBeenCalled()
    })
  })

  describe('logoutFederated', () => {
    it('calls federated logout API and opens logout URL', async () => {
      vi.mocked(authApi.getAuthStatus).mockResolvedValue(mockAuthStatus)
      vi.mocked(authApi.logoutFederated).mockResolvedValue({
        status: 'ok',
        logout_url: 'https://auth.example.com/logout',
        message: 'Redirecting...',
      })

      const { result } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      await act(async () => {
        await result.current.logoutFederated()
      })

      expect(authApi.logoutFederated).toHaveBeenCalled()
      expect(window.open).toHaveBeenCalledWith('https://auth.example.com/logout', '_blank')
    })

    it('sets error on federated logout failure', async () => {
      const { toast } = await import('@/components/ui/sonner')

      vi.mocked(authApi.getAuthStatus).mockResolvedValue(mockAuthStatus)
      vi.mocked(authApi.logoutFederated).mockRejectedValue(new Error('Provider error'))

      const { result } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      await act(async () => {
        await result.current.logoutFederated()
      })

      expect(result.current.error).toBe('Provider error')
      expect(toast.error).toHaveBeenCalledWith('Logout failed')
    })
  })

  describe('refresh', () => {
    it('refetches auth status when refresh is called', async () => {
      vi.mocked(authApi.getAuthStatus).mockResolvedValue(mockAuthStatus)

      const { result } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(authApi.getAuthStatus).toHaveBeenCalledTimes(1)

      await act(async () => {
        await result.current.refresh()
      })

      expect(authApi.getAuthStatus).toHaveBeenCalledTimes(2)
    })

    it('clears previous error on refresh', async () => {
      vi.mocked(authApi.getAuthStatus)
        .mockRejectedValueOnce(new Error('First error'))
        .mockResolvedValueOnce(mockAuthStatus)

      const { result } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(result.current.error).toBe('First error')
      })

      await act(async () => {
        await result.current.refresh()
      })

      expect(result.current.error).toBeNull()
      expect(result.current.status).toEqual(mockAuthStatus)
    })
  })

  describe('event listener', () => {
    it('refreshes on auth-state-changed event', async () => {
      vi.mocked(authApi.getAuthStatus).mockResolvedValue(mockAuthStatus)

      renderHook(() => useAuth())

      await waitFor(() => {
        expect(authApi.getAuthStatus).toHaveBeenCalledTimes(1)
      })

      // Dispatch auth state change event
      act(() => {
        window.dispatchEvent(new Event('auth-state-changed'))
      })

      await waitFor(() => {
        expect(authApi.getAuthStatus).toHaveBeenCalledTimes(2)
      })
    })

    it('removes event listener on unmount', async () => {
      vi.mocked(authApi.getAuthStatus).mockResolvedValue(mockAuthStatus)

      const removeEventListenerSpy = vi.spyOn(window, 'removeEventListener')

      const { unmount } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(authApi.getAuthStatus).toHaveBeenCalled()
      })

      unmount()

      expect(removeEventListenerSpy).toHaveBeenCalledWith('auth-state-changed', expect.any(Function))
    })
  })

  describe('return values', () => {
    it('returns all expected properties', async () => {
      vi.mocked(authApi.getAuthStatus).mockResolvedValue(mockAuthStatus)

      const { result } = renderHook(() => useAuth())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current).toHaveProperty('status')
      expect(result.current).toHaveProperty('loading')
      expect(result.current).toHaveProperty('loggingOut')
      expect(result.current).toHaveProperty('error')
      expect(result.current).toHaveProperty('logout')
      expect(result.current).toHaveProperty('logoutFederated')
      expect(result.current).toHaveProperty('refresh')
    })
  })
})
