/**
 * Unit tests for usePendingApprovals hook.
 *
 * Tests SSE subscription, approval actions, and state management.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { usePendingApprovals } from '@/hooks/usePendingApprovals'
import * as approvalsApi from '@/api/approvals'
import type { PendingApproval, SSEEvent } from '@/types/api'

// Mock the API module
vi.mock('@/api/approvals', () => ({
  subscribeToPendingApprovals: vi.fn(),
  approveRequest: vi.fn(),
  approveOnceRequest: vi.fn(),
  denyRequest: vi.fn(),
}))

// Mock notification sound
vi.mock('@/hooks/useNotificationSound', () => ({
  playApprovalChime: vi.fn(),
}))

describe('usePendingApprovals', () => {
  const mockApproval: PendingApproval = {
    id: 'approval-123',
    proxy_id: 'proxy-1',
    tool_name: 'read_file',
    path: '/project/file.txt',
    subject_id: 'user@example.com',
    created_at: '2024-01-01T12:00:00Z',
    timeout_seconds: 30,
    request_id: 'req-456',
    can_cache: true,
    cache_ttl_seconds: 3600,
  }

  let mockEventSource: {
    onmessage: ((event: MessageEvent) => void) | null
    onerror: ((event: Event) => void) | null
    close: ReturnType<typeof vi.fn>
  }
  let sseHandler: (event: SSEEvent) => void
  let sseErrorHandler: ((error: Event) => void) | undefined

  beforeEach(() => {
    vi.clearAllMocks()

    mockEventSource = {
      onmessage: null,
      onerror: null,
      close: vi.fn(),
    }

    // Capture the handlers passed to subscribeToPendingApprovals
    vi.mocked(approvalsApi.subscribeToPendingApprovals).mockImplementation((handler, errorHandler) => {
      sseHandler = handler
      sseErrorHandler = errorHandler
      return mockEventSource as unknown as EventSource
    })
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('SSE subscription', () => {
    it('subscribes to pending approvals on mount', () => {
      renderHook(() => usePendingApprovals())

      expect(approvalsApi.subscribeToPendingApprovals).toHaveBeenCalledTimes(1)
      expect(approvalsApi.subscribeToPendingApprovals).toHaveBeenCalledWith(
        expect.any(Function),
        expect.any(Function)
      )
    })

    it('closes EventSource on unmount', () => {
      const { unmount } = renderHook(() => usePendingApprovals())

      unmount()

      expect(mockEventSource.close).toHaveBeenCalled()
    })

    it('handles snapshot event', async () => {
      const { result } = renderHook(() => usePendingApprovals())

      act(() => {
        sseHandler({
          type: 'snapshot',
          approvals: [mockApproval],
        })
      })

      expect(result.current.pending).toEqual([mockApproval])
      expect(result.current.connected).toBe(true)
    })

    it('handles pending_created event', async () => {
      const { playApprovalChime } = await import('@/hooks/useNotificationSound')

      const { result } = renderHook(() => usePendingApprovals())

      // First send snapshot
      act(() => {
        sseHandler({
          type: 'snapshot',
          approvals: [],
        })
      })

      // Then create new approval
      act(() => {
        sseHandler({
          type: 'pending_created',
          approval: mockApproval,
        })
      })

      expect(result.current.pending).toEqual([mockApproval])
      expect(playApprovalChime).toHaveBeenCalled()
    })

    it('handles pending_resolved event', async () => {
      const { result } = renderHook(() => usePendingApprovals())

      // Send snapshot with approval
      act(() => {
        sseHandler({
          type: 'snapshot',
          approvals: [mockApproval],
        })
      })

      expect(result.current.pending).toHaveLength(1)

      // Resolve the approval
      act(() => {
        sseHandler({
          type: 'pending_resolved',
          approval_id: 'approval-123',
          decision: 'allow',
        })
      })

      expect(result.current.pending).toHaveLength(0)
    })

    it('handles pending_timeout event', async () => {
      const { result } = renderHook(() => usePendingApprovals())

      // Send snapshot with approval
      act(() => {
        sseHandler({
          type: 'snapshot',
          approvals: [mockApproval],
        })
      })

      // Timeout the approval
      act(() => {
        sseHandler({
          type: 'pending_timeout',
          approval_id: 'approval-123',
        })
      })

      expect(result.current.pending).toHaveLength(0)
    })

    it('handles SSE connection error', async () => {
      const { result } = renderHook(() => usePendingApprovals())

      act(() => {
        sseErrorHandler?.(new Event('error'))
      })

      expect(result.current.connected).toBe(false)
      expect(result.current.error).toEqual(new Error('SSE connection lost'))
    })
  })

  describe('document title', () => {
    it('updates document title when pending count changes', async () => {
      renderHook(() => usePendingApprovals())

      // Initially no pending
      expect(document.title).toBe('MCP ACP')

      // Add approval
      act(() => {
        sseHandler({
          type: 'snapshot',
          approvals: [mockApproval],
        })
      })

      expect(document.title).toContain('(1)')

      // Add another
      act(() => {
        sseHandler({
          type: 'pending_created',
          approval: { ...mockApproval, id: 'approval-456' },
        })
      })

      expect(document.title).toContain('(2)')

      // Remove all
      act(() => {
        sseHandler({ type: 'pending_resolved', approval_id: 'approval-123', decision: 'allow' })
        sseHandler({ type: 'pending_resolved', approval_id: 'approval-456', decision: 'deny' })
      })

      expect(document.title).toBe('MCP ACP')
    })
  })

  describe('approve', () => {
    it('calls approveRequest API', async () => {
      vi.mocked(approvalsApi.approveRequest).mockResolvedValue({ status: 'approved', approval_id: 'approval-123' })

      const { result } = renderHook(() => usePendingApprovals())

      await act(async () => {
        await result.current.approve('approval-123')
      })

      expect(approvalsApi.approveRequest).toHaveBeenCalledWith('approval-123')
    })

    it('sets error on approve failure', async () => {
      vi.mocked(approvalsApi.approveRequest).mockRejectedValue(new Error('Approval failed'))

      const { result } = renderHook(() => usePendingApprovals())

      await act(async () => {
        await result.current.approve('approval-123')
      })

      expect(result.current.error?.message).toBe('Approval failed')
    })

    it('handles non-Error rejection', async () => {
      vi.mocked(approvalsApi.approveRequest).mockRejectedValue('Unknown error')

      const { result } = renderHook(() => usePendingApprovals())

      await act(async () => {
        await result.current.approve('approval-123')
      })

      expect(result.current.error?.message).toBe('Failed to approve')
    })
  })

  describe('approveOnce', () => {
    it('calls approveOnceRequest API', async () => {
      vi.mocked(approvalsApi.approveOnceRequest).mockResolvedValue({
        status: 'allowed_once',
        approval_id: 'approval-123',
      })

      const { result } = renderHook(() => usePendingApprovals())

      await act(async () => {
        await result.current.approveOnce('approval-123')
      })

      expect(approvalsApi.approveOnceRequest).toHaveBeenCalledWith('approval-123')
    })

    it('sets error on approveOnce failure', async () => {
      vi.mocked(approvalsApi.approveOnceRequest).mockRejectedValue(new Error('Failed'))

      const { result } = renderHook(() => usePendingApprovals())

      await act(async () => {
        await result.current.approveOnce('approval-123')
      })

      expect(result.current.error).toBeTruthy()
    })
  })

  describe('deny', () => {
    it('calls denyRequest API', async () => {
      vi.mocked(approvalsApi.denyRequest).mockResolvedValue({ status: 'denied', approval_id: 'approval-123' })

      const { result } = renderHook(() => usePendingApprovals())

      await act(async () => {
        await result.current.deny('approval-123')
      })

      expect(approvalsApi.denyRequest).toHaveBeenCalledWith('approval-123')
    })

    it('sets error on deny failure', async () => {
      vi.mocked(approvalsApi.denyRequest).mockRejectedValue(new Error('Deny failed'))

      const { result } = renderHook(() => usePendingApprovals())

      await act(async () => {
        await result.current.deny('approval-123')
      })

      expect(result.current.error?.message).toBe('Deny failed')
    })
  })

  describe('return values', () => {
    it('returns all expected properties', () => {
      const { result } = renderHook(() => usePendingApprovals())

      expect(result.current).toHaveProperty('pending')
      expect(result.current).toHaveProperty('connected')
      expect(result.current).toHaveProperty('error')
      expect(result.current).toHaveProperty('approve')
      expect(result.current).toHaveProperty('approveOnce')
      expect(result.current).toHaveProperty('deny')
    })

    it('initially returns empty pending array', () => {
      const { result } = renderHook(() => usePendingApprovals())

      expect(result.current.pending).toEqual([])
      expect(result.current.connected).toBe(false)
      expect(result.current.error).toBeNull()
    })
  })
})
