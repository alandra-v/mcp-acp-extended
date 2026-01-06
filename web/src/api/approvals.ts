import { apiGet, apiPost, apiDelete, createSSEConnection } from './client'
import type {
  PendingApproval,
  CachedApprovalsResponse,
  SSEEvent
} from '@/types/api'

// Pending approvals
export async function getPendingApprovals(): Promise<PendingApproval[]> {
  return apiGet<PendingApproval[]>('/approvals/pending/list')
}

export function subscribeToPendingApprovals(
  onEvent: (event: SSEEvent) => void,
  onError?: (error: Event) => void
): EventSource {
  return createSSEConnection<SSEEvent>('/approvals/pending', onEvent, onError)
}

export async function approveRequest(id: string): Promise<{ status: string; approval_id: string }> {
  return apiPost(`/approvals/pending/${id}/approve`)
}

export async function approveOnceRequest(id: string): Promise<{ status: string; approval_id: string }> {
  return apiPost(`/approvals/pending/${id}/allow-once`)
}

export async function denyRequest(id: string): Promise<{ status: string; approval_id: string }> {
  return apiPost(`/approvals/pending/${id}/deny`)
}

// Cached approvals
export async function getCachedApprovals(): Promise<CachedApprovalsResponse> {
  return apiGet<CachedApprovalsResponse>('/approvals/cached')
}

export async function clearCachedApprovals(): Promise<{ cleared: number; status: string }> {
  return apiDelete('/approvals/cached')
}
