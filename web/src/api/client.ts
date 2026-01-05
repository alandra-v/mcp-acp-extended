import { ApiError } from '@/types/api'

const API_BASE = '/api'

// Token is injected by server into index.html as window.__API_TOKEN__
// In dev mode with Vite proxy, same-origin requests don't need token
declare global {
  interface Window {
    __API_TOKEN__?: string
  }
}

function getAuthHeaders(): HeadersInit {
  const headers: HeadersInit = {}
  const token = window.__API_TOKEN__
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  return headers
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: getAuthHeaders(),
  })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText, await res.text())
  }
  return res.json()
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const headers: HeadersInit = {
    ...getAuthHeaders(),
    ...(body ? { 'Content-Type': 'application/json' } : {}),
  }
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText, await res.text())
  }
  return res.json()
}

export async function apiPut<T>(path: string, body?: unknown): Promise<T> {
  const headers: HeadersInit = {
    ...getAuthHeaders(),
    ...(body ? { 'Content-Type': 'application/json' } : {}),
  }
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'PUT',
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText, await res.text())
  }
  return res.json()
}

export async function apiDelete<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText, await res.text())
  }
  return res.json()
}

// SSE connection for pending approvals
// EventSource doesn't support custom headers, so we pass token as query param
// In production (same-origin), the security middleware allows SSE without token
// In dev mode (cross-origin via Vite proxy), we need the token query param
export function createSSEConnection<T = unknown>(
  path: string,
  onMessage: (data: T) => void,
  onError?: (error: Event) => void
): EventSource {
  let url = `${API_BASE}${path}`

  // Add token as query param for cross-origin dev mode
  // The security middleware accepts ?token= for SSE endpoints
  const token = window.__API_TOKEN__
  if (token) {
    const separator = url.includes('?') ? '&' : '?'
    url = `${url}${separator}token=${encodeURIComponent(token)}`
  }

  const es = new EventSource(url)

  es.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      onMessage(data)
    } catch (e) {
      console.error('Failed to parse SSE message:', e)
    }
  }

  es.onerror = (error) => {
    console.error('SSE error:', error)
    onError?.(error)
  }

  return es
}
