import { ApiError } from '@/types/api'

const API_BASE = '/api'

// Retry configuration
const MAX_RETRIES = 3
const INITIAL_DELAY_MS = 1000

// Token is injected by server into index.html as window.__API_TOKEN__
// In dev mode with Vite proxy, same-origin requests don't need token
declare global {
  interface Window {
    __API_TOKEN__?: string
  }
}

// Capture token once and clear from window to minimize XSS exposure window.
// The token is validated server-side to be hex-only before injection.
const API_TOKEN = window.__API_TOKEN__
if (window.__API_TOKEN__) {
  delete window.__API_TOKEN__
}

function getAuthHeaders(): HeadersInit {
  const headers: HeadersInit = {}
  if (API_TOKEN) {
    headers['Authorization'] = `Bearer ${API_TOKEN}`
  }
  return headers
}

/**
 * Sleep for the specified number of milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Check if an error is retryable (network error or 5xx server error).
 */
function isRetryable(error: unknown): boolean {
  // Network errors (fetch throws)
  if (error instanceof TypeError) return true
  // Server errors (5xx)
  if (error instanceof ApiError && error.status >= 500) return true
  return false
}

/**
 * Options for API requests with optional abort signal.
 */
export interface RequestOptions {
  /** AbortSignal to cancel the request */
  signal?: AbortSignal
}

/**
 * Fetch with exponential backoff retry for transient failures.
 * Only retries on network errors and 5xx server errors.
 * Respects AbortSignal to cancel requests.
 */
async function fetchWithRetry(
  url: string,
  options: RequestInit,
  retries = MAX_RETRIES
): Promise<Response> {
  let lastError: unknown

  for (let attempt = 0; attempt < retries; attempt++) {
    // Check if request was aborted before attempting
    if (options.signal?.aborted) {
      throw new DOMException('Request aborted', 'AbortError')
    }

    try {
      const res = await fetch(url, options)

      // Don't retry client errors (4xx)
      if (res.ok || (res.status >= 400 && res.status < 500)) {
        return res
      }

      // Server error (5xx) - will retry
      const error = new ApiError(res.status, res.statusText, await res.text())
      lastError = error

      if (attempt < retries - 1 && isRetryable(error)) {
        const delay = INITIAL_DELAY_MS * Math.pow(2, attempt)
        console.warn(`Request failed (${res.status}), retrying in ${delay}ms...`)
        await sleep(delay)
        continue
      }

      throw error
    } catch (error) {
      // Don't retry if request was aborted
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw error
      }

      lastError = error

      // Network error - retry with backoff
      if (attempt < retries - 1 && isRetryable(error)) {
        const delay = INITIAL_DELAY_MS * Math.pow(2, attempt)
        console.warn(`Network error, retrying in ${delay}ms...`)
        await sleep(delay)
        continue
      }

      throw error
    }
  }

  throw lastError
}

export async function apiGet<T>(path: string, options?: RequestOptions): Promise<T> {
  const res = await fetchWithRetry(`${API_BASE}${path}`, {
    headers: getAuthHeaders(),
    signal: options?.signal,
  })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText, await res.text())
  }
  try {
    return await res.json()
  } catch {
    throw new ApiError(res.status, 'Invalid JSON', 'Server returned invalid JSON response')
  }
}

export async function apiPost<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
  const headers: HeadersInit = {
    ...getAuthHeaders(),
    ...(body ? { 'Content-Type': 'application/json' } : {}),
  }
  const res = await fetchWithRetry(`${API_BASE}${path}`, {
    method: 'POST',
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal: options?.signal,
  })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText, await res.text())
  }
  try {
    return await res.json()
  } catch {
    throw new ApiError(res.status, 'Invalid JSON', 'Server returned invalid JSON response')
  }
}

export async function apiPut<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
  const headers: HeadersInit = {
    ...getAuthHeaders(),
    ...(body ? { 'Content-Type': 'application/json' } : {}),
  }
  const res = await fetchWithRetry(`${API_BASE}${path}`, {
    method: 'PUT',
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal: options?.signal,
  })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText, await res.text())
  }
  try {
    return await res.json()
  } catch {
    throw new ApiError(res.status, 'Invalid JSON', 'Server returned invalid JSON response')
  }
}

export async function apiDelete<T>(path: string, options?: RequestOptions): Promise<T> {
  const res = await fetchWithRetry(`${API_BASE}${path}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
    signal: options?.signal,
  })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText, await res.text())
  }
  try {
    return await res.json()
  } catch {
    throw new ApiError(res.status, 'Invalid JSON', 'Server returned invalid JSON response')
  }
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
  if (API_TOKEN) {
    const separator = url.includes('?') ? '&' : '?'
    url = `${url}${separator}token=${encodeURIComponent(API_TOKEN)}`
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
