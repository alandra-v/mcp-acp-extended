import { apiGet } from './client'
import type { LogsResponse } from '@/types/api'

export type LogType = 'decisions' | 'operations' | 'auth' | 'system'

export async function getLogs(
  type: LogType,
  limit = 100,
  offset = 0
): Promise<LogsResponse> {
  const params = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
  })
  return apiGet<LogsResponse>(`/logs/${type}?${params}`)
}

export async function getDecisionLogs(limit = 100, offset = 0): Promise<LogsResponse> {
  return getLogs('decisions', limit, offset)
}

export async function getOperationLogs(limit = 100, offset = 0): Promise<LogsResponse> {
  return getLogs('operations', limit, offset)
}
