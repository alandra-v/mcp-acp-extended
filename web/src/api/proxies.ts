import { apiGet } from './client'
import type { Proxy, ProxyStatus } from '@/types/api'

export async function getProxies(): Promise<Proxy[]> {
  return apiGet<Proxy[]>('/proxies')
}

export async function getProxy(id: string): Promise<Proxy> {
  return apiGet<Proxy>(`/proxies/${id}`)
}

export async function getProxyStatus(): Promise<ProxyStatus> {
  return apiGet<ProxyStatus>('/control/status')
}
