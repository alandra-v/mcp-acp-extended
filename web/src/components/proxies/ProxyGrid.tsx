import { ProxyCard } from './ProxyCard'
import type { Proxy, PendingApproval } from '@/types/api'

interface ProxyGridProps {
  proxies: Proxy[]
  pendingApprovals: PendingApproval[]
}

export function ProxyGrid({ proxies, pendingApprovals }: ProxyGridProps) {
  // Count pending approvals per proxy
  const pendingByProxy = pendingApprovals.reduce<Record<string, number>>(
    (acc, approval) => {
      acc[approval.proxy_id] = (acc[approval.proxy_id] || 0) + 1
      return acc
    },
    {}
  )

  if (proxies.length === 0) {
    return (
      <div className="text-center py-16 text-muted-foreground">
        No proxies found
      </div>
    )
  }

  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(340px,1fr))] gap-5">
      {proxies.map((proxy) => (
        <ProxyCard
          key={proxy.id}
          proxy={proxy}
          pendingCount={pendingByProxy[proxy.id] || 0}
        />
      ))}
    </div>
  )
}
