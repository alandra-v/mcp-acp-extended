import { useState, useMemo, useCallback } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { StatsRow, type FilterType } from '@/components/proxies/StatsRow'
import { ProxyGrid } from '@/components/proxies/ProxyGrid'
import { PendingDrawer } from '@/components/proxies/PendingDrawer'
import { useProxies } from '@/hooks/useProxies'
import { usePendingApprovalsContext } from '@/context/PendingApprovalsContext'

export function ProxiesPage() {
  const { proxies, loading: proxiesLoading, error: proxiesError } = useProxies()
  const { pending, approve, approveOnce, deny, error: pendingError } = usePendingApprovalsContext()
  const [filter, setFilter] = useState<FilterType>('all')
  const [drawerOpen, setDrawerOpen] = useState(false)

  // Calculate stats
  const stats = useMemo(() => {
    const active = proxies.filter((p) => p.status === 'running').length
    const inactive = proxies.filter((p) => p.status !== 'running').length
    return {
      total: proxies.length,
      active,
      inactive,
      pending: pending.length,
    }
  }, [proxies, pending])

  // Filter proxies
  const filteredProxies = useMemo(() => {
    switch (filter) {
      case 'active':
        return proxies.filter((p) => p.status === 'running')
      case 'inactive':
        return proxies.filter((p) => p.status !== 'running')
      default:
        return proxies
    }
  }, [proxies, filter])

  const handleFilterChange = useCallback((newFilter: FilterType) => {
    if (newFilter === 'pending') {
      setDrawerOpen(true)
    } else {
      setFilter(newFilter)
    }
  }, [])

  const handlePendingClick = useCallback(() => {
    setDrawerOpen(true)
  }, [])

  return (
    <Layout>
      <div className="max-w-[1200px] mx-auto px-8 py-12">
        {/* Page header */}
        <div className="mb-10">
          <h1 className="font-display text-3xl font-semibold tracking-tight mb-2">
            Proxies
          </h1>
          <p className="text-muted-foreground text-base">
            Manage your MCP proxy connections
          </p>
        </div>

        {/* Stats row */}
        <StatsRow
          total={stats.total}
          active={stats.active}
          inactive={stats.inactive}
          pending={stats.pending}
          currentFilter={filter}
          onFilterChange={handleFilterChange}
          onPendingClick={handlePendingClick}
        />

        {/* Error display */}
        {(proxiesError || pendingError) && (
          <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
            <p className="text-sm text-red-300">
              {proxiesError?.message || pendingError?.message}
            </p>
          </div>
        )}

        {/* Proxy grid */}
        {proxiesLoading ? (
          <div className="text-center py-16 text-muted-foreground">
            Loading proxies...
          </div>
        ) : (
          <ProxyGrid proxies={filteredProxies} />
        )}

        {/* Hint */}
        <div className="text-center mt-12 text-base-600 text-sm">
          Click a proxy to view details, logs, and configuration
        </div>
      </div>

      {/* Pending approvals drawer */}
      <PendingDrawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        approvals={pending}
        onApprove={approve}
        onApproveOnce={approveOnce}
        onDeny={deny}
      />
    </Layout>
  )
}
