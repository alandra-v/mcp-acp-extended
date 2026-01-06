import { useState, useEffect, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { Button } from '@/components/ui/button'
import { DetailSidebar, type DetailSection } from '@/components/detail/DetailSidebar'
import { StatsSection } from '@/components/detail/StatsSection'
import { ApprovalsSection } from '@/components/detail/ApprovalsSection'
import { CachedSection } from '@/components/detail/CachedSection'
import { ActivitySection } from '@/components/detail/ActivitySection'
import { useProxies } from '@/hooks/useProxies'
import { useAppState } from '@/context/AppStateContext'
import { useCachedApprovals } from '@/hooks/useCachedApprovals'
import { useLogs } from '@/hooks/useLogs'
import { cn } from '@/lib/utils'

export function ProxyDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { proxies, loading: proxiesLoading } = useProxies()
  const { pending, approve, approveOnce, deny } = useAppState()
  const { cached, loading: cachedLoading, clear: clearCached, deleteEntry: deleteCached } = useCachedApprovals()
  const { logs, loading: logsLoading } = useLogs('decisions')
  const [activeSection, setActiveSection] = useState<DetailSection>('overview')
  const [loaded, setLoaded] = useState(false)

  // Find the current proxy
  const proxy = useMemo(
    () => proxies.find((p) => p.id === id),
    [proxies, id]
  )

  // Filter pending approvals for this proxy
  const proxyPending = useMemo(
    () => pending.filter((p) => p.proxy_id === id),
    [pending, id]
  )

  // Trigger section load animation
  useEffect(() => {
    const timer = setTimeout(() => setLoaded(true), 100)
    return () => clearTimeout(timer)
  }, [])

  if (proxiesLoading) {
    return (
      <Layout>
        <div className="text-center py-16 text-muted-foreground">
          Loading...
        </div>
      </Layout>
    )
  }

  if (!proxy) {
    return (
      <Layout>
        <div className="max-w-[1200px] mx-auto px-8 py-12 text-center">
          <h1 className="font-display text-2xl font-semibold mb-4">
            Proxy not found
          </h1>
          <Button onClick={() => navigate('/')}>Back to Proxies</Button>
        </div>
      </Layout>
    )
  }

  const isActive = proxy.status === 'running'

  return (
    <Layout proxyName={proxy.backend_id} showFooter={false}>
      <div className="grid grid-cols-[180px_1fr] gap-12 max-w-[1200px] mx-auto px-8 py-8">
        {/* Header */}
        <div className="col-span-2 flex items-center gap-6 pb-6 border-b border-[var(--border-subtle)] mb-2">
          <button
            onClick={() => navigate('/')}
            className="inline-flex items-center gap-2 px-4 py-2 bg-transparent border border-[var(--border-subtle)] rounded-lg text-muted-foreground text-sm hover:bg-base-900 hover:text-foreground transition-smooth"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </button>

          <div className="flex-1 flex items-center gap-3">
            <h1 className="font-display text-xl font-semibold">
              {proxy.backend_id}
            </h1>
            <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
              <span
                className={cn(
                  'w-2 h-2 rounded-full',
                  isActive
                    ? 'bg-success shadow-[0_0_8px_var(--success-border)]'
                    : 'bg-base-600'
                )}
              />
              {isActive ? 'Active' : 'Inactive'}
            </div>
          </div>

          {/* Stop/Restart buttons for multi-proxy support (Phase 2) */}
        </div>

        {/* Sidebar */}
        <DetailSidebar
          activeSection={activeSection}
          onSectionChange={setActiveSection}
        />

        {/* Content */}
        <div className="min-w-0">
          {activeSection === 'overview' && (
            <>
              <StatsSection loaded={loaded} />
              <ApprovalsSection
                approvals={proxyPending}
                onApprove={approve}
                onApproveOnce={approveOnce}
                onDeny={deny}
                loaded={loaded}
              />
              <CachedSection
                cached={cached}
                loading={cachedLoading}
                onClear={clearCached}
                onDelete={deleteCached}
                loaded={loaded}
              />
              <ActivitySection
                logs={logs}
                loading={logsLoading}
                loaded={loaded}
              />
            </>
          )}

          {activeSection === 'logs' && (
            <div className="text-center py-16 text-muted-foreground">
              Logs section coming soon
            </div>
          )}

          {activeSection === 'policy' && (
            <div className="text-center py-16 text-muted-foreground">
              Policy section coming soon
            </div>
          )}

          {activeSection === 'config' && (
            <div className="text-center py-16 text-muted-foreground">
              Config section coming soon
            </div>
          )}
        </div>
      </div>
    </Layout>
  )
}
