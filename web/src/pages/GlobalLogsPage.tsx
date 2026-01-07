import { Layout } from '@/components/layout/Layout'
import { LogViewer } from '@/components/logs'

export function GlobalLogsPage() {
  return (
    <Layout>
      <div className="max-w-[1200px] mx-auto px-8 py-12">
        <div className="mb-10">
          <h1 className="font-display text-3xl font-semibold tracking-tight mb-2">
            Global Logs
          </h1>
          <p className="text-muted-foreground text-base">
            View logs across all proxies
          </p>
        </div>

        <LogViewer
          initialFolder="audit"
          initialLogType="_all"
          initialTimeRange="5m"
        />
      </div>
    </Layout>
  )
}
