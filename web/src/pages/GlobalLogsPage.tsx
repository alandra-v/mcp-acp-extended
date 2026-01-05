import { Layout } from '@/components/layout/Layout'

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

        <div className="text-center py-16 text-muted-foreground">
          Global Logs page coming soon
        </div>
      </div>
    </Layout>
  )
}
