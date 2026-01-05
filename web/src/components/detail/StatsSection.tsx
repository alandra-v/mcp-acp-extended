import { Section } from './Section'

interface StatsSectionProps {
  requests?: number
  avgLatency?: string
  denied?: number
  loaded?: boolean
}

export function StatsSection({
  requests = 0,
  avgLatency = '--',
  denied = 0,
  loaded = true,
}: StatsSectionProps) {
  return (
    <Section number="001" title="Statistics" loaded={loaded}>
      <div className="grid grid-cols-3 gap-4">
        <StatBox label="Requests Today" value={requests.toString()} />
        <StatBox label="Avg Latency" value={avgLatency} />
        <StatBox label="Denied" value={denied.toString()} />
      </div>
    </Section>
  )
}

interface StatBoxProps {
  label: string
  value: string
}

function StatBox({ label, value }: StatBoxProps) {
  return (
    <div className="p-5 bg-gradient-to-br from-[oklch(0.14_0.01_228)] to-[oklch(0.11_0.008_228)] border border-[var(--border-subtle)] rounded-lg">
      <div className="font-display text-3xl font-semibold mb-1">{value}</div>
      <div className="text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
    </div>
  )
}
