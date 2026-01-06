import { ScrollArea } from '@/components/ui/scroll-area'
import { Section } from './Section'
import { cn } from '@/lib/utils'
import type { LogEntry } from '@/types/api'

interface ActivitySectionProps {
  logs: LogEntry[]
  loading?: boolean
  loaded?: boolean
}

export function ActivitySection({
  logs,
  loading = false,
  loaded = true,
}: ActivitySectionProps) {
  return (
    <Section number="003" title="Recent Activity" loaded={loaded}>
      <div className="border border-[var(--border-subtle)] rounded-lg bg-gradient-to-br from-[oklch(0.20_0.014_228)] to-[oklch(0.16_0.012_228)] overflow-hidden">
        <ScrollArea className="h-[300px]">
          {loading ? (
            <div className="text-center py-8 text-muted-foreground text-sm">
              Loading logs...
            </div>
          ) : logs.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground text-sm">
              No recent activity
            </div>
          ) : (
            <div>
              {logs.map((log, i) => (
                <LogEntryRow key={`${log.timestamp}-${i}`} log={log} />
              ))}
            </div>
          )}
        </ScrollArea>
      </div>
    </Section>
  )
}

interface LogEntryRowProps {
  log: LogEntry
}

function LogEntryRow({ log }: LogEntryRowProps) {
  const timestamp = formatTimestamp(log.timestamp)
  const toolName = (log.tool_name as string) || (log.tool as string) || '--'
  const path = (log.path as string) || (log.resource as string) || '--'
  const decision = (log.decision as string) || (log.outcome as string) || 'unknown'
  const isAllowed = decision === 'allow' || decision === 'allowed'

  return (
    <div className="flex items-center gap-4 px-4 py-3 border-b border-[var(--border-subtle)] last:border-b-0 hover:bg-base-900 transition-smooth text-sm">
      <span className="font-mono text-xs text-base-600 min-w-[70px]">
        {timestamp}
      </span>
      <span className="font-mono text-xs text-base-400 min-w-[100px]">
        {toolName}
      </span>
      <span className="font-mono text-xs text-base-500 flex-1 truncate">
        {path}
      </span>
      <span
        className={cn(
          'text-xs font-medium',
          isAllowed ? 'text-success-muted' : 'text-base-500'
        )}
      >
        {decision}
      </span>
    </div>
  )
}

function formatTimestamp(ts: string): string {
  try {
    const date = new Date(ts)
    return date.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return '--:--:--'
  }
}
