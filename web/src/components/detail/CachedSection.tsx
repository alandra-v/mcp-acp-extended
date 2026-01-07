import { Trash2 } from 'lucide-react'
import { Section } from './Section'
import { Button } from '@/components/ui/button'
import { useCountdown, formatCountdown } from '@/hooks/useCountdown'
import type { CachedApproval } from '@/types/api'

interface CachedSectionProps {
  cached: CachedApproval[]
  loading?: boolean
  onClear: () => void
  onDelete: (subjectId: string, toolName: string, path: string | null) => void
  loaded?: boolean
}

export function CachedSection({
  cached,
  loading = false,
  onClear,
  onDelete,
  loaded = true,
}: CachedSectionProps) {
  return (
    <Section number="003" title="Cached Decisions" loaded={loaded}>
      <div className="space-y-3">
        {loading ? (
          <div className="text-center py-8 text-muted-foreground text-sm">
            Loading...
          </div>
        ) : cached.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground text-sm">
            No cached decisions
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-base-500">
                {cached.length} cached decision{cached.length !== 1 ? 's' : ''}
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={onClear}
                className="text-xs text-base-500 hover:text-base-300 h-7 px-2"
              >
                <Trash2 className="w-3 h-3 mr-1" />
                Clear all
              </Button>
            </div>
            {cached.map((item) => (
              <CachedItem key={item.request_id} item={item} onDelete={onDelete} />
            ))}
          </>
        )}
      </div>
    </Section>
  )
}

interface CachedItemProps {
  item: CachedApproval
  onDelete: (subjectId: string, toolName: string, path: string | null) => void
}

function CachedItem({ item, onDelete }: CachedItemProps) {
  // Live countdown - expires_in_seconds is relative to when data was fetched
  const remaining = useCountdown(undefined, item.expires_in_seconds)
  const isExpiring = remaining < 30

  return (
    <div className="flex items-center gap-4 p-3 bg-gradient-to-br from-[oklch(0.16_0.012_228)] to-[oklch(0.13_0.01_228)] border border-[var(--border-subtle)] rounded-lg group">
      <span className="font-mono text-sm text-base-300 bg-base-800 px-2 py-1 rounded">
        {item.tool_name}
      </span>
      <span className="flex-1 font-mono text-xs text-base-500 truncate">
        {item.path || '--'}
      </span>
      <span className={`text-xs tabular-nums ${isExpiring ? 'text-warning' : 'text-base-600'}`}>
        {remaining > 0 ? `expires in ${formatCountdown(remaining)}` : 'expired'}
      </span>
      <button
        onClick={() => onDelete(item.subject_id, item.tool_name, item.path)}
        className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-base-700 rounded text-base-500 hover:text-base-300"
        title="Delete this cached approval"
      >
        <Trash2 className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}
