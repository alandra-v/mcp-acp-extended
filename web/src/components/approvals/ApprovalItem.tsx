import { Button } from '@/components/ui/button'
import { formatTimeAgo } from '@/lib/utils'
import type { PendingApproval } from '@/types/api'

interface ApprovalItemProps {
  approval: PendingApproval
  onApprove: () => void
  onDeny: () => void
  /** Show proxy ID badge (for global list) */
  showProxyId?: boolean
  /** Use compact horizontal layout */
  compact?: boolean
}

export function ApprovalItem({
  approval,
  onApprove,
  onDeny,
  showProxyId = false,
  compact = false,
}: ApprovalItemProps) {
  const timeAgo = formatTimeAgo(new Date(approval.created_at))

  if (compact) {
    return (
      <div className="flex items-center gap-4 p-4 bg-gradient-to-br from-[oklch(0.14_0.01_228)] to-[oklch(0.12_0.008_228)] border border-[var(--border-subtle)] rounded-lg">
        <span className="font-mono text-sm text-base-300 bg-base-800 px-2.5 py-1.5 rounded">
          {approval.tool_name}
        </span>
        <span className="flex-1 font-mono text-sm text-base-400 truncate">
          {approval.path || '--'}
        </span>
        <span className="text-xs text-base-600">{timeAgo}</span>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={onDeny}
            className="bg-base-800 text-base-400 border-[var(--border-subtle)] hover:bg-base-700 text-xs px-3 py-1.5"
          >
            Deny
          </Button>
          <Button
            size="sm"
            onClick={onApprove}
            className="bg-success-bg text-success-muted border border-success-border hover:bg-success-bg-hover text-xs px-3 py-1.5"
          >
            Allow
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="p-4 bg-gradient-to-br from-[oklch(0.14_0.01_228)] to-[oklch(0.12_0.008_228)] border border-[var(--border-subtle)] rounded-lg">
      <div className="flex items-center gap-3 mb-3">
        {showProxyId && (
          <span className="text-xs text-base-500 bg-base-800 px-2 py-1 rounded">
            {approval.proxy_id}
          </span>
        )}
        <span className="font-mono text-sm text-base-300">
          {approval.tool_name}
        </span>
        <span className="ml-auto text-xs text-base-600">{timeAgo}</span>
      </div>

      {approval.path && (
        <div className="font-mono text-xs text-base-400 mb-3 break-all">
          {approval.path}
        </div>
      )}

      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={onDeny}
          className="bg-base-800 text-base-400 border-[var(--border-subtle)] hover:bg-base-700"
        >
          Deny
        </Button>
        <Button
          size="sm"
          onClick={onApprove}
          className="bg-success-bg text-success-muted border border-success-border hover:bg-success-bg-hover"
        >
          Allow
        </Button>
      </div>
    </div>
  )
}
