import { Button } from '@/components/ui/button'
import { Section } from './Section'
import type { PendingApproval } from '@/types/api'

interface ApprovalsSectionProps {
  approvals: PendingApproval[]
  onApprove: (id: string) => void
  onDeny: (id: string) => void
  loaded?: boolean
}

export function ApprovalsSection({
  approvals,
  onApprove,
  onDeny,
  loaded = true,
}: ApprovalsSectionProps) {
  return (
    <Section number="002" title="Pending Approvals" loaded={loaded}>
      <div className="space-y-3">
        {approvals.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground text-sm">
            No pending approvals
          </div>
        ) : (
          approvals.map((approval) => (
            <ApprovalItem
              key={approval.id}
              approval={approval}
              onApprove={() => onApprove(approval.id)}
              onDeny={() => onDeny(approval.id)}
            />
          ))
        )}
      </div>
    </Section>
  )
}

interface ApprovalItemProps {
  approval: PendingApproval
  onApprove: () => void
  onDeny: () => void
}

function ApprovalItem({ approval, onApprove, onDeny }: ApprovalItemProps) {
  const timeAgo = formatTimeAgo(new Date(approval.created_at))

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
          className="bg-[oklch(0.7_0.15_145_/_0.2)] text-[oklch(0.75_0.12_145)] border border-[oklch(0.7_0.15_145_/_0.3)] hover:bg-[oklch(0.7_0.15_145_/_0.3)] text-xs px-3 py-1.5"
        >
          Allow
        </Button>
      </div>
    </div>
  )
}

function formatTimeAgo(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000)
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  return `${Math.floor(seconds / 3600)}h ago`
}
