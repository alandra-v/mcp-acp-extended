import { Section } from './Section'
import { ApprovalItem } from '@/components/approvals/ApprovalItem'
import type { PendingApproval } from '@/types/api'

interface ApprovalsSectionProps {
  approvals: PendingApproval[]
  onApprove: (id: string) => void
  onApproveOnce: (id: string) => void
  onDeny: (id: string) => void
  loaded?: boolean
}

export function ApprovalsSection({
  approvals,
  onApprove,
  onApproveOnce,
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
              onApproveOnce={() => onApproveOnce(approval.id)}
              onDeny={() => onDeny(approval.id)}
              compact
            />
          ))
        )}
      </div>
    </Section>
  )
}
