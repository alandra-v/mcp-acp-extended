import { X } from 'lucide-react'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import type { PendingApproval } from '@/types/api'

interface PendingDrawerProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  approvals: PendingApproval[]
  onApprove: (id: string) => void
  onDeny: (id: string) => void
}

export function PendingDrawer({
  open,
  onOpenChange,
  approvals,
  onApprove,
  onDeny,
}: PendingDrawerProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-[480px] bg-base-950 border-l border-border p-0" hideCloseButton>
        <SheetHeader className="px-6 py-6 border-b border-[var(--border-subtle)]">
          <div className="flex items-center justify-between">
            <SheetTitle className="font-display text-lg font-semibold">
              Pending Approvals
            </SheetTitle>
            <button
              onClick={() => onOpenChange(false)}
              className="w-8 h-8 flex items-center justify-center bg-transparent border border-[var(--border-subtle)] rounded-full text-muted-foreground hover:bg-base-800 hover:text-foreground transition-smooth"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </SheetHeader>

        <ScrollArea className="flex-1 h-[calc(100vh-80px)]">
          <div className="p-6 space-y-3">
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
        </ScrollArea>
      </SheetContent>
    </Sheet>
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
    <div className="p-4 bg-gradient-to-br from-[oklch(0.14_0.01_228)] to-[oklch(0.12_0.008_228)] border border-[var(--border-subtle)] rounded-lg">
      <div className="flex items-center gap-3 mb-3">
        <span className="text-xs text-base-500 bg-base-800 px-2 py-1 rounded">
          {approval.proxy_id}
        </span>
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
          className="bg-[oklch(0.7_0.15_145_/_0.2)] text-[oklch(0.75_0.12_145)] border border-[oklch(0.7_0.15_145_/_0.3)] hover:bg-[oklch(0.7_0.15_145_/_0.3)]"
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
