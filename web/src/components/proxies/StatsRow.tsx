import { cn } from '@/lib/utils'

export type FilterType = 'all' | 'active' | 'inactive' | 'pending'

interface StatsRowProps {
  total: number
  active: number
  inactive: number
  pending: number
  currentFilter: FilterType
  onFilterChange: (filter: FilterType) => void
  onPendingClick: () => void
  sseConnected?: boolean
}

export function StatsRow({
  total,
  active,
  inactive,
  pending,
  currentFilter,
  onFilterChange,
  onPendingClick,
  sseConnected = false,
}: StatsRowProps) {
  return (
    <div className="flex gap-4 mb-8">
      <StatCard
        label="All"
        value={total}
        active={currentFilter === 'all'}
        onClick={() => onFilterChange('all')}
      />
      <StatCard
        label="Active"
        value={active}
        active={currentFilter === 'active'}
        onClick={() => onFilterChange('active')}
      />
      <StatCard
        label="Inactive"
        value={inactive}
        active={currentFilter === 'inactive'}
        onClick={() => onFilterChange('inactive')}
      />
      <StatCard
        label="Pending"
        value={pending}
        active={currentFilter === 'pending'}
        onClick={onPendingClick}
        showConnectionStatus
        connected={sseConnected}
      />
    </div>
  )
}

interface StatCardProps {
  label: string
  value: number
  active?: boolean
  onClick: () => void
  showConnectionStatus?: boolean
  connected?: boolean
}

function StatCard({ label, value, active, onClick, showConnectionStatus, connected }: StatCardProps) {
  return (
    <button
      onClick={onClick}
      className={cn('stat-card', active && 'active')}
    >
      <div className="stat-card-inner">
        <div className="flex items-center gap-2">
          <span className="stat-value">{value}</span>
          {showConnectionStatus && connected && (
            <span
              className="w-2 h-2 rounded-full bg-success shadow-[0_0_6px_oklch(0.7_0.15_145_/_0.5)]"
              title="Live updates connected"
            />
          )}
        </div>
        <span className="stat-label">{label}</span>
      </div>
    </button>
  )
}
