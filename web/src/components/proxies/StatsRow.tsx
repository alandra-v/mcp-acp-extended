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
}

export function StatsRow({
  total,
  active,
  inactive,
  pending,
  currentFilter,
  onFilterChange,
  onPendingClick,
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
        showAlert={pending > 0}
      />
    </div>
  )
}

interface StatCardProps {
  label: string
  value: number
  active?: boolean
  onClick: () => void
  showAlert?: boolean
}

function StatCard({ label, value, active, onClick, showAlert }: StatCardProps) {
  return (
    <button
      onClick={onClick}
      className={cn('stat-card', active && 'active')}
    >
      <div className="stat-card-inner">
        <div className="flex items-center gap-2">
          <span className="stat-value">{value}</span>
          {showAlert && (
            <span
              className="w-2 h-2 rounded-full bg-error-indicator shadow-[0_0_6px_var(--error-indicator)] animate-pulse"
              title="Pending approvals"
            />
          )}
        </div>
        <span className="stat-label">{label}</span>
      </div>
    </button>
  )
}
