import { Link } from 'react-router-dom'
import { cn } from '@/lib/utils'
import type { Proxy } from '@/types/api'

interface ProxyCardProps {
  proxy: Proxy
}

export function ProxyCard({ proxy }: ProxyCardProps) {
  const isActive = proxy.status === 'running'

  return (
    <Link to={`/proxy/${proxy.id}`} className="proxy-card">
      <div className="proxy-card-inner">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <span className="proxy-name">{proxy.backend_id}</span>
          <div className="proxy-status">
            <span className={cn('status-dot', !isActive && 'inactive')} />
            {isActive ? 'Active' : 'Inactive'}
          </div>
        </div>

        {/* Meta */}
        <div className="proxy-meta">
          <div className="proxy-meta-row">
            <span className="proxy-meta-label">ID</span>
            <span className="proxy-meta-value">{proxy.id}</span>
          </div>
          {proxy.command && (
            <div className="proxy-meta-row">
              <span className="proxy-meta-label">Cmd</span>
              <span className="proxy-meta-value">{proxy.command}</span>
            </div>
          )}
          {proxy.args && proxy.args.length > 0 && (
            <div className="proxy-meta-row">
              <span className="proxy-meta-label">Args</span>
              <span className="proxy-meta-value">{proxy.args.join(' ')}</span>
            </div>
          )}
          {proxy.url && (
            <div className="proxy-meta-row">
              <span className="proxy-meta-label">URL</span>
              <span className="proxy-meta-value">{proxy.url}</span>
            </div>
          )}
        </div>

        {/* Stats */}
        <div className="proxy-stats">
          <div className="proxy-stat">
            <span className="proxy-stat-value">{formatUptime(proxy.uptime_seconds)}</span>
            <span className="proxy-stat-label">Uptime</span>
          </div>
          <div className="proxy-stat">
            <span className="proxy-stat-value">--</span>
            <span className="proxy-stat-label">Requests</span>
          </div>
          <div className="proxy-stat">
            <span className="proxy-stat-value">--</span>
            <span className="proxy-stat-label">Denied</span>
          </div>
        </div>
      </div>
    </Link>
  )
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  const hours = Math.floor(seconds / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  return `${hours}h ${mins}m`
}
