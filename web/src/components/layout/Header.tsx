import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'
import { AuthDropdown } from '@/components/auth/AuthDropdown'
import { useIncidentsContext } from '@/context/IncidentsContext'
import { cn } from '@/lib/utils'

interface HeaderProps {
  proxyName?: string
}

export function Header({ proxyName }: HeaderProps) {
  const location = useLocation()
  const { hasUnread } = useIncidentsContext()

  // Page loader state
  const [isLoading, setIsLoading] = useState(false)
  const [loaderKey, setLoaderKey] = useState(0)

  useEffect(() => {
    setIsLoading(true)
    setLoaderKey((k) => k + 1)
    const timer = setTimeout(() => setIsLoading(false), 600)
    return () => clearTimeout(timer)
  }, [location.pathname])

  return (
    <header className="flex items-center justify-between px-8 py-4 border-b border-[var(--border-subtle)] bg-gradient-to-b from-base-950 to-background sticky top-0 z-50">
      {/* Page transition loader - positioned on the border */}
      <div
        key={loaderKey}
        className={cn(
          'absolute bottom-0 left-0 h-px',
          'bg-gradient-to-r from-base-600 via-base-500 to-base-600',
          isLoading ? 'animate-page-load' : 'w-0 opacity-0'
        )}
      />
      <div className="flex items-center gap-4">
        <Link
          to="/"
          className="font-brand font-semibold text-lg tracking-wide text-base-200 hover:text-foreground transition-smooth"
        >
          MCP ACP
        </Link>

        {/* Breadcrumb - shown on detail page */}
        {proxyName && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <span className="text-base-600">/</span>
            <Link
              to="/"
              className="hover:text-foreground transition-smooth"
            >
              Proxies
            </Link>
            <span className="text-base-600">/</span>
            <span className="text-foreground font-medium">{proxyName}</span>
          </div>
        )}
      </div>

      <div className="flex items-center gap-4">
        {/* Incidents Link with Badge */}
        <Link
          to="/incidents"
          className={cn(
            'relative flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-smooth',
            location.pathname === '/incidents'
              ? 'bg-base-800 text-foreground'
              : 'text-muted-foreground hover:text-foreground hover:bg-base-900'
          )}
        >
          <AlertTriangle className="w-4 h-4" />
          Incidents
          {hasUnread && (
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.5)]" />
          )}
        </Link>

        <AuthDropdown />
      </div>
    </header>
  )
}
