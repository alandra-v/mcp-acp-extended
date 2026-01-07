import { Link, useLocation } from 'react-router-dom'
import { AuthDropdown } from '@/components/auth/AuthDropdown'
import { cn } from '@/lib/utils'

interface HeaderProps {
  proxyName?: string
}

export function Header({ proxyName }: HeaderProps) {
  const location = useLocation()
  const isProxiesPage = location.pathname === '/' || location.pathname === '/proxies'

  return (
    <header className="flex items-center justify-between px-8 py-4 border-b border-[var(--border-subtle)] bg-gradient-to-b from-base-950 to-background sticky top-0 z-50">
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

      <nav className="flex items-center gap-2">
        <Link
          to="/"
          className={cn(
            'px-4 py-2 rounded-lg text-sm font-medium transition-smooth',
            isProxiesPage
              ? 'text-foreground bg-base-800'
              : 'text-muted-foreground hover:text-foreground hover:bg-base-900'
          )}
        >
          Proxies
        </Link>
        <span
          className="px-4 py-2 rounded-lg text-sm font-medium text-base-600 cursor-not-allowed"
          title="Coming soon - available in multi-proxy mode"
        >
          Global Logs
        </span>

        {/* Auth dropdown */}
        <AuthDropdown />
      </nav>
    </header>
  )
}
