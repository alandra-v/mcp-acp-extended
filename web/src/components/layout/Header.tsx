import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { ChevronDown } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { LoginDialog } from '@/components/auth/LoginDialog'
import { cn } from '@/lib/utils'
import { useAuth } from '@/hooks/useAuth'

interface HeaderProps {
  proxyName?: string
}

export function Header({ proxyName }: HeaderProps) {
  const location = useLocation()
  const isProxiesPage = location.pathname === '/' || location.pathname === '/proxies'
  const isGlobalLogsPage = location.pathname === '/logs'

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
        <Link
          to="/logs"
          className={cn(
            'px-4 py-2 rounded-lg text-sm font-medium transition-smooth',
            isGlobalLogsPage
              ? 'text-foreground bg-base-800'
              : 'text-muted-foreground hover:text-foreground hover:bg-base-900'
          )}
        >
          Global Logs
        </Link>

        {/* Auth dropdown */}
        <AuthDropdown />
      </nav>
    </header>
  )
}

function AuthDropdown() {
  const navigate = useNavigate()
  const { status, loading, logout, logoutFederated, refresh } = useAuth()
  const [loginDialogOpen, setLoginDialogOpen] = useState(false)

  const isAuthenticated = status?.authenticated ?? false
  const displayName = status?.email || status?.name || (isAuthenticated ? 'Authenticated' : 'Not logged in')

  const handleLogout = async () => {
    await logout()
  }

  const handleLogoutFederated = async () => {
    await logoutFederated()
  }

  const handleSettings = () => {
    navigate('/auth')
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium hover:bg-base-900 transition-smooth outline-none">
          <span
            className={cn(
              'w-2 h-2 rounded-full',
              isAuthenticated
                ? 'bg-success shadow-[0_0_6px_oklch(0.7_0.15_145_/_0.5)]'
                : 'bg-[oklch(0.65_0.2_25)] shadow-[0_0_6px_oklch(0.65_0.2_25_/_0.5)]'
            )}
          />
          <span className={loading ? 'opacity-50' : ''}>
            {loading ? 'Loading...' : displayName}
          </span>
          <ChevronDown className="w-3 h-3 text-base-500" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuItem
            onClick={() => setLoginDialogOpen(true)}
            disabled={isAuthenticated}
            className={isAuthenticated ? 'opacity-40 cursor-not-allowed' : ''}
          >
            Login
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={handleLogout}
            disabled={!isAuthenticated}
            className={!isAuthenticated ? 'opacity-40 cursor-not-allowed' : ''}
          >
            Logout
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={handleLogoutFederated}
            disabled={!isAuthenticated}
            className={!isAuthenticated ? 'opacity-40 cursor-not-allowed' : ''}
          >
            Logout (federated)
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={handleSettings}>
            Auth details
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <LoginDialog
        open={loginDialogOpen}
        onOpenChange={setLoginDialogOpen}
        onSuccess={refresh}
      />
    </>
  )
}
