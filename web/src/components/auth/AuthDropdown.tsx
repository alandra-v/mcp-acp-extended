import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
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

export function AuthDropdown() {
  const navigate = useNavigate()
  const { status, loading, logout, logoutFederated, refresh } = useAuth()
  const [loginDialogOpen, setLoginDialogOpen] = useState(false)

  const isAuthenticated = status?.authenticated ?? false
  const hasProvider = !!status?.provider
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
                ? 'bg-success shadow-[0_0_6px_var(--success-border)]'
                : 'bg-error-indicator shadow-[0_0_6px_var(--error-indicator)]'
            )}
          />
          <span className={loading ? 'opacity-50' : ''}>
            {loading ? 'Loading...' : displayName}
          </span>
          <ChevronDown className="w-3 h-3 text-base-500" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          {!isAuthenticated && (
            <DropdownMenuItem onClick={() => setLoginDialogOpen(true)}>
              Login
            </DropdownMenuItem>
          )}
          {isAuthenticated && (
            <DropdownMenuItem onClick={handleLogout}>
              Logout
            </DropdownMenuItem>
          )}
          {hasProvider && (
            <DropdownMenuItem onClick={handleLogoutFederated}>
              Logout (federated)
            </DropdownMenuItem>
          )}
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
