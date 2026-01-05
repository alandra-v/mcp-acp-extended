import { useState, useEffect, useRef } from 'react'
import { ExternalLink } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { startLogin, pollLogin } from '@/api/auth'

interface LoginDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess: () => void
}

export function LoginDialog({ open, onOpenChange, onSuccess }: LoginDialogProps) {
  const [state, setState] = useState<{
    userCode?: string
    verificationUri?: string
    verificationUriComplete?: string
    polling?: boolean
    error?: string
  }>({})

  // Track poll interval for cleanup
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Cleanup on unmount or close
  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
      }
    }
  }, [])

  // Reset state when dialog closes
  useEffect(() => {
    if (!open) {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
      setState({})
    }
  }, [open])

  const handleStartLogin = async () => {
    setState({ polling: false })

    try {
      const response = await startLogin()
      setState({
        userCode: response.user_code,
        verificationUri: response.verification_uri,
        verificationUriComplete: response.verification_uri_complete || undefined,
        polling: true,
      })

      // Start polling
      pollIntervalRef.current = setInterval(async () => {
        try {
          const pollResponse = await pollLogin(response.user_code)

          if (pollResponse.status === 'complete') {
            if (pollIntervalRef.current) {
              clearInterval(pollIntervalRef.current)
              pollIntervalRef.current = null
            }
            onOpenChange(false)
            onSuccess()
          } else if (
            pollResponse.status === 'expired' ||
            pollResponse.status === 'denied' ||
            pollResponse.status === 'error'
          ) {
            if (pollIntervalRef.current) {
              clearInterval(pollIntervalRef.current)
              pollIntervalRef.current = null
            }
            setState((prev) => ({
              ...prev,
              polling: false,
              error: pollResponse.message || 'Login failed',
            }))
          }
        } catch {
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current)
            pollIntervalRef.current = null
          }
          setState((prev) => ({ ...prev, polling: false, error: 'Polling failed' }))
        }
      }, response.interval * 1000)
    } catch (err) {
      setState({ error: err instanceof Error ? err.message : 'Failed to start login' })
    }
  }

  // Start login when dialog opens
  useEffect(() => {
    if (open && !state.userCode && !state.error && !state.polling) {
      handleStartLogin()
    }
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="font-display">Login</DialogTitle>
          <DialogDescription>Complete authentication in your browser</DialogDescription>
        </DialogHeader>

        {state.error ? (
          <div className="py-4">
            <div className="text-[oklch(0.7_0.15_25)] mb-4">{state.error}</div>
            <Button onClick={handleStartLogin} variant="outline">
              Try Again
            </Button>
          </div>
        ) : state.userCode ? (
          <div className="py-4 space-y-4">
            <div>
              <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2">
                Your code
              </div>
              <div className="font-mono text-2xl font-bold tracking-widest text-center p-4 bg-base-900 rounded-lg">
                {state.userCode}
              </div>
            </div>

            <div className="text-sm text-muted-foreground text-center">
              Enter this code at the verification page
            </div>

            <Button
              className="w-full"
              onClick={() =>
                window.open(state.verificationUriComplete || state.verificationUri, '_blank')
              }
            >
              <ExternalLink className="w-4 h-4 mr-2" />
              Open Verification Page
            </Button>

            {state.polling && (
              <div className="text-center text-sm text-muted-foreground">
                <span className="inline-block w-2 h-2 bg-base-500 rounded-full animate-pulse mr-2" />
                Waiting for authentication...
              </div>
            )}
          </div>
        ) : (
          <div className="py-8 text-center text-muted-foreground">
            <span className="inline-block w-4 h-4 border-2 border-base-500 border-t-transparent rounded-full animate-spin mr-2" />
            Starting login...
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
