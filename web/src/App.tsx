import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { Toaster } from '@/components/ui/sonner'
import { PendingApprovalsProvider } from '@/context/PendingApprovalsContext'
import { ProxiesPage } from '@/pages/ProxiesPage'
import { ProxyDetailPage } from '@/pages/ProxyDetailPage'
import { GlobalLogsPage } from '@/pages/GlobalLogsPage'
import { AuthPage } from '@/pages/AuthPage'

export function App() {
  return (
    <ErrorBoundary>
      <PendingApprovalsProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<ProxiesPage />} />
            <Route path="/proxies" element={<ProxiesPage />} />
            <Route path="/proxy/:id" element={<ProxyDetailPage />} />
            <Route path="/logs" element={<GlobalLogsPage />} />
            <Route path="/auth" element={<AuthPage />} />
          </Routes>
        </BrowserRouter>
        <Toaster position="bottom-right" />
      </PendingApprovalsProvider>
    </ErrorBoundary>
  )
}
