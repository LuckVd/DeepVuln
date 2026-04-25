import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React, { Suspense } from 'react'
import { LanguageProvider } from './contexts/LanguageContext'
import { AuthProvider } from './contexts/AuthContext'
import AuthGuard from './components/auth/AuthGuard'
import AppLayout from './components/layout/AppLayout'
import LoginPage from './pages/Login'
import ScansPage from './pages/Scans'
import ScanDetailPage from './pages/ScanDetail'
import FindingsPage from './pages/Findings'
import DashboardPage from './pages/Dashboard'
import VulnerabilitiesPage from './pages/Vulnerabilities'

// Lazy-loaded low-frequency pages
const ReportsPage = React.lazy(() => import('./pages/Reports'))
const SettingsPage = React.lazy(() => import('./pages/Settings'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 30_000,
    },
  },
})

function App() {
  return (
    <BrowserRouter>
      <LanguageProvider>
        <AuthProvider>
          <QueryClientProvider client={queryClient}>
            <Routes>
              {/* Public route */}
              <Route path="/login" element={<LoginPage />} />

              {/* Protected routes */}
              <Route path="/" element={
                <AuthGuard>
                  <AppLayout />
                </AuthGuard>
              }>
                <Route index element={<Navigate to="/dashboard" replace />} />
                <Route path="dashboard" element={<DashboardPage />} />
                <Route path="scans" element={<ScansPage />} />
                <Route path="scans/:id" element={<ScanDetailPage />} />
                <Route path="scans/:id/findings" element={<FindingsPage />} />
                <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
                <Route path="reports" element={<Suspense fallback={<div className="p-6 text-center text-text-secondary font-mono">Loading...</div>}><ReportsPage /></Suspense>} />
                <Route path="settings" element={<Suspense fallback={<div className="p-6 text-center text-text-secondary font-mono">Loading...</div>}><SettingsPage /></Suspense>} />
                <Route path="*" element={
                  <div className="p-16 text-center">
                    <h1 className="text-4xl font-bold text-critical font-mono mb-4">404</h1>
                    <p className="text-text-secondary font-mono">Page Not Found</p>
                    <a href="/dashboard" className="text-cyan hover:underline font-mono mt-4 inline-block">Go to Dashboard</a>
                  </div>
                } />
              </Route>
            </Routes>
        </QueryClientProvider>
      </AuthProvider>
    </LanguageProvider>
    </BrowserRouter>
  )
}

export default App
