import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
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
import ReportsPage from './pages/Reports'
import SettingsPage from './pages/Settings'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
})

function App() {
  return (
    <LanguageProvider>
      <AuthProvider>
        <QueryClientProvider client={queryClient}>
          <BrowserRouter>
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
                <Route path="reports" element={<ReportsPage />} />
                <Route path="settings" element={<SettingsPage />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </QueryClientProvider>
      </AuthProvider>
    </LanguageProvider>
  )
}

export default App
