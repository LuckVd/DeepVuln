import { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '@/contexts/AuthContext'
import ChangePasswordModal from './ChangePasswordModal'
import { Loader2 } from 'lucide-react'

interface AuthGuardProps {
  children: ReactNode
}

export default function AuthGuard({ children }: AuthGuardProps) {
  const { isAuthenticated, isLoading, mustChangePassword, logout } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background-primary flex items-center justify-center">
        <Loader2 className="h-8 w-8 text-cyan animate-spin" />
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return (
    <>
      {children}
      <ChangePasswordModal
        open={mustChangePassword}
        onComplete={() => window.location.reload()}
      />
    </>
  )
}
