import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Button, Input } from '@/components/ui'
import { useAuth } from '@/contexts/AuthContext'
import { ShieldAlert, Loader2 } from 'lucide-react'

export default function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      await login(username, password)
      navigate('/dashboard', { replace: true })
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      if (detail) {
        setError(detail)
      } else {
        setError('登录失败，请检查网络连接')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-background-primary flex items-center justify-center p-6">
      <div className="w-full max-w-[420px]">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-lg bg-cyan/10 border-2 border-cyan/30 mb-4">
            <ShieldAlert className="h-8 w-8 text-cyan" />
          </div>
          <h1 className="text-3xl font-bold text-text-primary font-mono tracking-widest">
            DEEPVULN
          </h1>
          <p className="text-text-tertiary font-mono text-sm mt-1 tracking-wider">
            SECURITY SCAN PLATFORM
          </p>
        </div>

        {/* Login Card */}
        <div className="glass-panel rounded-lg p-8 corner-brackets">
          <h2 className="text-cyan font-mono font-bold text-sm tracking-widest mb-6">
            SYSTEM LOGIN
          </h2>

          <form onSubmit={handleSubmit} className="space-y-5">
            <Input
              label="用户名"
              type="text"
              placeholder="admin"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={loading}
              autoFocus
            />

            <Input
              label="密码"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
              error={error}
            />

            <Button
              type="submit"
              className="w-full font-mono tracking-wider"
              disabled={!username || !password || loading}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  认证中...
                </>
              ) : (
                'LOGIN'
              )}
            </Button>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-text-tertiary text-xs font-mono mt-6 tracking-wider">
          DeepVuln v0.9.0
        </p>
      </div>
    </div>
  )
}
