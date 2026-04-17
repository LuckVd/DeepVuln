import { useState } from 'react'
import { Button, Input } from '@/components/ui'
import { useAuth } from '@/contexts/AuthContext'
import { Lock, Loader2 } from 'lucide-react'

interface ChangePasswordModalProps {
  open: boolean
  onComplete: () => void
}

export default function ChangePasswordModal({ open, onComplete }: ChangePasswordModalProps) {
  const { changePassword } = useAuth()
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  if (!open) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (newPassword.length < 6) {
      setError('密码长度至少 6 位')
      return
    }
    if (newPassword !== confirmPassword) {
      setError('两次输入的密码不一致')
      return
    }

    setLoading(true)
    try {
      await changePassword(newPassword)
      onComplete()
    } catch (err: any) {
      setError(err?.response?.data?.detail || '修改密码失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="glass-panel rounded-lg p-8 max-w-md w-full mx-4 corner-brackets">
        <div className="flex items-center gap-3 mb-2">
          <Lock className="h-5 w-5 text-warning" />
          <h3 className="text-warning font-mono font-bold text-sm tracking-wider">
            SECURITY NOTICE
          </h3>
        </div>
        <p className="text-text-secondary font-sans text-sm mb-6">
          首次登录需要修改默认密码才能继续使用系统。
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="新密码"
            type="password"
            placeholder="至少 6 位"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            disabled={loading}
            autoFocus
          />
          <Input
            label="确认密码"
            type="password"
            placeholder="再次输入新密码"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            disabled={loading}
            error={error}
          />
          <Button
            type="submit"
            className="w-full font-mono tracking-wider"
            disabled={!newPassword || !confirmPassword || loading}
          >
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                修改中...
              </>
            ) : (
              '确认修改'
            )}
          </Button>
        </form>
      </div>
    </div>
  )
}
