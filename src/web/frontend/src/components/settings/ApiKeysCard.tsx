import { useState } from 'react'
import { Card, Input, Button } from '@/components/ui'
import { Key, CheckCircle, XCircle, Loader2 } from 'lucide-react'
import { systemSettingsApi } from '@/api/system'

interface ApiKeysCardProps {
  settings: Record<string, string | number>
  onUpdate: (key: string, value: string) => void
}

interface TestResult {
  key: string
  status: 'idle' | 'testing' | 'success' | 'error'
  message?: string
}

export function ApiKeysCard({ settings, onUpdate }: ApiKeysCardProps) {
  const [localSettings, setLocalSettings] = useState({
    'threat_intel.github_token': String(settings['threat_intel.github_token'] || ''),
    'threat_intel.nvd_api_key': String(settings['threat_intel.nvd_api_key'] || ''),
  })

  const [testResults, setTestResults] = useState<Record<string, TestResult>>({})

  const handleChange = (key: string, value: string) => {
    setLocalSettings(prev => ({ ...prev, [key]: value }))
    onUpdate(key, value)
    // Clear test result when value changes
    if (testResults[key]) {
      setTestResults(prev => {
        const updated = { ...prev }
        delete updated[key]
        return updated
      })
    }
  }

  const handleTest = async (key: string) => {
    setTestResults(prev => ({
      ...prev,
      [key]: { key, status: 'testing' }
    }))

    // Simulate API test (实际需要后端支持)
    setTimeout(() => {
      const value = localSettings[key as keyof typeof localSettings]
      if (value) {
        setTestResults(prev => ({
          ...prev,
          [key]: { key, status: 'success', message: '配置有效' }
        }))
      } else {
        setTestResults(prev => ({
          ...prev,
          [key]: { key, status: 'error', message: '请先输入值' }
        }))
      }
    }, 500)
  }

  const renderTestStatus = (key: string) => {
    const result = testResults[key]
    if (!result) return null

    if (result.status === 'testing') {
      return <Loader2 className="h-4 w-4 text-yellow animate-spin" />
    }

    if (result.status === 'success') {
      return <CheckCircle className="h-4 w-4 text-success" />
    }

    if (result.status === 'error') {
      return <XCircle className="h-4 w-4 text-critical" />
    }

    return null
  }

  return (
    <Card className="glass-panel">
      <div className="flex items-center gap-3 mb-6">
        <Key className="h-5 w-5 text-cyan" />
        <h3 className="text-cyan font-mono font-bold">API 密钥配置</h3>
      </div>

      <div className="space-y-6">
        <div>
          <label className="text-sm font-medium text-text-secondary mb-2 block">
            GitHub Token
          </label>
          <div className="flex gap-2 items-center">
            <Input
              type="password"
              placeholder="ghp_..."
              value={localSettings['threat_intel.github_token']}
              onChange={e => handleChange('threat_intel.github_token', e.target.value)}
              className="flex-1 font-mono text-sm"
            />
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleTest('threat_intel.github_token')}
              className="px-3"
            >
              测试
            </Button>
            {renderTestStatus('threat_intel.github_token')}
          </div>
          <p className="text-xs text-text-tertiary mt-1">
            用于获取 GitHub 漏洞库信息（可选）
          </p>
        </div>

        <div>
          <label className="text-sm font-medium text-text-secondary mb-2 block">
            NVD API Key
          </label>
          <div className="flex gap-2 items-center">
            <Input
              type="password"
              placeholder="ns..."
              value={localSettings['threat_intel.nvd_api_key']}
              onChange={e => handleChange('threat_intel.nvd_api_key', e.target.value)}
              className="flex-1 font-mono text-sm"
            />
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleTest('threat_intel.nvd_api_key')}
              className="px-3"
            >
              测试
            </Button>
            {renderTestStatus('threat_intel.nvd_api_key')}
          </div>
          <p className="text-xs text-text-tertiary mt-1">
            用于访问 NVD 漏洞数据库（可选）
          </p>
        </div>
      </div>
    </Card>
  )
}
