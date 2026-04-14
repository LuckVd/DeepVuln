import { useState } from 'react'
import { Card, Input } from '@/components/ui'
import { Settings } from 'lucide-react'

interface ScanSettingsCardProps {
  settings: Record<string, string | number>
  onUpdate: (key: string, value: string) => void
}

export function ScanSettingsCard({ settings, onUpdate }: ScanSettingsCardProps) {
  const [localSettings, setLocalSettings] = useState({
    'scan.timeout': String(settings['scan.timeout'] || 300),
    'scan.max_concurrent_files': String(settings['scan.max_concurrent_files'] || 10),
    'scan.agent_max_files': String(settings['scan.agent_max_files'] || 50),
  })

  const handleChange = (key: string, value: string) => {
    setLocalSettings(prev => ({ ...prev, [key]: value }))
    onUpdate(key, value)
  }

  return (
    <Card className="glass-panel">
      <div className="flex items-center gap-3 mb-6">
        <Settings className="h-5 w-5 text-cyan" />
        <h3 className="text-cyan font-mono font-bold">扫描配置</h3>
      </div>

      <div className="space-y-6">
        <div>
          <label className="text-sm font-medium text-text-secondary mb-2 block">
            扫描超时时间（秒）
          </label>
          <Input
            type="number"
            value={localSettings['scan.timeout']}
            onChange={e => handleChange('scan.timeout', e.target.value)}
            className="w-32 font-mono"
            min={60}
            max={3600}
          />
          <p className="text-xs text-text-tertiary mt-1">
            单次扫描的最大允许时间
          </p>
        </div>

        <div>
          <label className="text-sm font-medium text-text-secondary mb-2 block">
            最大并发文件数
          </label>
          <Input
            type="number"
            value={localSettings['scan.max_concurrent_files']}
            onChange={e => handleChange('scan.max_concurrent_files', e.target.value)}
            className="w-32 font-mono"
            min={1}
            max={50}
          />
          <p className="text-xs text-text-tertiary mt-1">
            同时处理的文件数量
          </p>
        </div>

        <div>
          <label className="text-sm font-medium text-text-secondary mb-2 block">
            Agent 最大分析文件数
          </label>
          <Input
            type="number"
            value={localSettings['scan.agent_max_files']}
            onChange={e => handleChange('scan.agent_max_files', e.target.value)}
            className="w-32 font-mono"
            min={1}
            max={500}
          />
          <p className="text-xs text-text-tertiary mt-1">
            LLM Agent 最多分析的源码文件数量（1-500）
          </p>
        </div>
      </div>
    </Card>
  )
}
