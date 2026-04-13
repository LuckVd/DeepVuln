import { useState, useEffect } from 'react'
import { Card } from '@/components/ui'
import { Globe } from 'lucide-react'
import { TIMEZONES, getTimezone, setTimezone, getTimezoneOffset } from '@/utils/format'

interface GeneralSettingsCardProps {
  settings: Record<string, string | number>
  onUpdate: (key: string, value: string) => void
}

export function GeneralSettingsCard({ settings, onUpdate }: GeneralSettingsCardProps) {
  const [timezone, setTimezoneState] = useState<string>(() => {
    const tz = settings['general.timezone']
    return (typeof tz === 'string' ? tz : 'Asia/Shanghai')
  })

  useEffect(() => {
    // 从系统设置加载时区
    const tz = settings['general.timezone']
    if (tz && typeof tz === 'string') {
      setTimezoneState(tz)
      setTimezone(tz)
    }
  }, [settings['general.timezone']])

  const handleTimezoneChange = (value: string) => {
    setTimezoneState(value)
    setTimezone(value)
    onUpdate('general.timezone', value)
  }

  return (
    <Card className="glass-panel">
      <div className="flex items-center gap-3 mb-6">
        <Globe className="h-5 w-5 text-cyan" />
        <h3 className="text-cyan font-mono font-bold">通用配置</h3>
      </div>

      <div className="space-y-6">
        <div>
          <label className="text-sm font-medium text-text-secondary mb-2 block">
            系统时区
          </label>
          <select
            value={timezone}
            onChange={e => handleTimezoneChange(e.target.value)}
            className="w-full max-w-md bg-background border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-cyan"
          >
            {TIMEZONES.map(tz => (
              <option key={tz.value} value={tz.value}>
                {tz.label} ({tz.offset})
              </option>
            ))}
          </select>
          <p className="text-xs text-text-tertiary mt-1">
            当前时区偏移: {getTimezoneOffset(timezone)}
          </p>
          <p className="text-xs text-text-tertiary mt-1">
            用于显示扫描时间、创建时间等
          </p>
        </div>
      </div>
    </Card>
  )
}
