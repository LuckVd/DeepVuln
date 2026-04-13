import { useState, useEffect, useRef } from 'react'
import { Card } from '@/components/ui'
import { Monitor } from 'lucide-react'
import { useLanguage } from '@/contexts/LanguageContext'
import { LLMConfigCard, LLMConfigForm } from '@/components/llm'
import { ScanSettingsCard, ApiKeysCard, GeneralSettingsCard } from '@/components/settings'
import { llmConfigApi, type LLMConfigListItem, type LLMConfig, type LLMConfigCreate, type LLMValidationResult } from '@/api/llm'
import { systemSettingsApi as systemApi } from '@/api/system'

type ConnectionStatus = 'idle' | 'checking' | 'connected' | 'failed'

export default function SettingsPage() {
  const { t } = useLanguage()
  const [uptime, setUptime] = useState('00:00:00')
  const startTime = useRef(Date.now())

  // LLM Config state
  const [llmConfigs, setLlmConfigs] = useState<LLMConfigListItem[]>([])
  const [loadingConfigs, setLoadingConfigs] = useState(true)
  const [editingConfig, setEditingConfig] = useState<LLMConfig | null>(null)
  const [connectionStatuses, setConnectionStatuses] = useState<Record<number, ConnectionStatus>>({})
  const [validationResults, setValidationResults] = useState<Record<number, LLMValidationResult>>({})

  // System Settings state
  const [systemSettings, setSystemSettings] = useState<Record<string, string | number>>({
    'general.timezone': 'Asia/Shanghai',
    'scan.timeout': 300,
    'scan.max_concurrent_files': 10,
    'threat_intel.github_token': '',
    'threat_intel.nvd_api_key': '',
  })
  const [savingSettings, setSavingSettings] = useState(false)

  // Update uptime every second (time since page load)
  useEffect(() => {
    const updateUptime = () => {
      const elapsed = Math.floor((Date.now() - startTime.current) / 1000)
      const hours = String(Math.floor(elapsed / 3600)).padStart(2, '0')
      const minutes = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0')
      const seconds = String(elapsed % 60).padStart(2, '0')
      setUptime(`${hours}:${minutes}:${seconds}`)
    }
    updateUptime()
    const interval = setInterval(updateUptime, 1000)
    return () => clearInterval(interval)
  }, [])

  // Load LLM configs
  useEffect(() => {
    loadLlmConfigs()
    loadSystemSettings()
  }, [])

  const loadLlmConfigs = async () => {
    setLoadingConfigs(true)
    try {
      const response = await llmConfigApi.list()
      setLlmConfigs(response.items)

      // 后台异步检测连接状态，不阻塞页面显示
      checkConnectionStatuses(response.items)
    } catch (err) {
      console.error('Failed to load LLM configs:', err)
      setLlmConfigs([])
    } finally {
      setLoadingConfigs(false)
    }
  }

  const loadSystemSettings = async () => {
    try {
      const response = await systemApi.get()
      // Extract values from categories
      const settings: Record<string, string | number> = {}
      Object.entries(response.categories).forEach(([category, items]) => {
        Object.entries(items).forEach(([key, value]) => {
          settings[key] = value
        })
      })
      setSystemSettings(settings)
    } catch (err) {
      console.error('Failed to load system settings:', err)
    }
  }

  // 检测所有配置的连接状态
  const checkConnectionStatuses = async (configs: LLMConfigListItem[]) => {
    // 重置状态
    setConnectionStatuses({})
    setValidationResults({})

    // 只检测有 API Key 的配置
    const configsWithKey = configs.filter(c => c.has_api_key)

    if (configsWithKey.length === 0) return

    // 设置所有配置为检测中
    const checkingStatuses: Record<number, ConnectionStatus> = {}
    configsWithKey.forEach(c => {
      checkingStatuses[c.id] = 'checking'
    })
    setConnectionStatuses(prev => ({ ...prev, ...checkingStatuses }))

    // 并行检测所有配置
    const results = await Promise.allSettled(
      configsWithKey.map(config =>
        llmConfigApi.validate(config.id).then(result => ({ config, result }))
      )
    )

    // 更新检测结果
    const newStatuses: Record<number, ConnectionStatus> = {}
    const newResults: Record<number, LLMValidationResult> = {}

    results.forEach((result, index) => {
      const config = configsWithKey[index]
      if (result.status === 'fulfilled') {
        if (result.value.result.success) {
          newStatuses[config.id] = 'connected'
        } else {
          newStatuses[config.id] = 'failed'
        }
        newResults[config.id] = result.value.result
      } else {
        newStatuses[config.id] = 'failed'
        newResults[config.id] = { success: false, message: '检测失败' }
      }
    })

    setConnectionStatuses(prev => ({ ...prev, ...newStatuses }))
    setValidationResults(prev => ({ ...prev, ...newResults }))
  }

  const handleUpdateLlmConfig = async (data: LLMConfigCreate) => {
    if (!editingConfig) return
    try {
      await llmConfigApi.update(editingConfig.id, data)
      setEditingConfig(null)
      await loadLlmConfigs()
    } catch (err) {
      console.error('Failed to update LLM config:', err)
      throw err
    }
  }

  const handleEditLlmConfig = async (config: LLMConfigListItem) => {
    try {
      const fullConfig = await llmConfigApi.get(config.id)
      setEditingConfig(fullConfig)
    } catch (err) {
      console.error('Failed to load LLM config:', err)
    }
  }

  const handleUpdateSystemSetting = async (key: string, value: string) => {
    setSystemSettings(prev => ({ ...prev, [key]: value }))
    setSavingSettings(true)

    try {
      await systemApi.update({
        settings: {
          [key]: value || null  // 空字符串转为 null
        }
      })
    } catch (err) {
      console.error('Failed to update system settings:', err)
      // Revert on error
      loadSystemSettings()
    } finally {
      setSavingSettings(false)
    }
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-text-primary font-mono tracking-wider">
            {t('settings.title')}
          </h1>
          <span className="text-cyan">//</span>
          <span className="text-cyan font-mono">{t('settings.configuration')}</span>
        </div>
        <p className="text-text-secondary font-sans">{t('settings.subtitle')}</p>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* LLM Configuration */}
        <Card className="glass-panel col-span-2">
          <div className="flex items-center gap-3 mb-6">
            <span className="text-2xl">🤖</span>
            <h3 className="text-cyan font-mono font-bold text-lg">LLM 配置</h3>
          </div>

          {loadingConfigs ? (
            <div className="text-center py-8 text-text-secondary font-mono">
              加载中...
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-6">
              {/* Agent 扫描配置 */}
              {(() => {
                const agentConfig = llmConfigs.find(c => c.config_type === 'agent_scan')
                return agentConfig ? (
                  <LLMConfigCard
                    key={agentConfig.id}
                    config={agentConfig}
                    onEdit={handleEditLlmConfig}
                    connectionStatus={connectionStatuses[agentConfig.id]}
                    validationResult={validationResults[agentConfig.id]}
                  />
                ) : (
                  <Card className="glass-panel py-12 text-center text-text-tertiary font-mono">
                    <div className="text-3xl mb-2">🔵</div>
                    <div className="font-bold mb-1">Agent 扫描配置</div>
                    <div className="text-sm">未配置</div>
                  </Card>
                )
              })()}

              {/* 对抗性验证配置 */}
              {(() => {
                const verifyConfig = llmConfigs.find(c => c.config_type === 'verification')
                return verifyConfig ? (
                  <LLMConfigCard
                    key={verifyConfig.id}
                    config={verifyConfig}
                    onEdit={handleEditLlmConfig}
                    connectionStatus={connectionStatuses[verifyConfig.id]}
                    validationResult={validationResults[verifyConfig.id]}
                  />
                ) : (
                  <Card className="glass-panel py-12 text-center text-text-tertiary font-mono">
                    <div className="text-3xl mb-2">🟠</div>
                    <div className="font-bold mb-1">对抗性验证配置</div>
                    <div className="text-sm">未配置</div>
                  </Card>
                )
              })()}
            </div>
          )}
        </Card>

        {/* General Settings */}
        <GeneralSettingsCard
          settings={systemSettings}
          onUpdate={handleUpdateSystemSetting}
        />

        {/* Scan Settings */}
        <ScanSettingsCard
          settings={systemSettings}
          onUpdate={handleUpdateSystemSetting}
        />

        {/* API Keys */}
        <ApiKeysCard
          settings={systemSettings}
          onUpdate={handleUpdateSystemSetting}
        />

        {/* System Info */}
        <Card className="glass-panel col-span-2">
          <div className="flex items-center gap-3 mb-6">
            <Monitor className="h-5 w-5 text-cyan" />
            <h3 className="text-cyan font-mono font-bold">{t('settings.system')}</h3>
          </div>
          <div className="grid grid-cols-4 gap-6 font-mono text-sm">
            <div className="space-y-2">
              <div className="text-text-secondary">{t('settings.version')}</div>
              <div className="text-cyan">{typeof __APP_VERSION__ !== 'undefined' ? `v${__APP_VERSION__}` : 'dev'}</div>
            </div>
            <div className="space-y-2">
              <div className="text-text-secondary">{t('settings.backend')}</div>
              <div className="text-success">{t('settings.connected')}</div>
            </div>
            <div className="space-y-2">
              <div className="text-text-secondary">{t('settings.websocket')}</div>
              <div className="text-success">{t('settings.active')}</div>
            </div>
            <div className="space-y-2">
              <div className="text-text-secondary">{t('settings.uptime')}</div>
              <div className="text-cyan">{uptime}</div>
            </div>
          </div>
        </Card>
      </div>

      {/* LLM Config Form Dialog */}
      {editingConfig && (
        <LLMConfigForm
          config={editingConfig}
          onSave={handleUpdateLlmConfig}
          onCancel={() => setEditingConfig(null)}
        />
      )}
    </div>
  )
}
