import { useState, useEffect } from 'react'
import { Loader2, Zap, RefreshCw, CheckCircle, XCircle } from 'lucide-react'
import { Card, Input, Button, CustomSelect } from '@/components/ui'
import { llmConfigApi, type LLMConfig, type LLMConfigCreate, type LLMValidationResult, type LLMModelsResult } from '@/api/llm'

interface LLMConfigFormProps {
  config?: LLMConfig
  onSave: (data: LLMConfigCreate) => Promise<void>
  onCancel: () => void
}

type LLMProvider = 'openai' | 'azure' | 'ollama' | 'custom'

interface ProviderOption {
  value: LLMProvider
  label: string
}

const COMMON_PROVIDERS: ProviderOption[] = [
  { value: 'openai', label: 'OpenAI' },
  { value: 'azure', label: 'Azure OpenAI' },
  { value: 'ollama', label: 'Ollama' },
  { value: 'custom', label: '自定义 (兼容 OpenAI)' }
]

const PROVIDER_DEFAULT_URLS: Record<LLMProvider, string> = {
  openai: 'https://api.openai.com/v1',
  azure: '',
  ollama: 'http://localhost:11434',
  custom: ''
}

// 根据配置类型获取标题和描述
const getConfigInfo = (configType: string) => {
  const info: Record<string, { title: string; description: string; icon: string }> = {
    agent_scan: {
      title: '编辑 Agent 扫描配置',
      description: '用于代码安全审计，分析漏洞模式',
      icon: '🔵'
    },
    verification: {
      title: '编辑 对抗性验证配置',
      description: '用于 LLM 辩论系统，验证漏洞真实性',
      icon: '🟠'
    },
    both: {
      title: '编辑 LLM 配置',
      description: '通用配置，可用于扫描和验证',
      icon: '⚪'
    }
  }
  return info[configType] || info.both
}

// 根据配置类型获取并发数标签
const getConfigConcurrencyLabel = (configType?: string) => {
  const labels: Record<string, string> = {
    agent_scan: 'Agent 扫描 LLM 最大并发数',
    verification: '对抗性验证 LLM 最大并发数',
    both: 'LLM 最大并发数'
  }
  return labels[configType || 'both'] || labels.both
}

export function LLMConfigForm({ config, onSave, onCancel }: LLMConfigFormProps) {
  const [formData, setFormData] = useState<Partial<LLMConfigCreate>>({
    name: '',
    provider: 'openai',
    api_key: '',
    base_url: 'https://api.openai.com/v1',
    model: '',
    context_size: 128000,
    temperature: 0,
    max_tokens: 4096,
    timeout: 120,
    max_concurrent_requests: 10,
    config_type: 'both',
    is_default: false
  })

  const [errors, setErrors] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)

  // 模型相关状态
  const [availableModels, setAvailableModels] = useState<string[]>([])
  const [showModelDropdown, setShowModelDropdown] = useState(false)
  const [loadingModels, setLoadingModels] = useState(false)

  // 测试连接状态
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<LLMValidationResult | null>(null)

  const isEdit = !!config
  const configInfo = isEdit ? getConfigInfo(config.config_type) : { title: '新增 LLM 配置', description: '', icon: '' }

  useEffect(() => {
    if (config) {
      setFormData({
        name: config.name,
        provider: config.provider as LLMProvider,
        // 如果 API Key 是屏蔽格式，清空显示（保持原值不变）
        api_key: config.api_key?.startsWith('***') ? '' : (config.api_key || ''),
        base_url: config.base_url || '',
        model: config.model,
        context_size: config.context_size,
        temperature: config.temperature,
        max_tokens: config.max_tokens,
        timeout: config.timeout,
        max_concurrent_requests: config.max_concurrent_requests || 10,
        config_type: config.config_type,
        is_default: config.is_default
      })
    }
  }, [config])

  const handleProviderChange = (value: string) => {
    const provider = value as LLMProvider
    const defaultBaseUrl = PROVIDER_DEFAULT_URLS[provider] || ''

    setFormData(prev => ({ ...prev, provider, base_url: defaultBaseUrl }))
    // 清空模型列表和测试结果
    setAvailableModels([])
    setTestResult(null)
  }

  const handleFetchModels = async () => {
    // 验证必填字段
    if (!formData.base_url) {
      setErrors({ base_url: '请先输入 Base URL' })
      return
    }

    setLoadingModels(true)
    setErrors({})

    try {
      // 创建临时配置来获取模型列表
      const tempConfig: LLMConfigCreate = {
        name: '_temp',
        provider: formData.provider || 'openai',
        api_key: formData.api_key,
        base_url: formData.base_url,
        model: 'temp',
        config_type: formData.config_type || 'both'
      }

      // 先创建临时配置
      const created = await llmConfigApi.create(tempConfig)

      // 获取模型列表
      const modelsResult = await llmConfigApi.getModels(created.id)

      setAvailableModels(modelsResult.models || [])

      // 删除临时配置
      await llmConfigApi.delete(created.id)

      if (modelsResult.models.length === 0) {
        setErrors({ model: '未获取到模型列表，请手动输入' })
      }
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || '获取模型列表失败'
      setErrors({ model: errorMsg })
    } finally {
      setLoadingModels(false)
    }
  }

  const handleTestConnection = async () => {
    // 验证必填字段
    const newErrors: Record<string, string> = {}
    if (!formData.base_url?.trim()) {
      newErrors.base_url = '请输入 Base URL'
    }
    if (!formData.model?.trim()) {
      newErrors.model = '请输入模型名称'
    }
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      return
    }

    setTesting(true)
    setTestResult(null)
    setErrors({})

    try {
      // 创建临时配置来测试连接
      const tempConfig: LLMConfigCreate = {
        name: '_temp_test',
        provider: formData.provider || 'openai',
        api_key: formData.api_key,
        base_url: formData.base_url,
        model: formData.model || '',
        temperature: formData.temperature || 0,
        timeout: formData.timeout || 120,
        config_type: formData.config_type || 'both'
      }

      const created = await llmConfigApi.create(tempConfig)
      const result = await llmConfigApi.validate(created.id)
      await llmConfigApi.delete(created.id)

      setTestResult(result)
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || '测试连接失败'
      setTestResult({
        success: false,
        message: errorMsg
      })
    } finally {
      setTesting(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // Validation
    const newErrors: Record<string, string> = {}

    if (!formData.name?.trim()) {
      newErrors.name = '请输入配置名称'
    }

    if (!formData.model?.trim()) {
      newErrors.model = '请输入模型名称'
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      return
    }

    setSaving(true)
    try {
      await onSave(formData as LLMConfigCreate)
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || '保存失败'
      setErrors({ form: errorMsg })
    } finally {
      setSaving(false)
    }
  }

  const handleModelSelect = (model: string) => {
    setFormData(prev => ({ ...prev, model }))
    setShowModelDropdown(false)
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <Card className="sm:max-w-lg w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex items-center gap-3 mb-2">
            {isEdit && <span className="text-xl">{configInfo.icon}</span>}
            <h2 className="text-xl font-bold text-cyan font-mono">
              {configInfo.title}
            </h2>
          </div>
          {isEdit && configInfo.description && (
            <p className="text-sm text-text-secondary mb-4">{configInfo.description}</p>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {errors.form && (
              <div className="p-3 rounded bg-critical/10 border border-critical/30">
                <p className="text-sm text-critical font-mono">⚠ {errors.form}</p>
              </div>
            )}

            <Input
              label="配置名称"
              placeholder="如: Agent 扫描配置"
              value={formData.name}
              onChange={e => setFormData({ ...formData, name: e.target.value })}
              error={errors.name}
            />

            <CustomSelect
              label="提供商"
              value={formData.provider || 'openai'}
              onChange={handleProviderChange}
              options={COMMON_PROVIDERS}
            />

            <Input
              label="Base URL"
              placeholder="https://api.openai.com/v1"
              value={formData.base_url}
              onChange={e => setFormData({ ...formData, base_url: e.target.value })}
              error={errors.base_url}
            />

            <div className="space-y-2">
              <label className="text-sm font-medium text-text-secondary">API Key</label>
              <Input
                type="password"
                placeholder="sk-..."
                value={formData.api_key}
                onChange={e => setFormData({ ...formData, api_key: e.target.value })}
                error={errors.api_key}
              />
              {isEdit && !formData.api_key && (
                <p className="text-xs text-text-tertiary">
                  当前 API Key 已隐藏，如需修改请输入新的 API Key
                </p>
              )}
            </div>

            {/* 模型输入 + 获取模型按钮 */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-text-secondary">模型</label>
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <Input
                    placeholder="手动输入模型名称，或点击获取"
                    value={formData.model}
                    onChange={e => {
                      setFormData({ ...formData, model: e.target.value })
                      setShowModelDropdown(true)
                    }}
                    error={errors.model}
                    onFocus={() => {
                      if (availableModels.length > 0) {
                        setShowModelDropdown(true)
                      }
                    }}
                  />
                  {/* 模型下拉列表 */}
                  {showModelDropdown && availableModels.length > 0 && (
                    <div className="absolute top-full left-0 right-0 mt-1 bg-background-primary border border-border rounded-md shadow-lg max-h-48 overflow-y-auto z-10">
                      {availableModels.map(model => (
                        <div
                          key={model}
                          className="px-3 py-2 text-sm cursor-pointer hover:bg-cyan/10 font-mono"
                          onClick={() => handleModelSelect(model)}
                        >
                          {model}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleFetchModels}
                  disabled={loadingModels}
                  className="px-3"
                  title="获取可用模型列表"
                >
                  {loadingModels ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4" />
                  )}
                </Button>
              </div>
              <p className="text-xs text-text-tertiary">
                可手动输入模型名称，或点击按钮获取可用模型列表
              </p>
            </div>

            <div className="grid grid-cols-3 gap-4">
              <Input
                label="上下文大小"
                type="number"
                value={formData.context_size}
                onChange={e => setFormData({ ...formData, context_size: parseInt(e.target.value) || 128000 })}
              />

              <Input
                label="Temperature"
                type="number"
                step="0.1"
                min="0"
                max="2"
                value={formData.temperature}
                onChange={e => setFormData({ ...formData, temperature: parseFloat(e.target.value) || 0 })}
              />

              <Input
                label="超时 (秒)"
                type="number"
                value={formData.timeout}
                onChange={e => setFormData({ ...formData, timeout: parseInt(e.target.value) || 120 })}
              />
            </div>

            {/* 最大并发数 */}
            <Input
              label={getConfigConcurrencyLabel(formData.config_type)}
              type="number"
              min="1"
              max="50"
              value={formData.max_concurrent_requests}
              onChange={e => setFormData({ ...formData, max_concurrent_requests: parseInt(e.target.value) || 10 })}
              helperText="同时进行的 LLM 请求数量"
            />

            {/* 测试连接 */}
            <div className="space-y-2">
              <Button
                type="button"
                variant="outline"
                onClick={handleTestConnection}
                disabled={testing}
                className="w-full"
              >
                {testing ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    测试中...
                  </>
                ) : (
                  <>
                    <Zap className="mr-2 h-4 w-4" />
                    测试连接
                  </>
                )}
              </Button>

              {/* 测试结果 */}
              {testResult && (
                <div className={`p-3 rounded flex items-center gap-2 ${
                  testResult.success
                    ? 'bg-success/10 border border-success/30'
                    : 'bg-critical/10 border border-critical/30'
                }`}>
                  {testResult.success ? (
                    <CheckCircle className="h-4 w-4 text-success flex-shrink-0" />
                  ) : (
                    <XCircle className="h-4 w-4 text-critical flex-shrink-0" />
                  )}
                  <span className={`text-sm font-mono ${
                    testResult.success ? 'text-success' : 'text-critical'
                  }`}>
                    {testResult.message}
                    {testResult.latency_ms && ` (${testResult.latency_ms}ms)`}
                  </span>
                </div>
              )}
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="is_default"
                checked={formData.is_default}
                onChange={e => setFormData({ ...formData, is_default: e.target.checked })}
                className="w-4 h-4 rounded border-border bg-background-primary text-cyan focus:ring-2 focus:ring-cyan"
              />
              <label htmlFor="is_default" className="text-sm text-text-secondary">
                设为默认配置
              </label>
            </div>

            <div className="flex justify-end gap-3 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={onCancel}
                disabled={saving}
              >
                取消
              </Button>
              <Button type="submit" disabled={saving}>
                {saving ? '保存中...' : '保存'}
              </Button>
            </div>
          </form>
        </div>
      </Card>
    </div>
  )
}
