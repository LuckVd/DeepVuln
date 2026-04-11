import { Edit, CheckCircle, XCircle, Loader2, AlertCircle, Cpu } from 'lucide-react'
import { Card, Button } from '@/components/ui'
import { type LLMConfigListItem, type LLMValidationResult } from '@/api/llm'

type ConnectionStatus = 'idle' | 'checking' | 'connected' | 'failed'

interface LLMConfigCardProps {
  config: LLMConfigListItem
  onEdit: (config: LLMConfigListItem) => void
  connectionStatus?: ConnectionStatus
  validationResult?: LLMValidationResult | null
}

export function LLMConfigCard({
  config,
  onEdit,
  connectionStatus = 'idle',
  validationResult
}: LLMConfigCardProps) {
  const getProviderLabel = (provider: string): string => {
    const labels: Record<string, string> = {
      openai: 'OpenAI',
      azure: 'Azure',
      ollama: 'Ollama',
      custom: '自定义'
    }
    return labels[provider] || provider
  }

  const getConfigTypeInfo = (type: string) => {
    const info: Record<string, {
      icon: string
      title: string
      description: string
      tips: string[]
      color: string
    }> = {
      agent_scan: {
        icon: '🔵',
        title: 'Agent 扫描',
        description: '用于代码安全审计，分析漏洞模式',
        tips: ['核心分析工作，建议使用推理能力强的高质量模型'],
        color: 'text-purple'
      },
      verification: {
        icon: '🟠',
        title: '对抗性验证',
        description: 'LLM 辩论系统，三方角色验证漏洞真实性',
        tips: ['消耗 Token 较大（多轮辩论），建议根据预算选择性价比高的模型'],
        color: 'text-orange'
      },
      both: {
        icon: '⚪',
        title: '通用配置',
        description: '可用于扫描和验证',
        tips: ['建议根据实际使用场景选择'],
        color: 'text-cyan'
      }
    }
    return info[type] || info.both
  }

  const getConfigConcurrencyLabel = (type: string) => {
    const labels: Record<string, string> = {
      agent_scan: 'Agent 扫描并发',
      verification: '验证并发',
      both: 'LLM 并发'
    }
    return labels[type] || labels.both
  }

  const configTypeInfo = getConfigTypeInfo(config.config_type)
  const concurrencyLabel = getConfigConcurrencyLabel(config.config_type)

  const renderConnectionStatus = () => {
    if (connectionStatus === 'checking') {
      return (
        <span className="flex items-center gap-1 text-yellow text-xs">
          <Loader2 className="h-3 w-3 animate-spin" />
          检测中
        </span>
      )
    }

    if (connectionStatus === 'connected') {
      return (
        <span className="flex items-center gap-1 text-success text-xs">
          <CheckCircle className="h-3 w-3" />
          {validationResult?.latency_ms ? `${validationResult.latency_ms}ms` : '连接正常'}
        </span>
      )
    }

    if (connectionStatus === 'failed') {
      return (
        <span className="flex items-center gap-1 text-critical text-xs" title={validationResult?.message}>
          <XCircle className="h-3 w-3" />
          连接失败
        </span>
      )
    }

    return null
  }

  return (
    <Card className="glass-panel">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <span className="text-2xl">{configTypeInfo.icon}</span>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-bold text-text-primary">{configTypeInfo.title}</h3>
              {config.is_default && (
                <span className="px-2 py-0.5 text-xs bg-cyan/20 text-cyan rounded">默认</span>
              )}
            </div>
            <p className="text-sm text-text-secondary">{configTypeInfo.description}</p>
          </div>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => onEdit(config)}
          className="h-8 px-2 text-xs"
        >
          <Edit className="h-3 w-3" />
        </Button>
      </div>

      {/* Tips */}
      <div className={`flex items-start gap-2 mb-4 p-3 rounded-md bg-${configTypeInfo.color.split('-')[1]}/5 border border-${configTypeInfo.color.split('-')[1]}/10`}>
        <AlertCircle className={`h-4 w-4 ${configTypeInfo.color} flex-shrink-0 mt-0.5`} />
        <div className="text-xs text-text-secondary space-y-1">
          {configTypeInfo.tips.map((tip, index) => (
            <div key={index}>• {tip}</div>
          ))}
        </div>
      </div>

      {/* Config Details */}
      <div className="flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-3 text-text-secondary">
          <span>{getProviderLabel(config.provider)}</span>
          <span className="text-cyan">•</span>
          <span className="text-text-primary">{config.model}</span>
          <span className="text-cyan">•</span>
          <span>API Key: {config.has_api_key ? '已配置' : '未配置'}</span>
          <span className="text-cyan">•</span>
          <span className="flex items-center gap-1" title={getConfigConcurrencyLabel(config.config_type) + '：同时进行的 LLM 请求数量'}>
            <Cpu className="h-3 w-3" />
            {concurrencyLabel}: {config.max_concurrent_requests}
          </span>
        </div>
        {renderConnectionStatus()}
      </div>
    </Card>
  )
}
