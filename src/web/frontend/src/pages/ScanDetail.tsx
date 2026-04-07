import { useParams, useNavigate } from 'react-router-dom'
import { useEffect } from 'react'
import {
  Card,
  Row,
  Col,
  Statistic,
  Tag,
  Button,
  Space,
  Progress,
  Descriptions,
  Timeline,
  Alert,
  Spin,
} from 'antd'
import {
  ArrowLeftOutlined,
  PlayCircleOutlined,
  PauseCircleOutlined,
  StopOutlined,
} from '@ant-design/icons'
import { useScan } from '@/hooks/useApi'
import { useScanProgress } from '@/hooks/useScanProgress'
import type { ScanStatus } from '@/types/models'

const STATUS_MAP: Record<ScanStatus, { text: string; color: string }> = {
  pending: { text: '等待中', color: 'default' },
  running: { text: '扫描中', color: 'processing' },
  paused: { text: '已暂停', color: 'warning' },
  completed: { text: '已完成', color: 'success' },
  failed: { text: '失败', color: 'error' },
  cancelled: { text: '已取消', color: 'default' },
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const scanId = parseInt(id || '0')

  const { data: scan, isLoading, error } = useScan(scanId)
  const {
    progress,
    status: progressStatus,
    usingPolling,
    wsState,
    pause,
    resume,
    cancel,
  } = useScanProgress(isNaN(scanId) ? null : scanId, {
    enabled: !isNaN(scanId),
  })

  // 使用 progress 或 scan 的状态（优先使用 progress）
  const currentStatus = (progress?.status || scan?.status || 'pending') as ScanStatus
  const statusConfig = STATUS_MAP[currentStatus] || { text: currentStatus, color: 'default' }

  // 计算控制按钮的可用状态
  const canPause = currentStatus === 'running'
  const canResume = currentStatus === 'paused'
  const canCancel = ['pending', 'running', 'paused'].includes(currentStatus)

  const handlePause = async () => {
    try {
      await pause()
    } catch (err) {
      console.error('Failed to pause:', err)
    }
  }

  const handleResume = async () => {
    try {
      await resume()
    } catch (err) {
      console.error('Failed to resume:', err)
    }
  }

  const handleCancel = async () => {
    try {
      await cancel()
    } catch (err) {
      console.error('Failed to cancel:', err)
    }
  }

  if (isNaN(scanId)) {
    return (
      <Alert
        message="无效的扫描 ID"
        type="error"
        showIcon
        action={
          <Button size="small" onClick={() => navigate('/scans')}>
            返回列表
          </Button>
        }
      />
    )
  }

  if (isLoading) {
    return (
      <div style={{ textAlign: 'center', padding: '100px 0' }}>
        <Spin size="large" />
      </div>
    )
  }

  if (error || !scan) {
    return (
      <Alert
        message="加载失败"
        description="无法加载扫描详情，请稍后重试。"
        type="error"
        showIcon
        action={
          <Button size="small" onClick={() => navigate('/scans')}>
            返回列表
          </Button>
        }
      />
    )
  }

  return (
    <div>
      {/* 头部 */}
      <div style={{ marginBottom: 16 }}>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/scans')}>
          返回扫描列表
        </Button>
      </div>

      {/* 状态卡片 */}
      <Card
        title={
          <Space>
            <span>扫描 #{scan.id}</span>
            <Tag color={statusConfig.color}>{statusConfig.text}</Tag>
            {usingPolling && <Tag color="orange">轮询模式</Tag>}
            {wsState === 'connected' && <Tag color="green">实时连接</Tag>}
          </Space>
        }
        extra={
          <Space>
            {canPause && (
              <Button icon={<PauseCircleOutlined />} onClick={handlePause}>
                暂停
              </Button>
            )}
            {canResume && (
              <Button type="primary" icon={<PlayCircleOutlined />} onClick={handleResume}>
                继续
              </Button>
            )}
            {canCancel && (
              <Button danger icon={<StopOutlined />} onClick={handleCancel}>
                取消
              </Button>
            )}
          </Space>
        }
        style={{ marginBottom: 16 }}
      >
        <Descriptions size="small" column={3}>
          <Descriptions.Item label="项目 ID">{scan.project_id}</Descriptions.Item>
          <Descriptions.Item label="扫描类型">
            {scan.scan_type === 'full' ? '完整扫描' : scan.scan_type === 'base' ? '基础扫描' : '增量扫描'}
          </Descriptions.Item>
          <Descriptions.Item label="创建时间">
            {new Date(scan.created_at).toLocaleString('zh-CN')}
          </Descriptions.Item>
        </Descriptions>

        {/* 进度条 */}
        {currentStatus !== 'failed' && currentStatus !== 'cancelled' && (
          <div style={{ marginTop: 16 }}>
            <Progress
              percent={progress?.progress_percent || scan.progress_percent || 0}
              status={currentStatus === 'running' ? 'active' : currentStatus === 'completed' ? 'success' : 'normal'}
            />
            {scan.current_phase && (
              <div style={{ marginTop: 8, color: '#666', fontSize: 12 }}>
                当前阶段: {scan.current_phase}
                {scan.current_step && ` - ${scan.current_step}`}
              </div>
            )}
          </div>
        )}
      </Card>

      {/* 统计信息 */}
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={6}>
          <Card>
            <Statistic title="总文件数" value={scan.total_files || 0} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="已索引" value={scan.indexed_files || 0} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="已分析" value={scan.analyzed_files || 0} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="发现漏洞"
              value={scan.findings_count || 0}
              valueStyle={{ color: (scan.findings_count || 0) > 0 ? '#cf1322' : undefined }}
            />
          </Card>
        </Col>
      </Row>

      {/* Token 使用情况 */}
      {(scan.tokens_used !== null || scan.tokens_budget !== null) && (
        <Card title="Token 使用情况" style={{ marginBottom: 16 }}>
          <Row gutter={16}>
            <Col span={8}>
              <Statistic title="已使用" value={scan.tokens_used || 0} />
            </Col>
            <Col span={8}>
              <Statistic title="预算" value={scan.tokens_budget || 0} />
            </Col>
            <Col span={8}>
              <Statistic
                title="剩余"
                value={(scan.tokens_budget || 0) - (scan.tokens_used || 0)}
                valueStyle={{
                  color:
                    (scan.tokens_budget || 0) - (scan.tokens_used || 0) <
                    (scan.tokens_budget || 0) * 0.2
                      ? '#cf1322'
                      : undefined,
                }}
              />
            </Col>
          </Row>
          {scan.tokens_budget && scan.tokens_used && (
            <div style={{ marginTop: 16 }}>
              <Progress
                percent={Math.round((scan.tokens_used / scan.tokens_budget) * 100)}
                status={
                  (scan.tokens_used / scan.tokens_budget) > 0.9 ? 'exception' : 'normal'
                }
              />
            </div>
          )}
        </Card>
      )}

      {/* 漏洞统计 */}
      <Card title="漏洞分布" style={{ marginBottom: 16 }}>
        <Row gutter={16}>
          <Col span={4}>
            <Statistic
              title="严重"
              value={scan.critical_count || 0}
              valueStyle={{ color: '#cf1322' }}
            />
          </Col>
          <Col span={4}>
            <Statistic
              title="高危"
              value={scan.high_count || 0}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Col>
          <Col span={4}>
            <Statistic
              title="中危"
              value={scan.medium_count || 0}
              valueStyle={{ color: '#faad14' }}
            />
          </Col>
          <Col span={4}>
            <Statistic
              title="低危"
              value={scan.low_count || 0}
              valueStyle={{ color: '#52c41a' }}
            />
          </Col>
          <Col span={4}>
            <Statistic
              title="信息"
              value={scan.info_count || 0}
              valueStyle={{ color: '#1890ff' }}
            />
          </Col>
          <Col span={4}>
            <Statistic
              title="已验证"
              value={scan.verified_count || 0}
              valueStyle={{ color: '#722ed1' }}
            />
          </Col>
        </Row>
      </Card>

      {/* 阶段时间线 */}
      {progress?.phases && progress.phases.length > 0 && (
        <Card title="扫描阶段">
          <Timeline>
            {progress.phases.map((phase, index) => {
              const isRunning = phase.status === 'running'
              const isCompleted = phase.status === 'completed'
              const isPending = phase.status === 'pending'

              return (
                <Timeline.Item
                  key={index}
                  color={isCompleted ? 'green' : isRunning ? 'blue' : isPending ? 'gray' : 'red'}
                >
                  <div>
                    <strong>{phase.name}</strong>
                    <Tag
                      color={
                        isCompleted
                          ? 'success'
                          : isRunning
                          ? 'processing'
                          : isPending
                          ? 'default'
                          : 'error'
                      }
                      style={{ marginLeft: 8 }}
                    >
                      {phase.status}
                    </Tag>
                  </div>
                  {isRunning && (
                    <Progress
                      percent={phase.progress_percent}
                      size="small"
                      style={{ marginTop: 8 }}
                    />
                  )}
                  <div style={{ marginTop: 4, fontSize: 12, color: '#666' }}>
                    {phase.duration_seconds && `耗时: ${phase.duration_seconds.toFixed(1)}秒`}
                    {phase.findings > 0 && ` | 发现: ${phase.findings} 个漏洞`}
                    {phase.tokens_used > 0 && ` | Tokens: ${phase.tokens_used}`}
                  </div>
                </Timeline.Item>
              )
            })}
          </Timeline>
        </Card>
      )}
    </div>
  )
}
