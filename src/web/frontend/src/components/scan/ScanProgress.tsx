import React from 'react'
import { Card, Progress, Tag, Space, Row, Col, Statistic, Timeline, Descriptions, Button } from 'antd'
import {
  CheckCircleOutlined,
  SyncOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  PauseCircleOutlined,
} from '@ant-design/icons'
import type { ScanProgressResponse, PhaseInfo } from '@/types/models'

interface ScanProgressProps {
  progress: ScanProgressResponse | null
  loading?: boolean
}

const PHASE_LABELS: Record<string, string> = {
  'L1_preparation': 'L1 准备阶段',
  'L1_attack_surface': 'L1 攻击面分析',
  'L2_semgrep': 'L2 Semgrep 扫描',
  'L2_codeql': 'L2 CodeQL 扫描',
  'L3_agent': 'L3 Agent 深度审计',
  'L3_adjudication': 'L3 裁决融合',
  'report_generation': '报告生成',
}

const STATUS_ICONS: Record<string, React.ReactNode> = {
  completed: <CheckCircleOutlined style={{ color: '#52c41a' }} />,
  running: <SyncOutlined spin style={{ color: '#1890ff' }} />,
  pending: <ClockCircleOutlined style={{ color: '#bfbfbf' }} />,
  failed: <CloseCircleOutlined style={{ color: '#ff4d4f' }} />,
  skipped: <PauseCircleOutlined style={{ color: '#bfbfbf' }} />,
}

export function ScanProgress({ progress, loading }: ScanProgressProps) {
  if (loading || !progress) {
    return (
      <Card title="扫描进度" loading={loading}>
        <div className="text-center text-gray-400 py-8">等待扫描数据...</div>
      </Card>
    )
  }

  const getStatusTag = (status: string) => {
    const statusMap: Record<string, { text: string; color: string }> = {
      pending: { text: '等待中', color: 'default' },
      running: { text: '扫描中', color: 'processing' },
      paused: { text: '已暂停', color: 'warning' },
      completed: { text: '已完成', color: 'success' },
      failed: { text: '失败', color: 'error' },
      cancelled: { text: '已取消', color: 'default' },
    }
    const config = statusMap[status] || { text: status, color: 'default' }
    return <Tag color={config.color}>{config.text}</Tag>
  }

  const getPhaseStatusIcon = (phase: PhaseInfo) => {
    return STATUS_ICONS[phase.status] || STATUS_ICONS.pending
  }

  const getPhaseColor = (status: string) => {
    const colorMap: Record<string, string> = {
      completed: 'green',
      running: 'blue',
      pending: 'gray',
      failed: 'red',
      skipped: 'default',
    }
    return colorMap[status] || 'default'
  }

  return (
    <Space direction="vertical" style={{ width: '100%' }} size="large">
      {/* 总体进度 */}
      <Card title="扫描状态" size="small">
        <Row gutter={16} align="middle">
          <Col span={16}>
            <div className="mb-2">
              <span className="text-gray-600">总体进度: </span>
              {getStatusTag(progress.status)}
            </div>
            <Progress
              percent={progress.progress_percent}
              status={progress.status === 'failed' ? 'exception' :
                     progress.status === 'completed' ? 'success' : 'active'}
              strokeColor={{
                '0%': '#108ee9',
                '100%': '#87d068',
              }}
            />
            {progress.current_step && (
              <div className="text-sm text-gray-500 mt-2">{progress.current_step}</div>
            )}
          </Col>
          <Col span={8}>
            <Row gutter={8}>
              <Col span={8}>
                <Statistic title="文件" value={progress.analyzed_files} suffix={`/ ${progress.total_files}`} />
              </Col>
              <Col span={8}>
                <Statistic title="漏洞" value={progress.findings.total} />
              </Col>
              <Col span={8}>
                <Statistic title="Token" value={progress.tokens.used} suffix={`/ ${progress.tokens.budget}`} />
              </Col>
            </Row>
          </Col>
        </Row>
      </Card>

      {/* 阶段进度 */}
      <Card title="扫描阶段" size="small">
        <Timeline
          items={progress.phases.map((phase) => ({
            color: getPhaseColor(phase.status),
            dot: getPhaseStatusIcon(phase),
            children: (
              <div>
                <div className="flex justify-between items-center">
                  <span className="font-medium">
                    {PHASE_LABELS[phase.name] || phase.name}
                  </span>
                  <Tag color={getPhaseColor(phase.status)}>{phase.status}</Tag>
                </div>
                {phase.status === 'running' && (
                  <Progress
                    percent={phase.progress_percent}
                    size="small"
                    showInfo={false}
                    className="mt-1"
                  />
                )}
                {phase.status === 'completed' && (
                  <Descriptions size="small" column={3} className="mt-1">
                    <Descriptions.Item label="耗时">{phase.duration_seconds?.toFixed(1)}s</Descriptions.Item>
                    <Descriptions.Item label="漏洞">{phase.findings}</Descriptions.Item>
                    <Descriptions.Item label="Token">{phase.tokens_used}</Descriptions.Item>
                  </Descriptions>
                )}
              </div>
            ),
          }))}
        />
      </Card>

      {/* 引擎状态 */}
      <Card title="引擎状态" size="small">
        <Descriptions size="small" column={3} bordered>
          <Descriptions.Item label="已完成">
            <Space>
              {progress.engines.completed.map((engine) => (
                <Tag key={engine} color="green">{engine}</Tag>
              ))}
              {progress.engines.completed.length === 0 && <span className="text-gray-400">-</span>}
            </Space>
          </Descriptions.Item>
          <Descriptions.Item label="运行中">
            <Space>
              {progress.engines.running ? (
                <Tag color="blue" icon={<SyncOutlined spin />}>{progress.engines.running}</Tag>
              ) : (
                <span className="text-gray-400">-</span>
              )}
            </Space>
          </Descriptions.Item>
          <Descriptions.Item label="等待中">
            <Space>
              {progress.engines.pending.map((engine) => (
                <Tag key={engine} color="default">{engine}</Tag>
              ))}
              {progress.engines.pending.length === 0 && <span className="text-gray-400">-</span>}
            </Space>
          </Descriptions.Item>
        </Descriptions>
      </Card>

      {/* 漏洞统计 */}
      <Card title="漏洞统计" size="small">
        <Row gutter={16}>
          <Col span={4}>
            <Statistic
              title="总计"
              value={progress.findings.total}
              valueStyle={{ color: progress.findings.total > 0 ? '#cf1322' : undefined }}
            />
          </Col>
          <Col span={4}>
            <Statistic
              title="已验证"
              value={progress.findings.verified}
              valueStyle={{ color: '#52c41a' }}
            />
          </Col>
          <Col span={4}>
            <Statistic
              title="误报"
              value={progress.findings.false_positive}
              valueStyle={{ color: '#bfbfbf' }}
            />
          </Col>
          <Col span={4}>
            <Statistic
              title="严重"
              value={progress.findings.by_severity.critical}
              valueStyle={{ color: progress.findings.by_severity.critical > 0 ? '#cf1322' : undefined }}
            />
          </Col>
          <Col span={4}>
            <Statistic
              title="高危"
              value={progress.findings.by_severity.high}
              valueStyle={{ color: progress.findings.by_severity.high > 0 ? '#fa8c16' : undefined }}
            />
          </Col>
          <Col span={4}>
            <Statistic
              title="中危"
              value={progress.findings.by_severity.medium}
              valueStyle={{ color: progress.findings.by_severity.medium > 0 ? '#fadb14' : undefined }}
            />
          </Col>
        </Row>
      </Card>
    </Space>
  )
}

export default ScanProgress
