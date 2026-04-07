import { Drawer, Descriptions, Tag, Space, Button, Alert, Tabs, Typography } from 'antd'
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  QuestionCircleOutlined,
  CopyOutlined,
} from '@ant-design/icons'
import type { Finding, FindingStatus } from '@/types/models'
import CodeHighlight from './CodeHighlight'

const { Title, Paragraph, Text } = Typography

interface FindingDrawerProps {
  finding: Finding | null
  open: boolean
  onClose: () => void
  onStatusChange?: (findingId: number, status: FindingStatus) => void
  isUpdating?: boolean
}

const STATUS_MAP: Record<FindingStatus, { text: string; color: string; icon: React.ReactNode }> = {
  pending: { text: '待处理', color: 'default', icon: <QuestionCircleOutlined /> },
  confirmed: { text: '已确认', color: 'success', icon: <CheckCircleOutlined /> },
  false_positive: { text: '误报', color: 'error', icon: <CloseCircleOutlined /> },
  conditional: { text: '有条件', color: 'warning', icon: <QuestionCircleOutlined /> },
}

const SEVERITY_MAP: Record<string, { text: string; color: string }> = {
  critical: { text: '严重', color: 'error' },
  high: { text: '高危', color: 'red' },
  medium: { text: '中危', color: 'orange' },
  low: { text: '低危', color: 'green' },
  info: { text: '信息', color: 'blue' },
}

/**
 * 漏洞详情抽屉组件
 */
export default function FindingDrawer({
  finding,
  open,
  onClose,
  onStatusChange,
  isUpdating = false,
}: FindingDrawerProps) {
  if (!finding) return null

  const statusConfig = STATUS_MAP[finding.status] || STATUS_MAP.pending
  const severityConfig = SEVERITY_MAP[finding.severity] || { text: finding.severity, color: 'default' }

  // 从文件路径推断语言
  const fileExt = finding.file_path.split('.').pop()?.toLowerCase() || ''
  const languageMap: Record<string, string> = {
    py: 'python',
    js: 'javascript',
    ts: 'typescript',
    jsx: 'jsx',
    tsx: 'tsx',
    java: 'java',
    go: 'go',
    c: 'c',
    cpp: 'cpp',
    cs: 'csharp',
    php: 'php',
    rb: 'ruby',
    rs: 'rust',
  }

  const handleStatusChange = (newStatus: FindingStatus) => {
    if (onStatusChange && !isUpdating) {
      onStatusChange(finding.id, newStatus)
    }
  }

  const copyEvidence = () => {
    if (finding.evidence) {
      navigator.clipboard.writeText(finding.evidence)
    }
  }

  return (
    <Drawer
      title={
        <Space>
          <span>漏洞 #{finding.id}</span>
          <Tag color={severityConfig.color}>{severityConfig.text}</Tag>
          <Tag color={statusConfig.color} icon={statusConfig.icon}>
            {statusConfig.text}
          </Tag>
        </Space>
      }
      placement="right"
      width={720}
      open={open}
      onClose={onClose}
    >
      {/* 状态操作区 */}
      <div style={{ marginBottom: 16 }}>
        <Space>
          <span>标记为:</span>
          <Button
            size="small"
            type={finding.status === 'confirmed' ? 'primary' : 'default'}
            icon={<CheckCircleOutlined />}
            onClick={() => handleStatusChange('confirmed')}
            disabled={isUpdating}
          >
            已确认
          </Button>
          <Button
            size="small"
            type={finding.status === 'false_positive' ? 'primary' : 'default'}
            danger
            icon={<CloseCircleOutlined />}
            onClick={() => handleStatusChange('false_positive')}
            disabled={isUpdating}
          >
            误报
          </Button>
          <Button
            size="small"
            type={finding.status === 'conditional' ? 'primary' : 'default'}
            icon={<QuestionCircleOutlined />}
            onClick={() => handleStatusChange('conditional')}
            disabled={isUpdating}
          >
            有条件
          </Button>
        </Space>
      </div>

      <Tabs
        defaultActiveKey="overview"
        items={[
          {
            key: 'overview',
            label: '概览',
            children: (
              <>
                {/* 基本信息 */}
                <Descriptions size="small" column={2} bordered>
                  <Descriptions.Item label="漏洞类型" span={2}>
                    {finding.vuln_type}
                  </Descriptions.Item>
                  <Descriptions.Item label="严重程度" span={2}>
                    <Tag color={severityConfig.color}>{severityConfig.text}</Tag>
                    <span style={{ marginLeft: 8 }}>
                      置信度: {(finding.confidence * 100).toFixed(0)}%
                    </span>
                  </Descriptions.Item>
                  <Descriptions.Item label="文件位置" span={2}>
                    <Text code>{finding.file_path}</Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="行号" span={2}>
                    {finding.line_start && finding.line_end
                      ? `${finding.line_start} - ${finding.line_end}`
                      : finding.line_start || '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="函数" span={2}>
                    {finding.function_name || '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="检测引擎" span={2}>
                    {finding.engine}
                  </Descriptions.Item>
                </Descriptions>

                {/* 描述 */}
                {finding.description && (
                  <div style={{ marginTop: 16 }}>
                    <Title level={5}>描述</Title>
                    <Paragraph>{finding.description}</Paragraph>
                  </div>
                )}

                {/* 修复建议 */}
                {finding.remediation && (
                  <div style={{ marginTop: 16 }}>
                    <Title level={5}>修复建议</Title>
                    <Alert
                      message="建议措施"
                      description={finding.remediation}
                      type="info"
                      showIcon
                    />
                  </div>
                )}
              </>
            ),
          },
          {
            key: 'code',
            label: '代码',
            children: finding.evidence ? (
              <>
                <div style={{ marginBottom: 8 }}>
                  <Space>
                    <Text type="secondary">问题代码片段</Text>
                    <Button size="small" icon={<CopyOutlined />} onClick={copyEvidence}>
                      复制
                    </Button>
                  </Space>
                </div>
                <CodeHighlight
                  code={finding.evidence}
                  language={languageMap[fileExt] || 'text'}
                  highlightLine={finding.line_start || undefined}
                  startLine={finding.line_start || 1}
                />
              </>
            ) : (
              <Alert message="无代码证据" type="warning" />
            ),
          },
          {
            key: 'metadata',
            label: '元数据',
            children: (
              <Descriptions size="small" column={1} bordered>
                <Descriptions.Item label="漏洞 ID">{finding.id}</Descriptions.Item>
                <Descriptions.Item label="扫描 ID">{finding.scan_id}</Descriptions.Item>
                <Descriptions.Item label="创建时间">
                  {new Date(finding.created_at).toLocaleString('zh-CN')}
                </Descriptions.Item>
                {finding.cpg_path && (
                  <Descriptions.Item label="CPG 路径" span={2}>
                    <pre style={{ margin: 0, fontSize: '12px' }}>
                      {JSON.stringify(finding.cpg_path, null, 2)}
                    </pre>
                  </Descriptions.Item>
                )}
              </Descriptions>
            ),
          },
        ]}
      />
    </Drawer>
  )
}
