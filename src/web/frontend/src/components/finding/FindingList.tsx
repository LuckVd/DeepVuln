import { Table, Tag, Space, Button, Select, Progress } from 'antd'
import { EyeOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import type { Finding, SeverityLevel, FindingStatus } from '@/types/models'

const STATUS_MAP: Record<FindingStatus, { text: string; color: string }> = {
  pending: { text: '待处理', color: 'default' },
  confirmed: { text: '已确认', color: 'success' },
  false_positive: { text: '误报', color: 'error' },
  conditional: { text: '有条件', color: 'warning' },
}

const SEVERITY_MAP: Record<SeverityLevel, { text: string; color: string }> = {
  critical: { text: '严重', color: 'error' },
  high: { text: '高危', color: 'red' },
  medium: { text: '中危', color: 'orange' },
  low: { text: '低危', color: 'green' },
  info: { text: '信息', color: 'blue' },
}

interface FindingListProps {
  findings: Finding[]
  loading?: boolean
  total: number
  page: number
  pageSize: number
  onPageChange: (page: number, pageSize: number) => void
  onViewDetail: (finding: Finding) => void
}

/**
 * 漏洞列表组件
 */
export default function FindingList({
  findings,
  loading = false,
  total,
  page,
  pageSize,
  onPageChange,
  onViewDetail,
}: FindingListProps) {
  const columns: ColumnsType<Finding> = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 60,
    },
    {
      title: '漏洞类型',
      dataIndex: 'vuln_type',
      key: 'vuln_type',
      ellipsis: true,
      width: 150,
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      width: 90,
      render: (severity: SeverityLevel) => {
        const config = SEVERITY_MAP[severity]
        return <Tag color={config.color}>{config.text}</Tag>
      },
      sorter: (a, b) => {
        const order = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
        return order[a.severity] - order[b.severity]
      },
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      width: 80,
      render: (confidence: number) => (
        <Progress
          percent={Math.round(confidence * 100)}
          size="small"
          status={confidence > 0.8 ? 'exception' : 'normal'}
        />
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (status: FindingStatus) => {
        const config = STATUS_MAP[status]
        return <Tag color={config.color}>{config.text}</Tag>
      },
    },
    {
      title: '文件位置',
      key: 'location',
      ellipsis: true,
      render: (_, record) => (
        <span style={{ fontSize: '12px' }}>
          {record.file_path.split('/').slice(-2).join('/')}:{record.line_start}
        </span>
      ),
    },
    {
      title: '函数',
      dataIndex: 'function_name',
      key: 'function_name',
      ellipsis: true,
      width: 120,
      render: (name) => name || '-',
    },
    {
      title: '引擎',
      dataIndex: 'engine',
      key: 'engine',
      width: 80,
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right' as const,
      render: (_, record) => (
        <Button
          type="link"
          size="small"
          icon={<EyeOutlined />}
          onClick={() => onViewDetail(record)}
        >
          详情
        </Button>
      ),
    },
  ]

  return (
    <Table
      rowKey="id"
      columns={columns}
      dataSource={findings}
      loading={loading}
      pagination={{
        current: page,
        pageSize: pageSize,
        total: total,
        showSizeChanger: true,
        showTotal: (total) => `共 ${total} 个漏洞`,
        onChange: onPageChange,
      }}
      scroll={{ x: 800 }}
      onRow={(record) => ({
        onClick: () => onViewDetail(record),
        style: { cursor: 'pointer' },
      })}
    />
  )
}
