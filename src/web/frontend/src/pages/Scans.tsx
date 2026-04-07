import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Button,
  Card,
  Table,
  Tag,
  Space,
  Select,
  Progress,
  message,
} from 'antd'
import { EyeOutlined, ReloadOutlined } from '@ant-design/icons'
import { useScans } from '@/hooks/useApi'
import type { Scan, ScanStatus } from '@/types/models'
import type { ColumnsType } from 'antd/es/table'

const STATUS_MAP: Record<ScanStatus, { text: string; color: string }> = {
  pending: { text: '等待中', color: 'default' },
  running: { text: '扫描中', color: 'processing' },
  paused: { text: '已暂停', color: 'warning' },
  completed: { text: '已完成', color: 'success' },
  failed: { text: '失败', color: 'error' },
  cancelled: { text: '已取消', color: 'default' },
}

const SCAN_TYPE_MAP: Record<string, string> = {
  full: '完整扫描',
  base: '基础扫描',
  incremental: '增量扫描',
}

export default function ScansPage() {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [statusFilter, setStatusFilter] = useState<ScanStatus | undefined>()

  const { data, isLoading, refetch } = useScans({
    page,
    page_size: pageSize,
    status: statusFilter,
  })

  const columns: ColumnsType<Scan> = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 60,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: ScanStatus, record) => {
        const config = STATUS_MAP[status]
        return (
          <Space>
            <Tag color={config.color}>{config.text}</Tag>
            {status === 'running' && (
              <Tag color="blue">{record.progress_percent || 0}%</Tag>
            )}
          </Space>
        )
      },
    },
    {
      title: '扫描类型',
      dataIndex: 'scan_type',
      key: 'scan_type',
      width: 100,
      render: (type) => SCAN_TYPE_MAP[type] || type,
    },
    {
      title: '进度',
      dataIndex: 'progress_percent',
      key: 'progress_percent',
      width: 150,
      render: (progress, record) => {
        if (record.status === 'completed') {
          return <Tag color="success">100%</Tag>
        }
        if (record.status === 'failed' || record.status === 'cancelled') {
          return <Tag>-</Tag>
        }
        return (
          <Progress
            percent={progress || 0}
            size="small"
            status={record.status === 'running' ? 'active' : 'normal'}
          />
        )
      },
    },
    {
      title: '当前阶段',
      dataIndex: 'current_phase',
      key: 'current_phase',
      ellipsis: true,
      render: (phase) => phase || '-',
    },
    {
      title: '漏洞数',
      key: 'findings_count',
      width: 80,
      render: (_, record) => record.findings_count || 0,
    },
    {
      title: '已分析文件',
      key: 'analyzed_files',
      width: 100,
      render: (_, record) => {
        const { analyzed_files, total_files } = record
        if (total_files) {
          return `${analyzed_files || 0}/${total_files}`
        }
        return analyzed_files || 0
      },
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (date) => new Date(date).toLocaleString('zh-CN'),
    },
    {
      title: '操作',
      key: 'actions',
      width: 100,
      render: (_, record) => (
        <Button
          type="link"
          size="small"
          icon={<EyeOutlined />}
          onClick={() => navigate(`/scans/${record.id}`)}
        >
          详情
        </Button>
      ),
    },
  ]

  return (
    <div>
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2 style={{ margin: 0 }}>扫描管理</h2>
        <Space>
          <Select
            placeholder="筛选状态"
            allowClear
            style={{ width: 120 }}
            onChange={(value) => setStatusFilter(value)}
            value={statusFilter}
          >
            <Select.Option value="pending">等待中</Select.Option>
            <Select.Option value="running">扫描中</Select.Option>
            <Select.Option value="paused">已暂停</Select.Option>
            <Select.Option value="completed">已完成</Select.Option>
            <Select.Option value="failed">失败</Select.Option>
            <Select.Option value="cancelled">已取消</Select.Option>
          </Select>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
            刷新
          </Button>
        </Space>
      </div>

      <Card>
        <Table
          rowKey="id"
          columns={columns}
          dataSource={data?.items || []}
          loading={isLoading}
          pagination={{
            current: page,
            pageSize: pageSize,
            total: data?.total || 0,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 个扫描`,
            onChange: (newPage, newPageSize) => {
              setPage(newPage)
              setPageSize(newPageSize || 20)
            },
          }}
        />
      </Card>
    </div>
  )
}
