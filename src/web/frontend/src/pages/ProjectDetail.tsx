import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Card,
  Button,
  Table,
  Tag,
  Space,
  Descriptions,
  Statistic,
  Row,
  Col,
  Progress,
  message,
  Popconfirm,
  Empty,
  Spin,
  Modal,
  Form,
  Select,
  Alert,
} from 'antd'
import {
  ArrowLeftOutlined,
  PlayCircleOutlined,
  HistoryOutlined,
  EyeOutlined,
  DeleteOutlined,
  PlusOutlined,
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { useProject, useProjectScans, useDeleteProject, useCreateScan } from '@/hooks/useApi'
import { scansApi } from '@/api'
import type { Project, Scan, ScanStatus, ScanType } from '@/types/models'

const SOURCE_TYPE_MAP: Record<string, { text: string; color: string }> = {
  local: { text: '本地目录', color: 'blue' },
  git: { text: 'Git 仓库', color: 'green' },
  zip: { text: 'ZIP 压缩包', color: 'orange' },
}

const SCAN_STATUS_MAP: Record<ScanStatus, { text: string; color: string }> = {
  pending: { text: '等待中', color: 'default' },
  running: { text: '扫描中', color: 'processing' },
  paused: { text: '已暂停', color: 'warning' },
  completed: { text: '已完成', color: 'success' },
  failed: { text: '失败', color: 'error' },
  cancelled: { text: '已取消', color: 'default' },
}

const SCAN_TYPE_MAP: Record<ScanType, string> = {
  full: '完整扫描',
  base: '基础扫描',
  incremental: '增量扫描',
}

// 创建扫描对话框组件
interface CreateScanModalProps {
  projectId: number
  projectName: string
  open: boolean
  onClose: () => void
  onSuccess: (scanId: number) => void
}

function CreateScanModal({ projectId, projectName, open, onClose, onSuccess }: CreateScanModalProps) {
  const [form] = Form.useForm()
  const createMutation = useCreateScan()

  const handleOk = async () => {
    try {
      const values = await form.validateFields()
      const result = await createMutation.mutateAsync({
        project_id: projectId,
        scan_type: values.scan_type,
      })

      message.loading({ content: '正在启动扫描...', key: 'scan_start' })

      try {
        // 启动扫描
        await scansApi.start(result.id)
        message.success({ content: '扫描已启动', key: 'scan_start', duration: 2 })
        onSuccess(result.id)
      } catch (startError) {
        message.error({ content: '扫描创建成功但启动失败', key: 'scan_start' })
        // 仍然跳转到扫描详情页
        onSuccess(result.id)
      }
    } catch (error: any) {
      if (error?.errorFields) {
        return // 表单验证错误
      }
      message.error('创建扫描失败')
      console.error('Create scan error:', error)
    }
  }

  const handleCancel = () => {
    form.resetFields()
    onClose()
  }

  return (
    <Modal
      title={`创建扫描 - ${projectName}`}
      open={open}
      onOk={handleOk}
      onCancel={handleCancel}
      confirmLoading={createMutation.isPending}
      okText="创建并启动"
      cancelText="取消"
      width={600}
    >
      <Form form={form} layout="vertical" initialValues={{ scan_type: 'full' }}>
        <Form.Item
          name="scan_type"
          label="扫描类型"
          rules={[{ required: true, message: '请选择扫描类型' }]}
        >
          <Select size="large">
            <Select.Option value="full">
              <div>
                <div className="font-semibold">完整扫描 (Full)</div>
                <div className="text-xs text-gray-500">使用所有引擎 (Semgrep + CodeQL + Agent)</div>
              </div>
            </Select.Option>
            <Select.Option value="base">
              <div>
                <div className="font-semibold">基础扫描 (Base)</div>
                <div className="text-xs text-gray-500">仅使用 Semgrep 快速扫描</div>
              </div>
            </Select.Option>
            <Select.Option value="incremental">
              <div>
                <div className="font-semibold">增量扫描 (Incremental)</div>
                <div className="text-xs text-gray-500">仅扫描 Git 差异文件</div>
              </div>
            </Select.Option>
          </Select>
        </Form.Item>

        <Alert
          message="提示"
          description={
            <ul className="m-0 pl-4 text-sm">
              <li>完整扫描耗时较长，但覆盖面最全</li>
              <li>基础扫描适合快速检查常见问题</li>
              <li>增量扫描仅支持 Git 仓库</li>
            </ul>
          }
          type="info"
          showIcon
        />
      </Form>
    </Modal>
  )
}

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const projectId = Number(id)
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)

  const { data: project, isLoading: projectLoading } = useProject(projectId)
  const { data: scansData, isLoading: scansLoading } = useProjectScans(projectId, 20)
  const deleteMutation = useDeleteProject()

  // 计算统计数据
  const stats = {
    totalScans: scansData?.scans?.length || 0,
    completedScans: scansData?.scans?.filter((s: Scan) => s.status === 'completed').length || 0,
    totalFindings: scansData?.scans?.reduce((sum: number, s: Scan) => sum + (s.findings_count || 0), 0) || 0,
    criticalFindings: scansData?.scans?.reduce((sum: number, s: Scan) => sum + (s.critical_count || 0), 0) || 0,
    highFindings: scansData?.scans?.reduce((sum: number, s: Scan) => sum + (s.high_count || 0), 0) || 0,
  }

  const handleDelete = async () => {
    try {
      await deleteMutation.mutateAsync(projectId)
      message.success('项目已删除')
      navigate('/projects')
    } catch {
      message.error('删除失败')
    }
  }

  const handleCreateScan = () => {
    setIsCreateModalOpen(true)
  }

  const scanColumns: ColumnsType<Scan> = [
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
      render: (status: ScanStatus) => {
        const config = SCAN_STATUS_MAP[status]
        return <Tag color={config.color}>{config.text}</Tag>
      },
    },
    {
      title: '类型',
      dataIndex: 'scan_type',
      key: 'scan_type',
      width: 100,
      render: (type: ScanType) => SCAN_TYPE_MAP[type] || type,
    },
    {
      title: '进度',
      dataIndex: 'progress_percent',
      key: 'progress_percent',
      width: 120,
      render: (percent: number, record: Scan) => {
        if (record.status === 'completed') {
          return <span style={{ color: '#52c41a' }}>100%</span>
        }
        if (record.status === 'failed') {
          return <span style={{ color: '#ff4d4f' }}>失败</span>
        }
        return (
          <Progress
            percent={percent || 0}
            size="small"
            status={record.status === 'running' ? 'active' : 'normal'}
          />
        )
      },
    },
    {
      title: '漏洞数',
      key: 'findings',
      width: 150,
      render: (_, record: Scan) => (
        <Space size={2}>
          {record.critical_count > 0 && (
            <Tag color="red">{record.critical_count} 严重</Tag>
          )}
          {record.high_count > 0 && (
            <Tag color="orange">{record.high_count} 高危</Tag>
          )}
          {record.medium_count > 0 && (
            <Tag color="gold">{record.medium_count} 中危</Tag>
          )}
          {(!record.critical_count && !record.high_count && !record.medium_count) && (
            <span style={{ color: '#bfbfbf' }}>-</span>
          )}
        </Space>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (date: string) => new Date(date).toLocaleString('zh-CN'),
    },
    {
      title: '操作',
      key: 'actions',
      width: 120,
      fixed: 'right' as const,
      render: (_, record: Scan) => (
        <Space size="small">
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => navigate(`/scans/${record.id}`)}
          >
            详情
          </Button>
        </Space>
      ),
    },
  ]

  if (projectLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <Spin size="large" tip="加载项目信息..." />
      </div>
    )
  }

  if (!project) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <Empty description="项目不存在" />
      </div>
    )
  }

  return (
    <div>
      {/* 顶部导航 */}
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/projects')}>
            返回
          </Button>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>{project.name}</h2>
        </Space>
        <Space>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={handleCreateScan}
          >
            创建扫描
          </Button>
          <Popconfirm
            title="确定删除该项目？"
            description="删除后将同时删除所有相关的扫描记录和漏洞结果。"
            onConfirm={handleDelete}
            okText="确定"
            cancelText="取消"
          >
            <Button danger icon={<DeleteOutlined />}>
              删除项目
            </Button>
          </Popconfirm>
        </Space>
      </div>

      {/* 项目信息卡片 */}
      <Card title="项目信息" style={{ marginBottom: 16 }}>
        <Row gutter={16}>
          <Col span={16}>
            <Descriptions column={2} bordered>
              <Descriptions.Item label="项目 ID">{project.id}</Descriptions.Item>
              <Descriptions.Item label="项目名称">{project.name}</Descriptions.Item>
              <Descriptions.Item label="来源类型">
                <Tag color={SOURCE_TYPE_MAP[project.source_type].color}>
                  {SOURCE_TYPE_MAP[project.source_type].text}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="分支">{project.branch || '-'}</Descriptions.Item>
              <Descriptions.Item label="来源路径" span={2}>
                <code style={{
                  background: '#f5f5f5',
                  padding: '4px 8px',
                  borderRadius: 4,
                  fontSize: 12,
                  display: 'inline-block',
                  maxWidth: '100%',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}>
                  {project.source_path}
                </code>
              </Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>
                {project.description || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {new Date(project.created_at).toLocaleString('zh-CN')}
              </Descriptions.Item>
              <Descriptions.Item label="更新时间">
                {new Date(project.updated_at).toLocaleString('zh-CN')}
              </Descriptions.Item>
            </Descriptions>
          </Col>
          <Col span={8}>
            <Card title="扫描统计" size="small">
              <Row gutter={16}>
                <Col span={12}>
                  <Statistic title="总扫描次数" value={stats.totalScans} />
                </Col>
                <Col span={12}>
                  <Statistic title="完成次数" value={stats.completedScans} />
                </Col>
                <Col span={12}>
                  <Statistic
                    title="发现漏洞"
                    value={stats.totalFindings}
                    valueStyle={{ color: stats.totalFindings > 0 ? '#cf1322' : undefined }}
                  />
                </Col>
                <Col span={12}>
                  <Statistic
                    title="高危以上"
                    value={stats.criticalFindings + stats.highFindings}
                    valueStyle={{ color: stats.criticalFindings + stats.highFindings > 0 ? '#cf1322' : undefined }}
                  />
                </Col>
              </Row>
            </Card>
          </Col>
        </Row>
      </Card>

      {/* 扫描历史 */}
      <Card
        title={
          <Space>
            <HistoryOutlined />
            <span>扫描历史</span>
          </Space>
        }
        extra={
          <Button
            type="primary"
            size="small"
            icon={<PlayCircleOutlined />}
            onClick={handleCreateScan}
          >
            新建扫描
          </Button>
        }
      >
        <Table
          rowKey="id"
          columns={scanColumns}
          dataSource={scansData?.scans || []}
          loading={scansLoading}
          pagination={{
            pageSize: 10,
            showSizeChanger: false,
            showTotal: (total) => `共 ${total} 条记录`,
          }}
          locale={{
            emptyText: (
              <Empty
                description="暂无扫描记录"
                image={Empty.PRESENTED_IMAGE_SIMPLE}
              >
                <Button type="primary" icon={<PlusOutlined />} onClick={handleCreateScan}>
                  创建第一个扫描
                </Button>
              </Empty>
            ),
          }}
          scroll={{ x: 800 }}
        />
      </Card>

      {/* 创建扫描对话框 */}
      <CreateScanModal
        projectId={projectId}
        projectName={project.name}
        open={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSuccess={(scanId) => {
          setIsCreateModalOpen(false)
          navigate(`/scans/${scanId}`)
        }}
      />
    </div>
  )
}
