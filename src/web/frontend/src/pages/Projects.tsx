import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Button,
  Card,
  Table,
  Tag,
  Space,
  Modal,
  Form,
  Input,
  Select,
  message,
  Popconfirm,
} from 'antd'
import { PlusOutlined, DeleteOutlined, EyeOutlined, HistoryOutlined } from '@ant-design/icons'
import { useProjects, useCreateProject, useDeleteProject, useProjectScans } from '@/hooks/useApi'
import type { Project, SourceType } from '@/types/models'
import type { ColumnsType } from 'antd/es/table'

const SOURCE_TYPE_MAP: Record<SourceType, { text: string; color: string }> = {
  local: { text: '本地', color: 'blue' },
  git: { text: 'Git', color: 'green' },
  zip: { text: 'ZIP', color: 'orange' },
}

export default function ProjectsPage() {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [form] = Form.useForm()
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null)

  const { data, isLoading } = useProjects({ page, page_size: pageSize })
  const createMutation = useCreateProject()
  const deleteMutation = useDeleteProject()
  const { data: scansData } = useProjectScans(selectedProjectId || 0, 10)

  const columns: ColumnsType<Project> = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 60,
    },
    {
      title: '项目名称',
      dataIndex: 'name',
      key: 'name',
      render: (name, record) => (
        <a onClick={() => navigate(`/projects/${record.id}`)}>{name}</a>
      ),
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      render: (desc) => desc || '-',
    },
    {
      title: '来源类型',
      dataIndex: 'source_type',
      key: 'source_type',
      width: 100,
      render: (type: SourceType) => {
        const config = SOURCE_TYPE_MAP[type]
        return <Tag color={config.color}>{config.text}</Tag>
      },
    },
    {
      title: '来源路径',
      dataIndex: 'source_path',
      key: 'source_path',
      ellipsis: true,
    },
    {
      title: '分支',
      dataIndex: 'branch',
      key: 'branch',
      width: 100,
      render: (branch) => branch || '-',
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
      width: 150,
      render: (_, record) => (
        <Space size="small">
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => navigate(`/projects/${record.id}`)}
          >
            详情
          </Button>
          <Button
            type="link"
            size="small"
            icon={<HistoryOutlined />}
            onClick={() => setSelectedProjectId(record.id)}
          >
            历史
          </Button>
          <Popconfirm
            title="确定删除该项目？"
            description="删除后将同时删除所有相关的扫描记录和漏洞结果。"
            onConfirm={() => handleDelete(record.id)}
            okText="确定"
            cancelText="取消"
          >
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const handleCreate = async () => {
    try {
      const values = await form.validateFields()
      await createMutation.mutateAsync(values)
      message.success('项目创建成功')
      setIsModalOpen(false)
      form.resetFields()
    } catch (error) {
      // form.validateFields 会抛出验证错误，这里只处理 API 错误
      if (error instanceof Error) {
        message.error(`创建失败: ${error.message}`)
      }
    }
  }

  const handleDelete = async (id: number) => {
    try {
      await deleteMutation.mutateAsync(id)
      message.success('项目已删除')
      if (selectedProjectId === id) {
        setSelectedProjectId(null)
      }
    } catch (error) {
      message.error('删除失败')
    }
  }

  return (
    <div>
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
        <h2 style={{ margin: 0 }}>项目管理</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>
          创建项目
        </Button>
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
            showTotal: (total) => `共 ${total} 个项目`,
            onChange: (newPage, newPageSize) => {
              setPage(newPage)
              setPageSize(newPageSize || 20)
            },
          }}
        />
      </Card>

      {/* 创建项目模态框 */}
      <Modal
        title="创建项目"
        open={isModalOpen}
        onOk={handleCreate}
        onCancel={() => {
          setIsModalOpen(false)
          form.resetFields()
        }}
        confirmLoading={createMutation.isPending}
        okText="创建"
        cancelText="取消"
      >
        <Form form={form} layout="vertical" style={{ marginTop: 24 }}>
          <Form.Item
            name="name"
            label="项目名称"
            rules={[{ required: true, message: '请输入项目名称' }]}
          >
            <Input placeholder="例如：my-awesome-project" />
          </Form.Item>

          <Form.Item name="description" label="项目描述">
            <Input.TextArea rows={3} placeholder="简要描述该项目..." />
          </Form.Item>

          <Form.Item
            name="source_type"
            label="来源类型"
            initialValue="local"
            rules={[{ required: true }]}
          >
            <Select>
              <Select.Option value="local">本地目录</Select.Option>
              <Select.Option value="git">Git 仓库</Select.Option>
              <Select.Option value="zip">ZIP 压缩包</Select.Option>
            </Select>
          </Form.Item>

          <Form.Item
            name="source_path"
            label="来源路径"
            rules={[{ required: true, message: '请输入来源路径' }]}
          >
            <Input placeholder="/path/to/project 或 https://github.com/user/repo" />
          </Form.Item>

          <Form.Item noStyle shouldUpdate={(prev, curr) => prev.source_type !== curr.source_type}>
            {({ getFieldValue }) =>
              getFieldValue('source_type') === 'git' ? (
                <Form.Item name="branch" label="分支">
                  <Input placeholder="main 或 master (留空使用默认)" />
                </Form.Item>
              ) : null
            }
          </Form.Item>
        </Form>
      </Modal>

      {/* 扫描历史模态框 */}
      <Modal
        title={`扫描历史 - ${data?.items.find((p) => p.id === selectedProjectId)?.name || ''}`}
        open={!!selectedProjectId}
        onCancel={() => setSelectedProjectId(null)}
        footer={null}
        width={800}
      >
        <Table
          rowKey="id"
          columns={[
            { title: 'ID', dataIndex: 'id', width: 60 },
            {
              title: '状态',
              dataIndex: 'status',
              width: 100,
              render: (status: string) => {
                const statusConfig: Record<string, { text: string; color: string }> = {
                  pending: { text: '等待中', color: 'default' },
                  running: { text: '扫描中', color: 'processing' },
                  paused: { text: '已暂停', color: 'warning' },
                  completed: { text: '已完成', color: 'success' },
                  failed: { text: '失败', color: 'error' },
                  cancelled: { text: '已取消', color: 'default' },
                }
                const config = statusConfig[status] || { text: status, color: 'default' }
                return <Tag color={config.color}>{config.text}</Tag>
              },
            },
            { title: '进度', dataIndex: 'progress_percent', width: 80, render: (p) => `${p || 0}%` },
            { title: '漏洞数', dataIndex: 'findings_count', width: 80 },
            {
              title: '创建时间',
              dataIndex: 'created_at',
              render: (date: string) => new Date(date).toLocaleString('zh-CN'),
            },
            {
              title: '操作',
              key: 'actions',
              render: (_, record: any) => (
                <Button
                  type="link"
                  size="small"
                  onClick={() => {
                    setSelectedProjectId(null)
                    navigate(`/scans/${record.id}`)
                  }}
                >
                  查看详情
                </Button>
              ),
            },
          ]}
          dataSource={scansData?.scans || []}
          pagination={false}
          size="small"
        />
      </Modal>
    </div>
  )
}
