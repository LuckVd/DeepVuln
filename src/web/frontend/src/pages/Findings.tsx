import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Card,
  Row,
  Col,
  Statistic,
  Select,
  Space,
  Button,
  Input,
  message,
} from 'antd'
import {
  ArrowLeftOutlined,
  ReloadOutlined,
  SearchOutlined,
} from '@ant-design/icons'
import { useFindings } from '@/hooks/useFindings'
import type { Finding, FindingStatus, SeverityLevel } from '@/types/models'
import FindingList from '@/components/finding/FindingList'
import FindingDrawer from '@/components/finding/FindingDrawer'

const STATUS_OPTIONS: { value: FindingStatus; label: string }[] = [
  { value: 'pending', label: '待处理' },
  { value: 'confirmed', label: '已确认' },
  { value: 'false_positive', label: '误报' },
  { value: 'conditional', label: '有条件' },
]

const SEVERITY_OPTIONS: { value: SeverityLevel; label: string }[] = [
  { value: 'critical', label: '严重' },
  { value: 'high', label: '高危' },
  { value: 'medium', label: '中危' },
  { value: 'low', label: '低危' },
  { value: 'info', label: '信息' },
]

/**
 * 漏洞列表页面
 */
export default function FindingsPage() {
  const { id: scanId } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const id = parseInt(scanId || '0')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [statusFilter, setStatusFilter] = useState<FindingStatus | undefined>()
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | undefined>()
  const [searchText, setSearchText] = useState('')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  const {
    data,
    isLoading,
    refetch,
    updateStatus,
    isUpdating,
  } = useFindings({
    scanId: id,
    page,
    page_size: pageSize,
    status: statusFilter,
    severity: severityFilter,
    enabled: !isNaN(id),
  })

  // 过滤结果（客户端搜索）
  const filteredFindings = data?.findings.filter((finding) => {
    if (!searchText) return true
    const searchLower = searchText.toLowerCase()
    return (
      finding.vuln_type.toLowerCase().includes(searchLower) ||
      finding.file_path.toLowerCase().includes(searchLower) ||
      finding.title?.toLowerCase().includes(searchLower) ||
      finding.description?.toLowerCase().includes(searchLower)
    )
  }) || []

  const handlePageChange = (newPage: number, newPageSize?: number) => {
    setPage(newPage)
    if (newPageSize && newPageSize !== pageSize) {
      setPageSize(newPageSize)
    }
  }

  const handleViewDetail = (finding: Finding) => {
    setSelectedFinding(finding)
    setDrawerOpen(true)
  }

  const handleStatusChange = (findingId: number, newStatus: FindingStatus) => {
    updateStatus(findingId, newStatus)
    message.success('状态已更新')
  }

  if (isNaN(id)) {
    navigate('/scans')
    return null
  }

  return (
    <div>
      {/* 头部 */}
      <div style={{ marginBottom: 16 }}>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/scans')}>
          返回扫描列表
        </Button>
      </div>

      {/* 统计卡片 */}
      {data?.summary && (
        <Row gutter={16} style={{ marginBottom: 16 }}>
          <Col span={4}>
            <Card>
              <Statistic title="总漏洞数" value={data.summary.total} />
            </Card>
          </Col>
          <Col span={5}>
            <Card>
              <Statistic
                title="已确认"
                value={data.summary.verified}
                valueStyle={{ color: '#52c41a' }}
              />
            </Card>
          </Col>
          <Col span={5}>
            <Card>
              <Statistic
                title="误报"
                value={data.summary.false_positive}
                valueStyle={{ color: '#ff4d4f' }}
              />
            </Card>
          </Col>
          <Col span={5}>
            <Card>
              <Statistic
                title="严重"
                value={data.summary.by_severity.critical || 0}
                valueStyle={{ color: '#cf1322' }}
              />
            </Card>
          </Col>
          <Col span={5}>
            <Card>
              <Statistic
                title="高危"
                value={data.summary.by_severity.high || 0}
                valueStyle={{ color: '#ff4d4f' }}
              />
            </Card>
          </Col>
        </Row>
      )}

      {/* 工具栏 */}
      <Card style={{ marginBottom: 16 }}>
        <Space wrap>
          <Select
            placeholder="筛选状态"
            allowClear
            style={{ width: 120 }}
            value={statusFilter}
            onChange={setStatusFilter}
            options={STATUS_OPTIONS.map((opt) => ({ label: opt.label, value: opt.value }))}
          />
          <Select
            placeholder="筛选严重程度"
            allowClear
            style={{ width: 120 }}
            value={severityFilter}
            onChange={setSeverityFilter}
            options={SEVERITY_OPTIONS.map((opt) => ({ label: opt.label, value: opt.value }))}
          />
          <Input
            placeholder="搜索漏洞类型、文件、描述..."
            prefix={<SearchOutlined />}
            style={{ width: 300 }}
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            allowClear
          />
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
            刷新
          </Button>
        </Space>
      </Card>

      {/* 漏洞列表 */}
      <Card>
        <FindingList
          findings={filteredFindings}
          loading={isLoading}
          total={searchText ? filteredFindings.length : (data?.total || 0)}
          page={page}
          pageSize={pageSize}
          onPageChange={handlePageChange}
          onViewDetail={handleViewDetail}
        />
      </Card>

      {/* 详情抽屉 */}
      <FindingDrawer
        finding={selectedFinding}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onStatusChange={handleStatusChange}
        isUpdating={isUpdating}
      />
    </div>
  )
}
