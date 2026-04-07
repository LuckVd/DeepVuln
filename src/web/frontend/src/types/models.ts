// 模型类型定义

// 项目来源类型
export type SourceType = 'local' | 'git' | 'zip'

// 扫描状态
export type ScanStatus =
  | 'pending'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'

// 扫描类型
export type ScanType = 'full' | 'base' | 'incremental'

// 严重程度
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'

// 漏洞状态
export type FindingStatus = 'pending' | 'confirmed' | 'false_positive' | 'conditional'

// 项目模型
export interface Project {
  id: number
  name: string
  description: string | null
  source_type: SourceType
  source_path: string
  branch: string | null
  created_at: string
  updated_at: string
}

// 创建项目请求
export interface ProjectCreate {
  name: string
  description?: string
  source_type: SourceType
  source_path: string
  branch?: string
}

// 更新项目请求
export interface ProjectUpdate {
  name?: string
  description?: string
  source_path?: string
  branch?: string
}

// 扫描模型
export interface Scan {
  id: number
  project_id: number
  status: ScanStatus
  scan_type: ScanType
  progress_percent: number
  current_phase: string | null
  current_step: string | null
  current_engine: string | null
  total_files: number | null
  indexed_files: number | null
  analyzed_files: number | null
  files_with_findings: number | null
  findings_count: number | null
  verified_count: number | null
  false_positive_count: number | null
  critical_count: number | null
  high_count: number | null
  medium_count: number | null
  low_count: number | null
  info_count: number | null
  tokens_used: number | null
  tokens_budget: number | null
  created_at: string
  started_at: string | null
  completed_at: string | null
}

// 创建扫描请求
export interface ScanCreate {
  project_id: number
  scan_type: ScanType
  branch?: string
}

// 扫描阶段信息
export interface PhaseInfo {
  name: string
  status: string
  progress_percent: number
  duration_seconds: number | null
  findings: number
  tokens_used: number
}

// Token 信息
export interface TokenInfo {
  used: number
  budget: number
  remaining: number
  percent_used: number
}

// 漏洞摘要
export interface FindingSummary {
  total: number
  verified: number
  false_positive: number
  by_severity: Record<SeverityLevel, number>
}

// 扫描进度响应
export interface ScanProgressResponse {
  scan_id: number
  status: ScanStatus
  progress_percent: number
  current_phase: string | null
  current_step: string | null
  current_engine: string | null
  total_files: number
  indexed_files: number
  analyzed_files: number
  files_with_findings: number
  engines: {
    completed: string[]
    running: string[] | null
    pending: string[]
  }
  tokens: TokenInfo
  findings: FindingSummary
  phases: PhaseInfo[]
  started_at: string | null
}

// 分页响应
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

// 漏洞模型
export interface Finding {
  id: number
  scan_id: number
  vuln_type: string
  severity: SeverityLevel
  confidence: number
  file_path: string
  line_start: number
  line_end: number
  function_name: string | null
  title: string
  description: string | null
  evidence: string | null
  remediation: string | null
  engine: string
  status: FindingStatus
  cpg_path: string | null
  created_at: string
}

// 漏洞状态更新请求
export interface FindingStatusUpdate {
  status: FindingStatus
  extra_metadata?: Record<string, unknown>
}
