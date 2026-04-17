// 模型类型定义
import type { ConcurrencyUpdateData } from './websocket'

// 来源类型
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

// 扫描配置
export interface ScanConfig {
  engines?: string[]
  llm_detect?: boolean
  static_only?: boolean
  llm_verify?: boolean
  adversarial?: boolean
  adversarial_max_rounds?: number
  adversarial_round_timeout?: number
  incremental?: boolean
  base_ref?: string
  head_ref?: string
  agent_max_files?: number
  model?: string
  skip_tests?: boolean
  [key: string]: unknown
}

// 扫描模型（已移除项目维度）
export interface Scan {
  id: number
  name: string
  source_type: SourceType
  source_path: string
  branch: string | null
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
  token_usage?: {
    prompt_tokens?: number
    completion_tokens?: number
    total_tokens?: number
    agent_scan_tokens?: number
    adversarial_tokens?: number
    estimated_cost?: number
  } | null
  tokens_budget: number | null
  task_id: string | null  // Celery task ID for task control
  config?: ScanConfig
  agent_analyzed_files?: string[] | null
  created_at: string
  started_at: string | null
  completed_at: string | null
}

// 创建扫描请求
export interface ScanCreate {
  name: string
  source_type: SourceType
  source_path: string
  branch?: string
  scan_type: ScanType
  config?: {
    engines?: string[]
    [key: string]: unknown
  }
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
  concurrency: Record<string, ConcurrencyUpdateData>
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
  cpg_path: CpgPath | null
  extra_metadata: FindingExtraMetadata | null
  created_at: string
}

// Finding extra_metadata 结构
export interface FindingExtraMetadata {
  rule_id?: string
  references?: string[]
  tags?: string[]
  fix_suggestion?: string
  evidence_strength?: string
  confidence_factors?: Record<string, number>
  score_detail?: {
    base_score?: number
    exploitability_score?: number
    directory_multiplier?: number
    final_score?: number
  }
  adversarial_verification?: {
    status?: string
    confidence?: number
    rounds_count?: number
    rounds?: AdversarialRound[]
    verdict?: AdversarialVerdictData
    reasoning?: string
    timeout?: boolean
  }
  [key: string]: unknown
}

// CPG 路径
export interface CpgPath {
  source?: { file: string; line: number; description?: string }
  sink?: { file: string; line: number; description?: string }
  propagation?: Array<{ file: string; line: number; description?: string }>
  attack_vector?: string
  exploitability?: string
  [key: string]: unknown
}

// 对抗性辩论轮次
export interface AdversarialRound {
  round_number: number
  attacker_argument?: {
    claim?: string
    evidence?: string[]
    reasoning?: string
    strength?: string
    confidence?: number
    poc_code?: string
    poc_type?: string
    exploitation_steps?: string[]
  }
  defender_argument?: {
    claim?: string
    evidence?: string[]
    reasoning?: string
    strength?: string
    confidence?: number
    sanitizers_found?: string[]
    validation_checks?: string[]
    false_positive_reasons?: string[]
  }
  arbiter_verdict?: {
    verdict?: string
    confidence?: number
    reasoning?: string
    continue_debate?: boolean
    continue_reason?: string
  }
}

// 对抗性判决数据
export interface AdversarialVerdictData {
  verdict?: string
  confidence?: number
  summary?: string
  reasoning?: string
  attacker_strength?: number
  defender_strength?: number
  recommended_action?: string
  priority?: string
  key_factors?: string[]
  conditions?: string[]
}

// 对抗性辩论 API 响应
export interface AdversarialDebateResponse {
  scan_id: number
  total_debates: number
  debates: AdversarialDebate[]
}

export interface AdversarialDebate {
  finding_id: number
  finding_title: string
  vuln_type: string
  status?: string
  confidence?: number
  rounds_count: number
  rounds: AdversarialRound[]
  verdict?: AdversarialVerdictData
  reasoning?: string
  timeout?: boolean
}

// 漏洞状态更新请求
export interface FindingStatusUpdate {
  status: FindingStatus
  extra_metadata?: Record<string, unknown>
}
