// WebSocket 事件类型定义

export type WebSocketEventType =
  | 'connected'
  | 'phase_start'
  | 'phase_complete'
  | 'finding_new'
  | 'progress'
  | 'scan_complete'
  | 'scan_failed'
  | 'scan_paused'
  | 'adversarial_round'
  | 'warning'
  | 'adjudication_result'
  | 'verification_result'
  | 'finding_skipped'
  | 'concurrency_update'
  | 'ping'
  | 'pong'

export interface WebSocketEvent<T = any> {
  type: WebSocketEventType
  scan_id?: number
  data: T
  timestamp: string
}

// phase_start 事件数据
export interface PhaseStartData {
  phase: string
  [key: string]: any
}

// phase_complete 事件数据
export interface PhaseCompleteData {
  phase: string
  duration_seconds: number
  findings: number
  tokens_used: number
  per_engine_details?: Record<string, EngineDetail>
  severity_breakdown?: SeverityBreakdown
  per_phase_tokens?: Record<string, number>
}

// Per-engine detail in phase_complete
export interface EngineDetail {
  findings: number
  duration_seconds: number
  tokens_used: number
}

// Severity breakdown for scan_complete
export interface SeverityBreakdown {
  critical: number
  high: number
  medium: number
  low: number
  info: number
  verified?: number
  false_positive?: number
}

// finding_new 事件数据
export interface FindingNewData {
  id: number
  vuln_type: string
  severity: string
  file_path: string
  line_start: number
  title: string
  [key: string]: any
}

// progress 事件数据
export interface ProgressData {
  progress_percent: number
  current_file?: string
  message?: string
}

// scan_complete 事件数据
export interface ScanCompleteData {
  findings_count: number
  duration_seconds: number
  tokens_used: number
  severity_breakdown?: SeverityBreakdown
  per_phase_tokens?: Record<string, number>
}

// scan_failed 事件数据
export interface ScanFailedData {
  error: string
}

// scan_paused 事件数据
export interface ScanPausedData {
  checkpoint_saved: boolean
}

// WebSocket 连接状态
export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'error'

// concurrency_update 事件数据
export interface ConcurrencyUpdateData {
  manager: 'agent_scan' | 'verification'
  max_concurrent: number
  current_concurrent: number
  previous_concurrent: number
  is_throttled: boolean
  rate_limit_hits: number
  concurrent_requests: number
}
