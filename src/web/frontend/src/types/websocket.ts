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
