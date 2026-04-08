import client from './client'
import type {
  Scan,
  ScanCreate,
  PaginatedResponse,
  ScanProgressResponse,
  Finding,
  FindingSummary,
  FindingStatusUpdate,
} from '@/types/models'

/**
 * 扫描 API
 */
export const scansApi = {
  /**
   * 获取扫描列表
   */
  async list(params?: {
    page?: number
    page_size?: number
    status?: string
    project_id?: number
  }): Promise<PaginatedResponse<Scan>> {
    const response = await client.get('/scans', { params })
    return response.data
  },

  /**
   * 获取扫描详情
   */
  async get(id: number): Promise<Scan> {
    const response = await client.get(`/scans/${id}`)
    return response.data
  },

  /**
   * 创建扫描
   */
  async create(data: ScanCreate): Promise<Scan> {
    const response = await client.post('/scans', data)
    return response.data
  },

  /**
   * 启动扫描
   */
  async start(id: number): Promise<any> {
    const response = await client.post(`/scans/${id}/start`)
    return response.data
  },

  /**
   * 获取扫描进度
   */
  async getProgress(id: number): Promise<ScanProgressResponse> {
    const response = await client.get(`/scans/${id}/progress`)
    return response.data
  },

  /**
   * 获取扫描阶段
   */
  async getPhases(id: number): Promise<any> {
    const response = await client.get(`/scans/${id}/phases`)
    return response.data
  },

  /**
   * 获取扫描事件流
   */
  async getEvents(id: number, params?: {
    page?: number
    page_size?: number
    event_type?: string
  }): Promise<any> {
    const response = await client.get(`/scans/${id}/events`, { params })
    return response.data
  },

  /**
   * 获取漏洞列表
   */
  async getFindings(id: number, params?: {
    page?: number
    page_size?: number
    severity?: string
    status?: string
  }): Promise<{
    scan_id: number
    total: number
    page: number
    page_size: number
    summary: FindingSummary
    findings: Finding[]
  }> {
    const response = await client.get(`/scans/${id}/findings`, { params })
    return response.data
  },

  /**
   * 获取扫描报告
   */
  async getReport(id: number): Promise<any> {
    const response = await client.get(`/scans/${id}/report`)
    return response.data
  },

  /**
   * 暂停扫描
   */
  async pause(id: number): Promise<any> {
    const response = await client.post(`/scans/${id}/pause`)
    return response.data
  },

  /**
   * 继续扫描
   */
  async resume(id: number): Promise<any> {
    const response = await client.post(`/scans/${id}/resume`)
    return response.data
  },

  /**
   * 取消扫描
   */
  async cancel(id: number): Promise<any> {
    const response = await client.post(`/scans/${id}/cancel`)
    return response.data
  },

  /**
   * 获取扫描状态
   */
  async getStatus(id: number): Promise<any> {
    const response = await client.get(`/scans/${id}/status`)
    return response.data
  },

  /**
   * 更新漏洞状态
   */
  async updateFindingStatus(scanId: number, findingId: number, data: FindingStatusUpdate): Promise<Finding> {
    const response = await client.patch(`/scans/${scanId}/findings/${findingId}/status`, data)
    return response.data
  },
}
