import client from './client'
import type {
  Project,
  ProjectCreate,
  ProjectUpdate,
  PaginatedResponse,
} from '@/types/models'

/**
 * 项目 API
 */
export const projectsApi = {
  /**
   * 获取项目列表
   */
  async list(params?: {
    page?: number
    page_size?: number
    source_type?: string
  }): Promise<PaginatedResponse<Project>> {
    const response = await client.get('/projects', { params })
    return response.data
  },

  /**
   * 获取项目详情
   */
  async get(id: number): Promise<Project> {
    const response = await client.get(`/projects/${id}`)
    return response.data
  },

  /**
   * 创建项目
   */
  async create(data: ProjectCreate): Promise<Project> {
    const response = await client.post('/projects', data)
    return response.data
  },

  /**
   * 更新项目
   */
  async update(id: number, data: ProjectUpdate): Promise<Project> {
    const response = await client.put(`/projects/${id}`, data)
    return response.data
  },

  /**
   * 删除项目
   */
  async delete(id: number): Promise<void> {
    await client.delete(`/projects/${id}`)
  },

  /**
   * 获取项目扫描历史
   */
  async getScans(id: number, limit: number = 50): Promise<any> {
    const response = await client.get(`/projects/${id}/scans`, { params: { limit } })
    return response.data
  },
}
