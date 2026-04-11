import client from './client'

// System Settings Types
export interface SystemSetting {
  id: number
  key: string
  value: string | null
  category: string | null
  description: string | null
  updated_at: string
}

export interface SystemSettingsResponse {
  settings: Record<string, SystemSetting>
  categories: Record<string, Record<string, string | number>>
}

export interface SystemSettingsBatch {
  settings: Record<string, string | null | undefined>
}

// System Settings API
export const systemSettingsApi = {
  async get(): Promise<SystemSettingsResponse> {
    const response = await client.get('/system-settings')
    return response.data
  },

  async update(data: SystemSettingsBatch): Promise<SystemSettingsResponse> {
    const response = await client.put('/system-settings', data)
    return response.data
  }
}
