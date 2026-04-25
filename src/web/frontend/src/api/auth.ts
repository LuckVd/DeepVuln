import client from './client'

export interface LoginResponse {
  access_token: string
  token_type: string
  must_change_password: boolean
  username: string
  user_id: number
}

export interface UserInfo {
  id: number
  username: string
  must_change_password: boolean
  is_active: boolean
}

export const authApi = {
  async login(username: string, password: string): Promise<LoginResponse> {
    const response = await client.post<LoginResponse>('/auth/login', { username, password })
    return response.data
  },

  async changePassword(newPassword: string): Promise<{ message: string; access_token: string }> {
    const response = await client.post('/auth/change-password', { new_password: newPassword })
    return response.data
  },

  async getMe(): Promise<UserInfo> {
    const response = await client.get<UserInfo>('/auth/me')
    return response.data
  },
}
