import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios'

// API 基础路径
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1'

// 创建 axios 实例
const client: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Token key - must match AuthContext
const TOKEN_KEY = 'deepvuln_token'

// 请求拦截器 - 注入 JWT token
client.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem(TOKEN_KEY)
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// 响应拦截器 - 统一错误处理
client.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response) {
      // 服务器返回错误响应
      const status = error.response.status
      const data = error.response.data as any

      switch (status) {
        case 401:
          // 未授权 - 清除 token
          localStorage.removeItem(TOKEN_KEY)
          localStorage.removeItem('deepvuln_user')
          // 如果不在登录页，跳转
          if (window.location.pathname !== '/login') {
            window.location.href = '/login'
          }
          break
        case 403:
          console.error('权限不足:', data?.detail || '禁止访问')
          break
        case 404:
          console.error('资源不存在:', data?.detail || '未找到')
          break
        case 500:
          console.error('服务器错误:', data?.detail || '内部服务器错误')
          break
        default:
          console.error('请求失败:', data?.detail || error.message)
      }
    } else if (error.request) {
      // 请求已发出但没有收到响应
      console.error('网络错误: 无法连接到服务器')
    } else {
      // 请求配置错误
      console.error('请求错误:', error.message)
    }
    return Promise.reject(error)
  }
)

export default client
