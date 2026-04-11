import client from './client'

// LLM Config Types
export type LLMProvider = 'openai' | 'azure' | 'ollama' | 'custom'
export type LLMConfigType = 'agent_scan' | 'verification' | 'both'

export interface LLMConfig {
  id: number
  name: string
  provider: LLMProvider
  api_key?: string
  base_url?: string
  model: string
  context_size: number
  temperature: number
  max_tokens: number
  timeout: number
  max_concurrent_requests: number
  is_default: boolean
  config_type: LLMConfigType
  created_at: string
  updated_at: string
}

export interface LLMConfigListItem {
  id: number
  name: string
  provider: LLMProvider
  model: string
  max_concurrent_requests: number
  is_default: boolean
  config_type: LLMConfigType
  has_api_key: boolean
  created_at: string
}

export interface LLMConfigCreate {
  name: string
  provider: LLMProvider
  api_key?: string
  base_url?: string
  model: string
  context_size?: number
  temperature?: number
  max_tokens?: number
  timeout?: number
  max_concurrent_requests?: number
  config_type?: LLMConfigType
  is_default?: boolean
}

export interface LLMValidationResult {
  success: boolean
  message: string
  model_info?: {
    model: string
    provider: string
    prompt_tokens?: number
    completion_tokens?: number
  }
  latency_ms?: number
}

export interface LLMModelsResult {
  models: string[]
  provider: string
}

// LLM Config API
export const llmConfigApi = {
  async list(): Promise<{ items: LLMConfigListItem[]; total: number }> {
    const response = await client.get('/llm-configs')
    return response.data
  },

  async get(id: number): Promise<LLMConfig> {
    const response = await client.get(`/llm-configs/${id}`)
    return response.data
  },

  async create(data: LLMConfigCreate): Promise<LLMConfig> {
    const response = await client.post('/llm-configs', data)
    return response.data
  },

  async update(id: number, data: Partial<LLMConfigCreate>): Promise<LLMConfig> {
    const response = await client.put(`/llm-configs/${id}`, data)
    return response.data
  },

  async delete(id: number): Promise<void> {
    await client.delete(`/llm-configs/${id}`)
  },

  async validate(id: number): Promise<LLMValidationResult> {
    const response = await client.post(`/llm-configs/${id}/validate`, {})
    return response.data
  },

  async getModels(id: number): Promise<LLMModelsResult> {
    const response = await client.get(`/llm-configs/${id}/models`)
    return response.data
  }
}
