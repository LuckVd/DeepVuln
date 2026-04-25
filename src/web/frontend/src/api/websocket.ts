import type {
  WebSocketEvent,
  ConnectionState,
  PhaseStartData,
  PhaseCompleteData,
  FindingNewData,
  ProgressData,
  ScanCompleteData,
  ScanFailedData,
  ScanPausedData,
} from '@/types/websocket'

type EventCallback<T = any> = (event: WebSocketEvent<T>) => void
type StateCallback = (state: ConnectionState) => void

/**
 * WebSocket 客户端
 */
export class WebSocketClient {
  private ws: WebSocket | null = null
  private scanId: number | null = null
  private url: string = ''
  private reconnectAttempts: number = 0
  private maxReconnectAttempts: number = 10
  private reconnectTimeout: NodeJS.Timeout | null = null
  private pingInterval: NodeJS.Timeout | null = null
  private eventCallbacks: Map<string, Set<EventCallback>> = new Map()
  private stateCallbacks: Set<StateCallback> = new Set()
  private connectionState: ConnectionState = 'disconnected'

  constructor() {
    // 获取 WebSocket 基础 URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = import.meta.env.VITE_WS_HOST || window.location.host
    this.url = `${protocol}//${host}/api/v1/ws`
  }

  /**
   * 连接到指定扫描的 WebSocket
   */
  connect(scanId: number): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      if (this.scanId === scanId) {
        return // 已连接到同一扫描
      }
      this.disconnect()
    }

    this.scanId = scanId
    this.setState('connecting')

    try {
      // Include JWT token as query parameter for authentication
      const token = localStorage.getItem('deepvuln_token')
      const wsUrl = token
        ? `${this.url}/${scanId}?token=${encodeURIComponent(token)}`
        : `${this.url}/${scanId}`
      this.ws = new WebSocket(wsUrl)

      this.ws.onopen = () => {
        console.log(`[WebSocket] Connected to scan ${scanId}`)
        this.setState('connected')
        this.reconnectAttempts = 0
        this.startPing()
      }

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as WebSocketEvent
          this.emit(data.type, data)
        } catch (err) {
          console.error('[WebSocket] Failed to parse message:', err)
        }
      }

      this.ws.onclose = (event) => {
        console.log(`[WebSocket] Disconnected: ${event.code} ${event.reason}`)
        this.setState('disconnected')
        this.stopPing()

        // 如果不是主动关闭，尝试重连
        if (!event.wasClean && this.reconnectAttempts < this.maxReconnectAttempts) {
          this.scheduleReconnect()
        }
      }

      this.ws.onerror = (error) => {
        console.error('[WebSocket] Error:', error)
        this.setState('error')
      }
    } catch (err) {
      console.error('[WebSocket] Failed to connect:', err)
      this.setState('error')
      this.scheduleReconnect()
    }
  }

  /**
   * 断开连接
   */
  disconnect(): void {
    this.stopPing()
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    this.scanId = null
    this.setState('disconnected')
  }

  /**
   * 安排重连
   */
  private scheduleReconnect(): void {
    if (this.reconnectTimeout) {
      return
    }

    this.reconnectAttempts++
    // 指数退避：1s, 2s, 4s, 8s, 15s, 15s, ...
    const delays = [1000, 2000, 4000, 8000, 15000]
    const delay = delays[Math.min(this.reconnectAttempts - 1, delays.length - 1)]

    console.log(`[WebSocket] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`)

    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null
      if (this.scanId) {
        this.connect(this.scanId)
      }
    }, delay)
  }

  /**
   * 开始 Ping
   */
  private startPing(): void {
    this.stopPing()
    this.pingInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping' }))
      }
    }, 30000) // 每 30 秒发送一次 ping
  }

  /**
   * 停止 Ping
   */
  private stopPing(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval)
      this.pingInterval = null
    }
  }

  /**
   * 设置连接状态
   */
  private setState(state: ConnectionState): void {
    this.connectionState = state
    this.stateCallbacks.forEach((callback) => callback(state))
  }

  /**
   * 获取连接状态
   */
  getState(): ConnectionState {
    return this.connectionState
  }

  /**
   * 订阅事件
   */
  on(eventType: string, callback: EventCallback): () => void {
    if (!this.eventCallbacks.has(eventType)) {
      this.eventCallbacks.set(eventType, new Set())
    }
    this.eventCallbacks.get(eventType)!.add(callback)

    // 返回取消订阅函数
    return () => {
      const callbacks = this.eventCallbacks.get(eventType)
      if (callbacks) {
        callbacks.delete(callback)
      }
    }
  }

  /**
   * 触发事件
   */
  private emit<T>(eventType: string, event: WebSocketEvent<T>): void {
    const callbacks = this.eventCallbacks.get(eventType)
    if (callbacks) {
      callbacks.forEach((callback) => {
        try {
          callback(event)
        } catch (err) {
          console.error(`[WebSocket] Error in ${eventType} callback:`, err)
        }
      })
    }
  }

  /**
   * 订阅状态变化
   */
  onStateChange(callback: StateCallback): () => void {
    this.stateCallbacks.add(callback)
    return () => {
      this.stateCallbacks.delete(callback)
    }
  }

  /**
   * 发送消息
   */
  send(data: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    } else {
      console.warn('[WebSocket] Cannot send message: not connected')
    }
  }
}

// 创建全局 WebSocket 客户端实例
let globalWsClient: WebSocketClient | null = null

export function getWebSocketClient(): WebSocketClient {
  if (!globalWsClient) {
    globalWsClient = new WebSocketClient()
  }
  return globalWsClient
}

/**
 * 重置全局 WebSocket 客户端（用于测试）
 */
export function resetWebSocketClient(): void {
  if (globalWsClient) {
    globalWsClient.disconnect()
  }
  globalWsClient = null
}
