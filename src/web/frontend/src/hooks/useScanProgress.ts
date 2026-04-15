import { useEffect, useState, useRef } from 'react'
import { useWebSocket } from './useWebSocket'
import { scansApi } from '@/api/scans'
import type { ScanProgressResponse, ScanStatus } from '@/types/models'
import type { ConcurrencyUpdateData } from '@/types/websocket'

interface UseScanProgressOptions {
  enabled?: boolean
  pollInterval?: number // 轮询间隔（毫秒）
  maxRetries?: number // 最大重试次数
  retryDelay?: number // 失败后的重试延迟（毫秒）
  onProgressChange?: (progress: ScanProgressResponse) => void
  onComplete?: (result: ScanProgressResponse) => void
  onFailed?: (error: string) => void
}

// 如果 WS 连接后这么久都没收到事件，说明后端进程隔离导致事件无法送达，回退到轮询
const WS_EVENT_TIMEOUT_MS = 8000

export function useScanProgress(
  scanId: number | null,
  options: UseScanProgressOptions = {}
) {
  const {
    enabled = true,
    pollInterval = 5000,
    maxRetries = 10,
    retryDelay = 10000,
    onProgressChange,
    onComplete,
    onFailed,
  } = options

  const [progress, setProgress] = useState<ScanProgressResponse | null>(null)
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [usingPolling, setUsingPolling] = useState(false)
  const [concurrency, setConcurrency] = useState<Record<string, ConcurrencyUpdateData>>({})

  // 使用 ref 存储可变状态，避免闭包问题
  const stateRef = useRef({
    pollTimeout: null as NodeJS.Timeout | null,
    isComplete: false,
    retryCount: 0,
    isPollingActive: false,
    wsState: 'disconnected' as 'connected' | 'disconnected' | 'error' | 'connecting',
    lastWsEventAt: 0 as number, // 上次收到 WS 事件的时间戳
    wsFallbackCheckId: null as NodeJS.Timeout | null, // WS 事件超时检查定时器
  })

  // 获取进度数据
  const fetchProgress = async () => {
    if (!scanId || stateRef.current.isComplete) return false

    try {
      const data = await scansApi.getProgress(scanId)
      setProgress(data)
      setStatus(data.status)

      // 重置重试计数
      stateRef.current.retryCount = 0

      onProgressChange?.(data)

      // 检查是否完成
      if (data.status === 'completed') {
        stateRef.current.isComplete = true
        onComplete?.(data)
        return false // 停止轮询
      }

      if (data.status === 'failed') {
        stateRef.current.isComplete = true
        onFailed?.('扫描失败')
        return false // 停止轮询
      }

      return true // 继续轮询
    } catch (err) {
      console.error('Failed to fetch progress:', err)
      stateRef.current.retryCount++

      // 超过最大重试次数则停止
      if (stateRef.current.retryCount >= maxRetries) {
        console.error(`Max retries (${maxRetries}) exceeded for scan progress`)
        onFailed?.('无法获取扫描进度')
        return false
      }

      return true // 继续轮询
    }
  }

  // 停止轮询
  const stopPolling = () => {
    stateRef.current.isPollingActive = false
    if (stateRef.current.pollTimeout) {
      clearTimeout(stateRef.current.pollTimeout)
      stateRef.current.pollTimeout = null
    }
    setUsingPolling(false)
  }

  // 启动轮询
  const startPolling = () => {
    if (stateRef.current.pollTimeout || stateRef.current.isPollingActive) return

    stateRef.current.isPollingActive = true
    setUsingPolling(true)

    const poll = async () => {
      if (!stateRef.current.isPollingActive) return

      const shouldContinue = await fetchProgress()

      if (!shouldContinue || stateRef.current.isComplete) {
        stopPolling()
        return
      }

      // 根据是否有错误决定使用哪个延迟
      const delay = stateRef.current.retryCount > 0 ? retryDelay : pollInterval
      stateRef.current.pollTimeout = setTimeout(poll, delay)
    }
    poll()
  }

  // 标记收到 WS 事件（用于超时检测）
  const markWsEvent = () => {
    stateRef.current.lastWsEventAt = Date.now()
  }

  // 启动 WS 事件超时检测：如果连接后一段时间没收到事件，自动回退到轮询
  const startWsFallbackCheck = () => {
    clearWsFallbackCheck()
    stateRef.current.wsFallbackCheckId = setTimeout(() => {
      if (stateRef.current.isComplete) return
      // WS 连接但超时无事件 → 回退到轮询
      console.warn('[useScanProgress] No WS events received, falling back to polling')
      startPolling()
    }, WS_EVENT_TIMEOUT_MS)
  }

  const clearWsFallbackCheck = () => {
    if (stateRef.current.wsFallbackCheckId) {
      clearTimeout(stateRef.current.wsFallbackCheckId)
      stateRef.current.wsFallbackCheckId = null
    }
  }

  // WebSocket 连接状态处理
  const { state: wsState } = useWebSocket(scanId, {
    onProgress: (data) => {
      markWsEvent()
      stopPolling()
      clearWsFallbackCheck()

      setProgress((prev) => {
        const updated = prev ? { ...prev, ...data } : null
        onProgressChange?.(updated as ScanProgressResponse)
        return updated
      })
    },
    onPhaseStart: () => {
      markWsEvent()
      // 收到事件说明 WS 通道正常，取消 fallback 检查
      clearWsFallbackCheck()
    },
    onPhaseComplete: (data) => {
      markWsEvent()
      clearWsFallbackCheck()
      // 阶段完成时刷新完整进度
      fetchProgress()
    },
    onFindingNew: () => {
      markWsEvent()
      clearWsFallbackCheck()
    },
    onScanComplete: (data) => {
      markWsEvent()
      clearWsFallbackCheck()
      stateRef.current.isComplete = true
      fetchProgress().then(() => {
        onComplete?.(progress!)
      })
    },
    onScanFailed: (error) => {
      markWsEvent()
      clearWsFallbackCheck()
      stateRef.current.isComplete = true
      onFailed?.(error)
    },
    onScanPaused: () => {
      markWsEvent()
      clearWsFallbackCheck()
    },
    onConcurrencyUpdate: (data) => {
      markWsEvent()
      setConcurrency((prev) => ({ ...prev, [data.manager]: data }))
    },
  })

  // 保存 WebSocket 状态到 ref
  stateRef.current.wsState = wsState as 'connected' | 'disconnected' | 'error' | 'connecting'

  // 统一处理轮询和 WebSocket 状态
  useEffect(() => {
    if (!enabled || !scanId) return

    // 初始加载
    fetchProgress()

    // 清理函数
    return () => {
      stopPolling()
      clearWsFallbackCheck()
    }
  }, [scanId, enabled]) // 只依赖 scanId 和 enabled

  // 单独处理 WebSocket 状态变化（使用 ref 避免依赖循环）
  useEffect(() => {
    if (!enabled || !scanId || stateRef.current.isComplete) return

    const currentWsState = stateRef.current.wsState

    // WebSocket 连接成功时：停止轮询，但启动超时检测
    if (currentWsState === 'connected') {
      stopPolling()
      // 如果从未收到过 WS 事件，启动 fallback 检测
      if (stateRef.current.lastWsEventAt === 0) {
        startWsFallbackCheck()
      }
    }
    // WebSocket 失败或断开时启动轮询
    else if (currentWsState === 'disconnected' || currentWsState === 'error') {
      clearWsFallbackCheck()
      startPolling()
    }
  }, [wsState]) // 只依赖 wsState，避免触发整个 effect 重跑

  // 控制操作
  const pause = async () => {
    if (!scanId) return
    try {
      await scansApi.pause(scanId)
      await fetchProgress()
    } catch (err) {
      console.error('Failed to pause scan:', err)
    }
  }

  const resume = async () => {
    if (!scanId) return
    try {
      await scansApi.resume(scanId)
      await fetchProgress()
      stateRef.current.isComplete = false // 重置完成状态
    } catch (err) {
      console.error('Failed to resume scan:', err)
    }
  }

  const cancel = async () => {
    if (!scanId) return
    try {
      await scansApi.cancel(scanId)
      await fetchProgress()
      stateRef.current.isComplete = true
    } catch (err) {
      console.error('Failed to cancel scan:', err)
    }
  }

  // 强制刷新：重置完成状态后再获取进度
  const forceRefresh = async () => {
    stateRef.current.isComplete = false
    return fetchProgress()
  }

  return {
    progress,
    status,
    usingPolling,
    wsState,
    concurrency,
    pause,
    resume,
    cancel,
    refresh: fetchProgress,
    forceRefresh,
  }
}
