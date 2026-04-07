import { useEffect, useState, useRef } from 'react'
import { useWebSocket } from './useWebSocket'
import { scansApi } from '@/api/scans'
import type { ScanProgressResponse, ScanStatus } from '@/types/models'

interface UseScanProgressOptions {
  enabled?: boolean
  pollInterval?: number // 轮询间隔（毫秒）
  onProgressChange?: (progress: ScanProgressResponse) => void
  onComplete?: (result: ScanProgressResponse) => void
  onFailed?: (error: string) => void
}

export function useScanProgress(
  scanId: number | null,
  options: UseScanProgressOptions = {}
) {
  const {
    enabled = true,
    pollInterval = 5000,
    onProgressChange,
    onComplete,
    onFailed,
  } = options

  const [progress, setProgress] = useState<ScanProgressResponse | null>(null)
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [usingPolling, setUsingPolling] = useState(false)
  const pollTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const isCompleteRef = useRef(false)

  // 获取进度数据
  const fetchProgress = async () => {
    if (!scanId || isCompleteRef.current) return

    try {
      const data = await scansApi.getProgress(scanId)
      setProgress(data)
      setStatus(data.status)

      onProgressChange?.(data)

      // 检查是否完成
      if (data.status === 'completed') {
        isCompleteRef.current = true
        onComplete?.(data)
        return false // 停止轮询
      }

      if (data.status === 'failed') {
        isCompleteRef.current = true
        onFailed?.('扫描失败')
        return false // 停止轮询
      }

      return true // 继续轮询
    } catch (err) {
      console.error('Failed to fetch progress:', err)
      return true // 出错也继续轮询
    }
  }

  // 轮询逻辑
  const startPolling = () => {
    if (pollTimeoutRef.current) return

    setUsingPolling(true)
    const poll = async () => {
      const shouldContinue = await fetchProgress()
      if (shouldContinue && !isCompleteRef.current) {
        pollTimeoutRef.current = setTimeout(poll, pollInterval)
      } else {
        pollTimeoutRef.current = null
      }
    }
    poll()
  }

  const stopPolling = () => {
    if (pollTimeoutRef.current) {
      clearTimeout(pollTimeoutRef.current)
      pollTimeoutRef.current = null
    }
    setUsingPolling(false)
  }

  // WebSocket 连接状态处理
  const { state: wsState } = useWebSocket(scanId, {
    onProgress: (data) => {
      setUsingPolling(false)
      stopPolling()

      setProgress((prev) => {
        const updated = prev ? { ...prev, ...data } : null
        onProgressChange?.(updated as ScanProgressResponse)
        return updated
      })
    },
    onPhaseComplete: (data) => {
      // 阶段完成时刷新完整进度
      fetchProgress()
    },
    onScanComplete: (data) => {
      isCompleteRef.current = true
      fetchProgress().then(() => {
        onComplete?.(progress!)
      })
    },
    onScanFailed: (error) => {
      isCompleteRef.current = true
      onFailed?.(error)
    },
  })

  // 初始加载和状态变化时的处理
  useEffect(() => {
    if (!enabled || !scanId) return

    // 初始加载
    fetchProgress()

    // 如果 WebSocket 未连接，启动轮询
    if (wsState === 'disconnected' || wsState === 'error') {
      startPolling()
    }

    return () => {
      stopPolling()
    }
  }, [scanId, enabled, wsState])

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
      isCompleteRef.current = false // 重置完成状态
    } catch (err) {
      console.error('Failed to resume scan:', err)
    }
  }

  const cancel = async () => {
    if (!scanId) return
    try {
      await scansApi.cancel(scanId)
      await fetchProgress()
      isCompleteRef.current = true
    } catch (err) {
      console.error('Failed to cancel scan:', err)
    }
  }

  return {
    progress,
    status,
    usingPolling,
    wsState,
    pause,
    resume,
    cancel,
    refresh: fetchProgress,
  }
}
