import { useEffect, useRef, useState } from 'react'
import { getWebSocketClient } from '@/api/websocket'
import type { ConnectionState } from '@/types/websocket'

interface UseWebSocketOptions {
  onMessage?: (event: any) => void
  onProgress?: (data: { progress_percent: number; current_file?: string; message?: string }) => void
  onPhaseStart?: (data: { phase: string }) => void
  onPhaseComplete?: (data: { phase: string; findings: number; duration_seconds: number }) => void
  onFindingNew?: (data: any) => void
  onScanComplete?: (data: any) => void
  onScanFailed?: (error: string) => void
  onScanPaused?: (checkpoint_saved: boolean) => void
}

export function useWebSocket(scanId: number | null, options: UseWebSocketOptions = {}) {
  const [state, setState] = useState<ConnectionState>('disconnected')
  const clientRef = useRef(getWebSocketClient())

  useEffect(() => {
    const client = clientRef.current

    // 订阅状态变化
    const unsubscribeState = client.onStateChange(setState)

    // 订阅各种事件
    const unsubscribers: (() => void)[] = []

    if (options.onMessage) {
      unsubscribers.push(
        client.on('connected', options.onMessage),
        client.on('pong', options.onMessage),
      )
    }

    if (options.onProgress) {
      unsubscribers.push(
        client.on('progress', (event) => {
          options.onProgress?.(event.data)
        })
      )
    }

    if (options.onPhaseStart) {
      unsubscribers.push(
        client.on('phase_start', (event) => {
          options.onPhaseStart?.({ phase: event.data.phase })
        })
      )
    }

    if (options.onPhaseComplete) {
      unsubscribers.push(
        client.on('phase_complete', (event) => {
          options.onPhaseComplete?.({
            phase: event.data.phase,
            findings: event.data.findings,
            duration_seconds: event.data.duration_seconds,
          })
        })
      )
    }

    if (options.onFindingNew) {
      unsubscribers.push(
        client.on('finding_new', (event) => {
          options.onFindingNew?.(event.data)
        })
      )
    }

    if (options.onScanComplete) {
      unsubscribers.push(
        client.on('scan_complete', (event) => {
          options.onScanComplete?.(event.data)
        })
      )
    }

    if (options.onScanFailed) {
      unsubscribers.push(
        client.on('scan_failed', (event) => {
          options.onScanFailed?.(event.data.error)
        })
      )
    }

    if (options.onScanPaused) {
      unsubscribers.push(
        client.on('scan_paused', (event) => {
          options.onScanPaused?.(event.data.checkpoint_saved)
        })
      )
    }

    return () => {
      unsubscribeState()
      unsubscribers.forEach((unsub) => unsub())
      client.disconnect()
    }
  }, [options])

  useEffect(() => {
    const client = clientRef.current

    if (scanId && state !== 'connected') {
      client.connect(scanId)
    } else if (!scanId && state === 'connected') {
      client.disconnect()
    }
  }, [scanId, state])

  return {
    state,
    connect: (id: number) => clientRef.current.connect(id),
    disconnect: () => clientRef.current.disconnect(),
    send: (data: any) => clientRef.current.send(data),
  }
}
