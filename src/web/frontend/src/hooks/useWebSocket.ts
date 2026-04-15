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
  onConcurrencyUpdate?: (data: import('@/types/websocket').ConcurrencyUpdateData) => void
}

export function useWebSocket(scanId: number | null, options: UseWebSocketOptions = {}) {
  const [state, setState] = useState<ConnectionState>('disconnected')
  const clientRef = useRef(getWebSocketClient())

  // Keep options in a ref so event subscriptions always use latest callbacks
  // without triggering effect re-run (which would disconnect WS).
  const optionsRef = useRef(options)
  optionsRef.current = options

  // --- Event subscriptions (no disconnect in cleanup!) ---
  useEffect(() => {
    const client = clientRef.current

    // Subscribe to state changes
    const unsubscribeState = client.onStateChange((newState) => {
      setState(newState)
    })

    // Subscribe to events using ref-based callbacks
    const unsubscribers: (() => void)[] = []

    unsubscribers.push(
      client.on('progress', (event) => {
        optionsRef.current.onProgress?.(event.data)
      })
    )

    unsubscribers.push(
      client.on('phase_start', (event) => {
        optionsRef.current.onPhaseStart?.({ phase: event.data.phase })
      })
    )

    unsubscribers.push(
      client.on('phase_complete', (event) => {
        optionsRef.current.onPhaseComplete?.({
          phase: event.data.phase,
          findings: event.data.findings,
          duration_seconds: event.data.duration_seconds,
        })
      })
    )

    unsubscribers.push(
      client.on('finding_new', (event) => {
        optionsRef.current.onFindingNew?.(event.data)
      })
    )

    unsubscribers.push(
      client.on('scan_complete', (event) => {
        optionsRef.current.onScanComplete?.(event.data)
      })
    )

    unsubscribers.push(
      client.on('scan_failed', (event) => {
        optionsRef.current.onScanFailed?.(event.data.error)
      })
    )

    unsubscribers.push(
      client.on('scan_paused', (event) => {
        optionsRef.current.onScanPaused?.(event.data.checkpoint_saved)
      })
    )

    unsubscribers.push(
      client.on('concurrency_update', (event) => {
        optionsRef.current.onConcurrencyUpdate?.(event.data)
      })
    )

    return () => {
      unsubscribeState()
      unsubscribers.forEach((unsub) => unsub())
      // NOTE: do NOT call client.disconnect() here!
      // Connection lifecycle is managed by the scanId effect below.
    }
  }, []) // Run once on mount

  // --- Connection management (driven only by scanId) ---
  useEffect(() => {
    const client = clientRef.current

    if (scanId) {
      client.connect(scanId)
    }

    return () => {
      client.disconnect()
    }
  }, [scanId])

  return {
    state,
    connect: (id: number) => clientRef.current.connect(id),
    disconnect: () => clientRef.current.disconnect(),
    send: (data: any) => clientRef.current.send(data),
  }
}
