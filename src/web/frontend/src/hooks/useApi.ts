import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scansApi } from '@/api'
import type {
  Scan,
  ScanCreate,
} from '@/types/models'

// ==================== Scans ====================

/**
 * 获取扫描列表
 */
export function useScans(params?: {
  page?: number
  page_size?: number
  status?: string
}) {
  return useQuery({
    queryKey: ['scans', params],
    queryFn: () => scansApi.list(params),
  })
}

/**
 * 获取扫描详情
 */
export function useScan(id: number) {
  return useQuery({
    queryKey: ['scan', id],
    queryFn: () => scansApi.get(id),
    enabled: !!id,
    refetchInterval: (query) => {
      // 如果扫描正在运行，每 5 秒刷新一次
      const data = query.state.data as Scan | undefined
      return data?.status === 'running' ? 5000 : false
    },
  })
}

/**
 * 创建扫描
 */
export function useCreateScan() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: ScanCreate) => scansApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}

/**
 * 获取扫描漏洞列表
 */
export function useScanFindings(
  scanId: number,
  params?: {
    page?: number
    page_size?: number
    severity?: string
    status?: string
  }
) {
  return useQuery({
    queryKey: ['scan', scanId, 'findings', params],
    queryFn: () => scansApi.getFindings(scanId, params),
    enabled: !!scanId,
  })
}

/**
 * 暂停扫描
 */
export function usePauseScan() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (scanId: number) => scansApi.pause(scanId),
    onSuccess: (_, scanId) => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
    },
  })
}

/**
 * 继续扫描
 */
export function useResumeScan() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (scanId: number) => scansApi.resume(scanId),
    onSuccess: (_, scanId) => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
    },
  })
}

/**
 * 取消扫描
 */
export function useCancelScan() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (scanId: number) => scansApi.cancel(scanId),
    onSuccess: (_, scanId) => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
    },
  })
}
