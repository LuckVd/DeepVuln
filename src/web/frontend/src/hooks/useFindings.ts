import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scansApi } from '@/api/scans'
import type { Finding, FindingStatusUpdate, SeverityLevel, FindingStatus } from '@/types/models'

interface UseFindingsParams {
  scanId: number
  page?: number
  page_size?: number
  severity?: SeverityLevel
  status?: FindingStatus
  engine?: string
  sort_field?: string
  sort_dir?: string
  enabled?: boolean
}

interface FindingsResponse {
  scan_id: number
  total: number
  page: number
  page_size: number
  summary: {
    total: number
    verified: number
    false_positive: number
    by_severity: Record<SeverityLevel, number>
  }
  findings: Finding[]
}

/**
 * 漏洞数据管理 Hook
 */
export function useFindings({
  scanId,
  page = 1,
  page_size = 20,
  severity,
  status,
  engine,
  sort_field,
  sort_dir,
  enabled = true,
}: UseFindingsParams) {
  const queryClient = useQueryClient()

  // 获取漏洞列表
  const findingsQuery = useQuery({
    queryKey: ['findings', scanId, page, page_size, severity, status, engine, sort_field, sort_dir],
    queryFn: () =>
      scansApi.getFindings(scanId, {
        page,
        page_size,
        severity,
        status,
        engine,
        sort_field,
        sort_dir,
      }),
    enabled: enabled && !!scanId,
  })

  // 更新漏洞状态
  const updateStatusMutation = useMutation({
    mutationFn: ({ findingId, data }: { findingId: number; data: FindingStatusUpdate }) =>
      scansApi.updateFindingStatus(scanId, findingId, data),
    onSuccess: () => {
      // 使查询无效，触发重新获取
      queryClient.invalidateQueries({
        queryKey: ['findings', scanId],
      })
    },
  })

  return {
    data: findingsQuery.data,
    isLoading: findingsQuery.isLoading,
    error: findingsQuery.error,
    refetch: findingsQuery.refetch,

    // 状态更新操作
    updateStatus: (findingId: number, status: FindingStatus) => {
      updateStatusMutation.mutate({
        findingId,
        data: { status },
      })
    },
    isUpdating: updateStatusMutation.isPending,
    updateError: updateStatusMutation.error,
  }
}

/**
 * 单个漏洞 Hook
 */
export function useFinding(scanId: number, findingId: number) {
  return useQuery({
    queryKey: ['finding', scanId, findingId],
    queryFn: async () => {
      const data = await scansApi.getFindings(scanId, { page: 1, page_size: 1000 })
      return data.findings.find((f) => f.id === findingId)
    },
    enabled: !!scanId && !!findingId,
  })
}
