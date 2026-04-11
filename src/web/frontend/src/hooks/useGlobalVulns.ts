import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { globalVulnsApi, scansApi } from '@/api/scans';
import type { FindingStatus, SeverityLevel } from '@/types/models';

interface UseGlobalVulnsParams {
  page?: number;
  page_size?: number;
  severity?: SeverityLevel;
  status?: FindingStatus;
  search?: string;
  enabled?: boolean;
}

/**
 * Hook for global vulnerabilities list across all scans
 */
export function useGlobalVulns(params: UseGlobalVulnsParams = {}) {
  const {
    page = 1,
    page_size = 20,
    severity,
    status,
    search = '',
    enabled = true,
  } = params;

  return useQuery({
    queryKey: ['global-vulns', page, page_size, severity, status, search],
    queryFn: () => globalVulnsApi.list({ page, page_size, severity, status, search }),
    enabled,
  });
}

/**
 * Hook for global vulnerabilities summary
 */
export function useGlobalVulnsSummary(enabled: boolean = true) {
  return useQuery({
    queryKey: ['global-vulns-summary'],
    queryFn: () => globalVulnsApi.getSummary(),
    enabled,
  });
}

/**
 * Hook for updating finding status (works with global vulnerabilities)
 */
export function useUpdateFindingStatus() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ scanId, findingId, status }: {
      scanId: number;
      findingId: number;
      status: FindingStatus;
    }) => scansApi.updateFindingStatus(scanId, findingId, { status }),

    onSuccess: () => {
      // Invalidate related queries
      queryClient.invalidateQueries({ queryKey: ['global-vulns'] });
      queryClient.invalidateQueries({ queryKey: ['global-vulns-summary'] });
    },
  });
}
