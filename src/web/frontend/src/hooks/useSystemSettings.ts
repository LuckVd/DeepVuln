import { useQuery } from '@tanstack/react-query'
import { systemSettingsApi } from '@/api/system'
import { setTimezone } from '@/utils/format'

/**
 * Shared hook for system settings with 5-minute staleTime.
 * Prevents repeated API calls across Scans, ScanDetail, and FindingDrawer.
 */
export function useSystemSettings() {
  return useQuery({
    queryKey: ['systemSettings'],
    queryFn: async () => {
      const response = await systemSettingsApi.get()
      const tz = response.categories?.general?.['general.timezone']
      if (tz && typeof tz === 'string') {
        setTimezone(tz)
      }
      return response
    },
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  })
}
