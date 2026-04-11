import { useQuery } from '@tanstack/react-query'
import client from '@/api/client'

// Dashboard statistics types
export interface DashboardStats {
  total_scans: number
  active_scans: number
  total_vulns: number
  critical_vulns: number
  severity_breakdown: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  recent_scans: number
}

export interface RecentActivity {
  items: Array<{
    id: number
    name: string
    status: string
    progress_percent: number
    findings_count: number
    created_at: string | null
    completed_at: string | null
  }>
}

// Fetch dashboard statistics
export function useDashboardStats() {
  return useQuery<DashboardStats>({
    queryKey: ['dashboard', 'stats'],
    queryFn: async () => {
      const response = await client.get('/stats/dashboard')
      return response.data
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  })
}

// Fetch recent activity
export function useRecentActivity(limit: number = 10) {
  return useQuery<RecentActivity>({
    queryKey: ['dashboard', 'activity', limit],
    queryFn: async () => {
      const response = await client.get('/stats/recent-activity', { params: { limit } })
      return response.data
    },
    refetchInterval: 15000, // Refresh every 15 seconds
  })
}
