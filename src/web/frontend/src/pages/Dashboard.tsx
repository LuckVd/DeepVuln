import { Card, Statistic, Badge, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui';
import { Activity, ShieldAlert, TrendingUp, AlertTriangle, Clock } from 'lucide-react';
import { useDashboardStats, useRecentActivity } from '@/hooks/useDashboard';
import { LoadingPage } from '@/components/ui';
import { useNavigate } from 'react-router-dom';

export default function DashboardPage() {
  const navigate = useNavigate();
  const { data: stats, isLoading: statsLoading, error: statsError } = useDashboardStats();
  const { data: activity, isLoading: activityLoading } = useRecentActivity(5);

  if (statsLoading) {
    return <LoadingPage message="INITIALIZING DASHBOARD..." />;
  }

  if (statsError || !stats) {
    return (
      <div className="p-6">
        <div className="text-center text-critical font-mono py-16">
          <AlertTriangle className="h-12 w-12 mx-auto mb-4" />
          <p>FAILED TO LOAD DASHBOARD DATA</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-text-primary font-mono tracking-wider">
            DASHBOARD
          </h1>
          <span className="text-cyan">//</span>
          <span className="text-cyan font-mono">OVERVIEW</span>
        </div>
        <p className="text-text-secondary font-sans">Security scan overview and statistics</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatisticCard
          title="TOTAL SCANS"
          value={stats.total_scans}
          icon={<Activity className="h-10 w-10" />}
          color="cyan"
          trend={`+${stats.recent_scans} this week`}
        />
        <StatisticCard
          title="ACTIVE SCANS"
          value={stats.active_scans}
          icon={<TrendingUp className="h-10 w-10" />}
          color="warning"
        />
        <StatisticCard
          title="TOTAL VULNS"
          value={stats.total_vulns}
          icon={<ShieldAlert className="h-10 w-10" />}
          color="critical"
        />
        <StatisticCard
          title="CRITICAL"
          value={stats.critical_vulns}
          icon={<AlertTriangle className="h-10 w-10" />}
          color="critical"
        />
      </div>

      {/* Severity Breakdown */}
      <Card className="glass-panel mb-6">
        <h3 className="text-cyan font-mono font-bold mb-4">VULNERABILITY BREAKDOWN</h3>
        <div className="grid grid-cols-5 gap-4">
          <SeverityStat label="CRITICAL" count={stats.severity_breakdown.critical} color="critical" />
          <SeverityStat label="HIGH" count={stats.severity_breakdown.high} color="high" />
          <SeverityStat label="MEDIUM" count={stats.severity_breakdown.medium} color="medium" />
          <SeverityStat label="LOW" count={stats.severity_breakdown.low} color="low" />
          <SeverityStat label="INFO" count={stats.severity_breakdown.info} color="info" />
        </div>
      </Card>

      {/* Recent Activity */}
      <div className="grid grid-cols-2 gap-6">
        <Card className="glass-panel">
          <h3 className="text-cyan font-mono font-bold mb-4">RECENT SCANS</h3>
          {activityLoading ? (
            <div className="text-center text-text-secondary font-mono py-8">
              LOADING...
            </div>
          ) : activity && activity.items.length > 0 ? (
            <div className="space-y-2">
              {activity.items.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center justify-between p-3 rounded bg-background-tertiary border border-border hover:border-cyan/50 transition-colors cursor-pointer"
                  onClick={() => navigate(`/scans/${item.id}`)}
                >
                  <div className="flex-1 min-w-0">
                    <div className="font-mono text-cyan text-sm truncate">#{String(item.id).padStart(4, '0')}</div>
                    <div className="text-text-primary text-sm truncate">{item.name}</div>
                  </div>
                  <Badge
                    variant={
                      item.status === 'running' ? 'running' :
                      item.status === 'completed' ? 'completed' :
                      item.status === 'failed' ? 'failed' : 'pending'
                    }
                    className="min-w-[90px] justify-center"
                  >
                    {item.status.toUpperCase()}
                  </Badge>
                  {item.findings_count > 0 && (
                    <span className="text-critical font-mono text-sm ml-2">{item.findings_count}</span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center text-text-tertiary font-mono py-8">
              NO SCANS YET
            </div>
          )}
        </Card>

        <Card className="glass-panel">
          <h3 className="text-cyan font-mono font-bold mb-4">QUICK ACTIONS</h3>
          <div className="space-y-3">
            <QuickAction
              title="NEW SCAN"
              description="Start a new security scan"
              onClick={() => navigate('/scans')}
            />
            <QuickAction
              title="VIEW ALL SCANS"
              description="Browse all scan tasks"
              onClick={() => navigate('/scans')}
            />
            <QuickAction
              title="VULNERABILITIES"
              description="View all detected vulnerabilities"
              onClick={() => navigate('/vulnerabilities')}
            />
            <QuickAction
              title="REPORTS"
              description="Generate and download reports"
              onClick={() => navigate('/reports')}
            />
          </div>
        </Card>
      </div>
    </div>
  );
}

// Statistic Card Component
function StatisticCard({
  title,
  value,
  icon,
  color,
  trend,
}: {
  title: string;
  value: number;
  icon: React.ReactNode;
  color: 'cyan' | 'warning' | 'critical';
  trend?: string;
}) {
  const colorClasses = {
    cyan: 'text-cyan/50',
    warning: 'text-warning/50',
    critical: 'text-critical/50',
  };

  return (
    <Card className="glass-panel">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-text-secondary font-mono text-xs uppercase tracking-wider mb-2">
            {title}
          </div>
          <div className={`text-3xl font-bold font-mono ${
            color === 'critical' ? 'text-critical' :
            color === 'warning' ? 'text-warning' :
            'text-cyan'
          }`}>
            {value}
          </div>
          {trend && (
            <div className="text-text-secondary font-mono text-xs mt-2 flex items-center gap-1">
              <TrendingUp className="h-3 w-3" />
              {trend}
            </div>
          )}
        </div>
        <div className={colorClasses[color]}>{icon}</div>
      </div>
    </Card>
  );
}

// Severity Stat Component
function SeverityStat({
  label,
  count,
  color,
}: {
  label: string;
  count: number;
  color: 'critical' | 'high' | 'medium' | 'low' | 'info';
}) {
  const colorClasses = {
    critical: 'text-critical',
    high: 'text-warning',
    medium: 'text-yellow-500',
    low: 'text-success',
    info: 'text-text-secondary',
  };

  return (
    <div className="text-center">
      <div className={`text-2xl font-bold font-mono ${colorClasses[color]}`}>
        {count}
      </div>
      <div className="text-text-secondary font-mono text-xs uppercase mt-1">
        {label}
      </div>
    </div>
  );
}

// Quick Action Component
function QuickAction({
  title,
  description,
  onClick,
}: {
  title: string;
  description: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left p-4 rounded bg-background-tertiary border border-border hover:border-cyan/50 hover:bg-cyan/5 transition-all"
    >
      <div className="text-cyan font-mono font-bold mb-1">{title}</div>
      <div className="text-text-secondary text-sm">{description}</div>
    </button>
  );
}
