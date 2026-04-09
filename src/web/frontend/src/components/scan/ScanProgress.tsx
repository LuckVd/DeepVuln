import React from 'react';
import { Card, Badge, Progress, Statistic, Timeline } from '@/components/ui';
import { Check, Loader2, Clock, X, Pause } from 'lucide-react';
import type { ScanProgressResponse, PhaseInfo } from '@/types/models';
import { cn } from '@/shared/utils/cn';

interface ScanProgressProps {
  progress: ScanProgressResponse | null;
  loading?: boolean;
}

const PHASE_LABELS: Record<string, string> = {
  'L1_preparation': 'L1 PREPARATION',
  'L1_attack_surface': 'L1 ATTACK SURFACE',
  'L2_semgrep': 'L2 SEMGREP',
  'L2_codeql': 'L2 CODEQL',
  'L3_agent': 'L3 AGENT AUDIT',
  'L3_adjudication': 'L3 ADJUDICATION',
  'report_generation': 'REPORT GENERATION',
};

const STATUS_ICONS: Record<string, React.ReactNode> = {
  completed: <Check className="h-4 w-4" />,
  running: <Loader2 className="h-4 w-4 animate-spin" />,
  pending: <Clock className="h-4 w-4" />,
  failed: <X className="h-4 w-4" />,
  skipped: <Pause className="h-4 w-4" />,
};

export function ScanProgress({ progress, loading }: ScanProgressProps) {
  if (loading || !progress) {
    return (
      <Card className="glass-panel">
        <div className="text-center text-text-secondary font-mono py-8">
          <span className="inline-flex items-center gap-2">
            <Loader2 className="h-5 w-5 animate-spin text-cyan" />
            AWAITING SCAN DATA...
          </span>
        </div>
      </Card>
    );
  }

  const getStatusBadge = (status: string) => {
    const statusMap: Record<string, 'pending' | 'running' | 'completed' | 'failed'> = {
      pending: 'pending',
      running: 'running',
      paused: 'pending',
      completed: 'completed',
      failed: 'failed',
      cancelled: 'failed',
    };
    return statusMap[status] || 'pending';
  };

  const getPhaseStatus = (phase: PhaseInfo) => {
    const statusMap: Record<string, 'completed' | 'running' | 'pending' | 'failed'> = {
      completed: 'completed',
      running: 'running',
      pending: 'pending',
      failed: 'failed',
      skipped: 'pending',
    };
    return statusMap[phase.status] || 'pending';
  };

  return (
    <div className="space-y-4">
      {/* Overall Progress */}
      <Card className="glass-panel">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-cyan font-mono font-bold">SCAN STATUS</h3>
          <Badge variant={getStatusBadge(progress.status)}>
            {progress.status.toUpperCase()}
          </Badge>
        </div>
        <Progress
          value={progress.progress_percent}
          variant={progress.status === 'failed' ? 'critical' : progress.status === 'completed' ? 'green' : 'cyan'}
          className="h-3 mb-3"
        />
        {progress.current_step && (
          <div className="text-sm text-text-secondary font-mono">{progress.current_step}</div>
        )}

        {/* Quick Stats */}
        <div className="grid grid-cols-3 gap-4 mt-6">
          <div className="text-center">
            <div className="text-2xl font-bold font-mono text-cyan">
              {progress.analyzed_files}/{progress.total_files}
            </div>
            <div className="text-xs text-text-secondary font-mono mt-1">FILES</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold font-mono text-critical">
              {progress.findings.total}
            </div>
            <div className="text-xs text-text-secondary font-mono mt-1">VULNS</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold font-mono text-warning">
              {progress.tokens.used}
            </div>
            <div className="text-xs text-text-secondary font-mono mt-1">TOKENS</div>
          </div>
        </div>
      </Card>

      {/* Phase Progress */}
      <Card className="glass-panel">
        <h3 className="text-cyan font-mono font-bold mb-4">SCAN PHASES</h3>
        <Timeline
          items={progress.phases.map((phase) => ({
            status: getPhaseStatus(phase),
            title: (
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm">
                  {PHASE_LABELS[phase.name] || phase.name}
                </span>
                <Badge variant={getStatusBadge(phase.status)} className="min-w-[80px] justify-center">
                  {phase.status.toUpperCase()}
                </Badge>
              </div>
            ),
            description: (
              <div className="space-y-2 mt-2">
                {phase.status === 'running' && (
                  <Progress value={phase.progress_percent} variant="cyan" className="h-1" />
                )}
                {phase.status === 'completed' && (
                  <div className="flex gap-4 text-xs font-mono text-text-secondary">
                    <span>TIME: {phase.duration_seconds?.toFixed(1)}s</span>
                    {phase.findings > 0 && <span>VULNS: {phase.findings}</span>}
                    {phase.tokens_used > 0 && <span>TOKENS: {phase.tokens_used}</span>}
                  </div>
                )}
              </div>
            ),
          }))}
        />
      </Card>

      {/* Engine Status */}
      <Card className="glass-panel">
        <h3 className="text-cyan font-mono font-bold mb-4">ENGINE STATUS</h3>
        <div className="space-y-3 font-mono text-sm">
          <div className="flex items-center justify-between">
            <span className="text-text-secondary">COMPLETED:</span>
            <div className="flex gap-2">
              {progress.engines.completed.map((engine) => (
                <Badge key={engine} variant="completed">{engine}</Badge>
              ))}
              {progress.engines.completed.length === 0 && <span className="text-text-tertiary">--</span>}
            </div>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-text-secondary">RUNNING:</span>
            <div className="flex gap-2">
              {progress.engines.running ? (
                <Badge variant="running">{progress.engines.running}</Badge>
              ) : (
                <span className="text-text-tertiary">--</span>
              )}
            </div>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-text-secondary">PENDING:</span>
            <div className="flex gap-2">
              {progress.engines.pending.map((engine) => (
                <Badge key={engine} variant="pending">{engine}</Badge>
              ))}
              {progress.engines.pending.length === 0 && <span className="text-text-tertiary">--</span>}
            </div>
          </div>
        </div>
      </Card>

      {/* Vulnerability Statistics */}
      <Card className="glass-panel">
        <h3 className="text-cyan font-mono font-bold mb-4">VULNERABILITY STATS</h3>
        <div className="grid grid-cols-6 gap-4">
          <Statistic title="TOTAL" value={progress.findings.total} valueClassName="text-critical" />
          <Statistic title="VERIFIED" value={progress.findings.verified} valueClassName="text-success" />
          <Statistic
            title="FALSE POS"
            value={progress.findings.false_positive}
            valueClassName="text-text-tertiary"
          />
          <Statistic
            title="CRITICAL"
            value={progress.findings.by_severity.critical}
            valueClassName={progress.findings.by_severity.critical > 0 ? 'text-critical' : ''}
          />
          <Statistic
            title="HIGH"
            value={progress.findings.by_severity.high}
            valueClassName={progress.findings.by_severity.high > 0 ? 'text-warning' : ''}
          />
          <Statistic
            title="MEDIUM"
            value={progress.findings.by_severity.medium}
            valueClassName={progress.findings.by_severity.medium > 0 ? 'text-yellow-500' : ''}
          />
        </div>
      </Card>
    </div>
  );
}

export default ScanProgress;
