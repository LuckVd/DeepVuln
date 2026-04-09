import { useParams, useNavigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import {
  Card,
  Badge,
  Button,
  Progress,
  Descriptions,
  Alert,
  LoadingPage,
  Statistic,
  Timeline,
} from '@/components/ui';
import {
  ArrowLeft,
  Play,
  Pause,
  Square,
  MessageSquare,
  Check,
  Loader2,
  Clock,
  X,
} from 'lucide-react';
import { useScan, useScanFindings } from '@/hooks/useApi';
import { useScanProgress } from '@/hooks/useScanProgress';
import { ScanProgress } from '@/components/scan';
import type { ScanStatus } from '@/types/models';

const STATUS_MAP: Record<string, { text: string; variant: 'pending' | 'running' | 'completed' | 'failed' }> = {
  pending: { text: 'WAITING', variant: 'pending' },
  running: { text: 'SCANNING', variant: 'running' },
  paused: { text: 'PAUSED', variant: 'pending' },
  completed: { text: 'COMPLETE', variant: 'completed' },
  failed: { text: 'FAILED', variant: 'failed' },
  cancelled: { text: 'CANCELLED', variant: 'failed' },
};

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const scanId = parseInt(id || '0');

  const { data: scan, isLoading, error } = useScan(scanId);
  const {
    progress,
    status: progressStatus,
    usingPolling,
    wsState,
    pause,
    resume,
    cancel,
  } = useScanProgress(isNaN(scanId) ? null : scanId, {
    enabled: !isNaN(scanId),
  });

  // Get events stream
  const [events, setEvents] = useState<any[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);

  // Load events
  useEffect(() => {
    if (scanId && !isNaN(scanId)) {
      const loadEvents = async () => {
        setEventsLoading(true);
        try {
          const { scansApi } = await import('@/api');
          const data = await scansApi.getEvents(scanId, { page: 1, page_size: 50 });
          setEvents(data.events || []);
        } catch (err) {
          console.error('Failed to load events:', err);
        } finally {
          setEventsLoading(false);
        }
      };
      loadEvents();
    }
  }, [scanId]);

  // Use progress or scan status (prefer progress)
  const currentStatus = (progress?.status || scan?.status || 'pending') as ScanStatus;
  const statusConfig = STATUS_MAP[currentStatus] || { text: currentStatus, variant: 'pending' as const };

  // Calculate control button availability
  const canPause = currentStatus === 'running';
  const canResume = currentStatus === 'paused';
  const canCancel = ['pending', 'running', 'paused'].includes(currentStatus);

  const handlePause = async () => {
    try {
      await pause();
    } catch (err) {
      console.error('Failed to pause:', err);
    }
  };

  const handleResume = async () => {
    try {
      await resume();
    } catch (err) {
      console.error('Failed to resume:', err);
    }
  };

  const handleCancel = async () => {
    try {
      await cancel();
    } catch (err) {
      console.error('Failed to cancel:', err);
    }
  };

  if (isNaN(scanId)) {
    return (
      <div className="p-6">
        <Alert variant="critical" title="INVALID SCAN ID">
          <div className="mt-4">
            <Button variant="outline" onClick={() => navigate('/scans')}>
              RETURN TO SCAN LIST
            </Button>
          </div>
        </Alert>
      </div>
    );
  }

  if (isLoading) {
    return <LoadingPage message="INITIALIZING..." />;
  }

  if (error || !scan) {
    return (
      <div className="p-6">
        <Alert variant="critical" title="LOADING FAILED">
          Unable to load scan details. Please try again later.
          <div className="mt-4">
            <Button variant="outline" onClick={() => navigate('/scans')}>
              RETURN TO SCAN LIST
            </Button>
          </div>
        </Alert>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <Button variant="outline" size="sm" onClick={() => navigate('/scans')}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          RETURN TO SCAN LIST
        </Button>
      </div>

      {/* Status Card */}
      <Card className="glass-panel mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <span className="font-mono text-cyan font-bold text-lg">SCAN #{String(scan.id).padStart(4, '0')}</span>
            <Badge variant={statusConfig.variant}>{statusConfig.text}</Badge>
            {usingPolling && <Badge variant="high">POLLING MODE</Badge>}
            {wsState === 'connected' && <Badge variant="running">LIVE</Badge>}
          </div>
          <div className="flex gap-2">
            {canPause && (
              <Button variant="outline" size="sm" onClick={handlePause}>
                <Pause className="mr-2 h-4 w-4" />
                PAUSE
              </Button>
            )}
            {canResume && (
              <Button size="sm" onClick={handleResume}>
                <Play className="mr-2 h-4 w-4" />
                RESUME
              </Button>
            )}
            {canCancel && (
              <Button variant="destructive" size="sm" onClick={handleCancel}>
                <Square className="mr-2 h-4 w-4" />
                CANCEL
              </Button>
            )}
          </div>
        </div>

        <Descriptions
          items={[
            {
              label: 'SCAN ID',
              value: <span className="text-cyan font-mono">#{String(scan.id).padStart(4, '0')}</span>,
            },
            {
              label: 'SCAN TYPE',
              value: scan.scan_type === 'full' ? 'FULL SCAN' : scan.scan_type === 'base' ? 'BASE SCAN' : 'INCREMENTAL',
            },
            {
              label: 'CREATED',
              value: new Date(scan.created_at).toLocaleString('zh-CN'),
            },
          ]}
          columns={3}
        />

        {/* Progress Bar */}
        {currentStatus !== 'failed' && currentStatus !== 'cancelled' && (
          <div className="mt-6">
            <Progress
              value={progress?.progress_percent || scan.progress_percent || 0}
              variant={currentStatus === 'running' ? 'cyan' : currentStatus === 'completed' ? 'green' : 'default'}
              className="h-3"
            />
            {scan.current_phase && (
              <div className="mt-3 text-text-secondary font-mono text-sm flex items-center gap-2">
                <Loader2 className="h-4 w-4 animate-spin text-cyan" />
                <span>PHASE: {scan.current_phase}</span>
                {scan.current_step && <span className="text-text-tertiary">// {scan.current_step}</span>}
              </div>
            )}
          </div>
        )}
      </Card>

      {/* Statistics Grid */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Statistic title="TOTAL FILES" value={scan.total_files || 0} />
        <Statistic title="INDEXED" value={scan.indexed_files || 0} />
        <Statistic title="ANALYZED" value={scan.analyzed_files || 0} />
        <Statistic
          title="FINDINGS"
          value={scan.findings_count || 0}
          valueClassName={(scan.findings_count || 0) > 0 ? 'text-critical' : ''}
        />
      </div>

      {/* Token Usage */}
      {(scan.tokens_used !== null || scan.tokens_budget !== null) && (
        <Card className="glass-panel mb-6">
          <h3 className="text-cyan font-mono font-bold mb-4">TOKEN USAGE</h3>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <Statistic title="USED" value={scan.tokens_used || 0} />
            <Statistic title="BUDGET" value={scan.tokens_budget || 0} />
            <Statistic
              title="REMAINING"
              value={(scan.tokens_budget || 0) - (scan.tokens_used || 0)}
              valueClassName={
                (scan.tokens_budget || 0) - (scan.tokens_used || 0) < (scan.tokens_budget || 0) * 0.2
                  ? 'text-critical'
                  : ''
              }
            />
          </div>
          {scan.tokens_budget && scan.tokens_used && (
            <Progress
              value={Math.round((scan.tokens_used / scan.tokens_budget) * 100)}
              variant={scan.tokens_used / scan.tokens_budget > 0.9 ? 'critical' : 'cyan'}
              className="h-2"
            />
          )}
        </Card>
      )}

      {/* Vulnerability Distribution */}
      <Card className="glass-panel mb-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-cyan font-mono font-bold">VULNERABILITY DISTRIBUTION</h3>
          {scan.findings_count && scan.findings_count > 0 && (
            <Button size="sm" onClick={() => navigate(`/scans/${scan.id}/findings`)}>
              VIEW ALL FINDINGS
            </Button>
          )}
        </div>
        <div className="grid grid-cols-6 gap-4">
          <Statistic
            title="CRITICAL"
            value={scan.critical_count || 0}
            valueClassName={scan.critical_count ? 'text-critical' : ''}
          />
          <Statistic
            title="HIGH"
            value={scan.high_count || 0}
            valueClassName={scan.high_count ? 'text-warning' : ''}
          />
          <Statistic
            title="MEDIUM"
            value={scan.medium_count || 0}
            valueClassName={scan.medium_count ? 'text-yellow-500' : ''}
          />
          <Statistic
            title="LOW"
            value={scan.low_count || 0}
            valueClassName={scan.low_count ? 'text-success' : ''}
          />
          <Statistic
            title="INFO"
            value={scan.info_count || 0}
            valueClassName={scan.info_count ? 'text-text-secondary' : ''}
          />
          <Statistic
            title="VERIFIED"
            value={scan.verified_count || 0}
            valueClassName={scan.verified_count ? 'text-purple-400' : ''}
          />
        </div>
      </Card>

      {/* Phase Timeline */}
      {progress?.phases && progress.phases.length > 0 && (
        <Card className="glass-panel mb-6">
          <h3 className="text-cyan font-mono font-bold mb-4">SCAN TIMELINE</h3>
          <Timeline
            items={progress.phases.map((phase) => {
              const statusMap: Record<string, 'completed' | 'running' | 'pending' | 'failed'> = {
                completed: 'completed',
                running: 'running',
                pending: 'pending',
                failed: 'failed',
              };

              return {
                status: statusMap[phase.status] || 'pending',
                title: (
                  <div className="flex items-center justify-between">
                    <span className="font-mono">{phase.name}</span>
                    <Badge variant={STATUS_MAP[phase.status]?.variant || 'pending'}>
                      {phase.status.toUpperCase()}
                    </Badge>
                  </div>
                ),
                description: phase.status === 'completed' ? (
                  <div className="text-xs text-text-secondary font-mono mt-2 space-y-1">
                    <span>DURATION: {phase.duration_seconds?.toFixed(1)}s</span>
                    {phase.findings > 0 && <span> | FINDINGS: {phase.findings}</span>}
                    {phase.tokens_used > 0 && <span> | TOKENS: {phase.tokens_used}</span>}
                  </div>
                ) : undefined,
                progress: phase.progress_percent,
              };
            })}
          />
        </Card>
      )}

      {/* Real-time Progress */}
      {currentStatus === 'running' && progress && (
        <Card className="glass-panel mb-6">
          <h3 className="text-cyan font-mono font-bold mb-4">REAL-TIME PROGRESS</h3>
          <ScanProgress progress={progress} />
        </Card>
      )}

      {/* Events Log */}
      <Card className="glass-panel">
        <div className="flex items-center gap-2 mb-4">
          <MessageSquare className="h-5 w-5 text-cyan" />
          <h3 className="text-cyan font-mono font-bold">EVENT LOG</h3>
        </div>
        <div className="space-y-2 font-mono text-sm max-h-96 overflow-y-auto">
          {eventsLoading ? (
            <div className="text-center text-text-secondary py-8">
              <Loader2 className="h-5 w-5 animate-spin mx-auto mb-2" />
              LOADING EVENTS...
            </div>
          ) : events.length === 0 ? (
            <div className="text-center text-text-tertiary py-8">NO EVENTS RECORDED</div>
          ) : (
            events.map((event: any, index: number) => (
              <div
                key={index}
                className="flex items-start gap-3 p-3 rounded bg-background-tertiary border border-border hover:border-cyan/50 transition-colors"
              >
                <Badge
                  variant={
                    event.event_level === 'error'
                      ? 'critical'
                      : event.event_level === 'warning'
                      ? 'high'
                      : event.event_level === 'info'
                      ? 'info'
                      : 'pending'
                  }
                  className="shrink-0"
                >
                  {event.event_type}
                </Badge>
                <div className="flex-1 min-w-0">
                  <div className="text-text-primary">{event.message}</div>
                  {event.file_path && (
                    <div className="text-text-tertiary text-xs mt-1">{event.file_path}</div>
                  )}
                </div>
                <div className="text-text-tertiary text-xs whitespace-nowrap">
                  {new Date(event.created_at).toLocaleTimeString('zh-CN')}
                </div>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}
