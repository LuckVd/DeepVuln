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
import { useLanguage } from '@/contexts/LanguageContext';
import { ScanProgress } from '@/components/scan';
import { scansApi } from '@/api/scans';
import type { ScanStatus } from '@/types/models';

const getStatusMap = (t: (key: string) => string) => ({
  pending: { text: t('status.waiting'), variant: 'pending' as const },
  running: { text: t('status.scanning'), variant: 'running' as const },
  paused: { text: t('status.paused'), variant: 'pending' as const },
  completed: { text: t('status.complete'), variant: 'completed' as const },
  failed: { text: t('status.failed'), variant: 'failed' as const },
  cancelled: { text: t('status.cancelled'), variant: 'failed' as const },
});

const getPhaseName = (phase: string, t: (key: string) => string): string => {
  const phaseMap: Record<string, string> = {
    l1_preparation: 'phase.l1_preparation',
    source_preparation: 'phase.source_preparation',
    engine_selection: 'phase.engine_selection',
    engine_execution: 'phase.engine_execution',
    exploitability_verification: 'phase.exploitability_verification',
    deduplication_adjudication: 'phase.deduplication_adjudication',
    adversarial_verification: 'phase.adversarial_verification',
    result_merging: 'phase.result_merging',
    token_statistics: 'phase.token_statistics',
  };
  const key = phaseMap[phase];
  return key ? t(key) : phase;
};

const getEventTypeName = (eventType: string, t: (key: string) => string): string => {
  const eventMap: Record<string, string> = {
    scan_complete: 'event.scan_complete',
    engine_start: 'event.engine_start',
    engine_complete: 'event.engine_complete',
    error: 'event.error',
    warning: 'event.warning',
    info: 'event.info',
  };
  const key = eventMap[eventType];
  return key ? t(key) : eventType;
};

const formatEventMessage = (event: any, t: (key: string) => string): string => {
  const { event_type, message } = event;

  // Try to parse and format known event messages
  if (event_type === 'scan_complete') {
    const match = message.match(/(\d+)\s+findings?/);
    if (match) {
      return t('event.scan_complete_msg').replace('{}', match[1]);
    }
  }

  if (event_type === 'engine_start') {
    const match = message.match(/Engine\s+['"](\w+)['"]\s+started/i);
    if (match) {
      return t('event.engine_start_msg').replace('{}', match[1]);
    }
  }

  if (event_type === 'engine_complete') {
    const match = message.match(/Engine\s+['"](\w+)['"]\s+completed\s+with\s+(\d+)\s+findings?/i);
    if (match) {
      return t('event.engine_complete_msg').replace('{}', match[1]).replace('{}', match[2]);
    }
  }

  // Return original message if no pattern matches
  return message;
};

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { t } = useLanguage();
  const scanId = parseInt(id || '0');
  const STATUS_MAP = getStatusMap(t);

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
  const canStart = currentStatus === 'pending';
  const canRetry = currentStatus === 'failed';
  const canPause = currentStatus === 'running';
  const canResume = currentStatus === 'paused';
  const canCancel = ['pending', 'running', 'paused'].includes(currentStatus);

  const handleStart = async () => {
    try {
      await scansApi.start(scanId);
      // Refresh after starting
      window.location.reload();
    } catch (err) {
      console.error('Failed to start:', err);
    }
  };

  const handleRetry = async () => {
    try {
      // For failed scans, create a new scan based on the failed one
      if (!scan) return;

      const retryData = {
        name: `${scan.name} (重试)`,
        source_type: scan.source_type,
        source_path: scan.source_path,
        branch: scan.branch || undefined,
        scan_type: scan.scan_type,
        config: scan.config,
      };

      const newScan = await scansApi.create(retryData);
      navigate(`/scans/${newScan.id}`);
    } catch (err) {
      console.error('Failed to retry scan:', err);
    }
  };

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
        <Alert variant="critical" title={t('scanDetail.invalidId')}>
          <div className="mt-4">
            <Button variant="outline" onClick={() => navigate('/scans')}>
              {t('scanDetail.returnToList')}
            </Button>
          </div>
        </Alert>
      </div>
    );
  }

  if (isLoading) {
    return <LoadingPage message={t('common.loading')} />;
  }

  if (error || !scan) {
    return (
      <div className="p-6">
        <Alert variant="critical" title={t('scanDetail.loadingFailed')}>
          {t('scanDetail.loadingFailedMsg')}
          <div className="mt-4">
            <Button variant="outline" onClick={() => navigate('/scans')}>
              {t('scanDetail.returnToList')}
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
          {t('scanDetail.returnToList')}
        </Button>
      </div>

      {/* Status Card */}
      <Card className="glass-panel mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <span className="font-mono text-cyan font-bold text-lg">{t('scanDetail.scan')} #{String(scan.id).padStart(4, '0')}</span>
            <Badge variant={statusConfig.variant}>{statusConfig.text}</Badge>
            {usingPolling && <Badge variant="high">{t('scanDetail.pollingMode')}</Badge>}
            {wsState === 'connected' && <Badge variant="running">{t('scanDetail.live')}</Badge>}
          </div>
          <div className="flex gap-2">
            {canStart && (
              <Button size="sm" onClick={handleStart}>
                <Play className="mr-2 h-4 w-4" />
                {t('scanDetail.resume')}
              </Button>
            )}
            {canRetry && (
              <Button variant="outline" size="sm" onClick={handleRetry} className="border-warning text-warning hover:bg-warning/10">
                <Play className="mr-2 h-4 w-4" />
                重新扫描
              </Button>
            )}
            {canPause && (
              <Button variant="outline" size="sm" onClick={handlePause}>
                <Pause className="mr-2 h-4 w-4" />
                {t('scanDetail.pause')}
              </Button>
            )}
            {canResume && (
              <Button size="sm" onClick={handleResume}>
                <Play className="mr-2 h-4 w-4" />
                {t('scanDetail.resume')}
              </Button>
            )}
            {canCancel && (
              <Button variant="destructive" size="sm" onClick={handleCancel}>
                <Square className="mr-2 h-4 w-4" />
                {t('scanDetail.cancel')}
              </Button>
            )}
          </div>
        </div>

        <Descriptions
          items={[
            {
              label: t('scanDetail.scanId'),
              value: <span className="text-cyan font-mono">#{String(scan.id).padStart(4, '0')}</span>,
            },
            {
              label: t('scanDetail.scanType'),
              value: scan.scan_type === 'full' ? t('scanDetail.fullScan') : scan.scan_type === 'base' ? t('scanDetail.baseScan') : t('scanDetail.incremental'),
            },
            {
              label: t('scanDetail.created'),
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
            {scan.current_phase && currentStatus === 'running' && (
              <div className="mt-3 text-text-secondary font-mono text-sm flex items-center gap-2">
                <Loader2 className="h-4 w-4 animate-spin text-cyan" />
                <span>{t('scanDetail.phase')}: {getPhaseName(scan.current_phase, t)}</span>
                {scan.current_step && <span className="text-text-tertiary">// {scan.current_step}</span>}
              </div>
            )}
            {scan.current_phase && currentStatus === 'completed' && (
              <div className="mt-3 text-text-secondary font-mono text-sm flex items-center gap-2">
                <Check className="h-4 w-4 text-success" />
                <span>{t('scanDetail.phase')}: {getPhaseName(scan.current_phase, t)}</span>
              </div>
            )}
          </div>
        )}
      </Card>

      {/* Statistics Grid */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Statistic title={t('scanDetail.totalFiles')} value={scan.total_files || 0} />
        <Statistic title={t('scanDetail.indexed')} value={scan.indexed_files || 0} />
        <Statistic title={t('scanDetail.analyzed')} value={scan.analyzed_files || 0} />
        <Statistic
          title={t('scanDetail.findings')}
          value={scan.findings_count || 0}
          valueClassName={(scan.findings_count || 0) > 0 ? 'text-critical' : ''}
        />
      </div>

      {/* Token Usage */}
      {(scan.tokens_used !== null || scan.tokens_used !== null) && (
        <Card className="glass-panel mb-6">
          <h3 className="text-cyan font-mono font-bold mb-4">{t('scanDetail.tokenUsage')}</h3>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <Statistic
              title={t('scanDetail.agentScanTokens')}
              value={(scan.token_usage as any)?.agent_scan_tokens || 0}
              valueClassName="text-cyan"
            />
            <Statistic
              title={t('scanDetail.adversarialTokens')}
              value={(scan.token_usage as any)?.adversarial_tokens || 0}
              valueClassName="text-purple-400"
            />
            <Statistic
              title={t('scanDetail.totalTokens')}
              value={scan.tokens_used || 0}
              valueClassName="text-success"
            />
          </div>
        </Card>
      )}

      {/* Vulnerability Distribution */}
      <Card className="glass-panel mb-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-cyan font-mono font-bold">{t('scanDetail.vulnDistribution')}</h3>
          {scan.findings_count && scan.findings_count > 0 && (
            <Button size="sm" onClick={() => navigate(`/scans/${scan.id}/findings`)}>
              {t('scanDetail.viewAllFindings')}
            </Button>
          )}
        </div>
        <div className="grid grid-cols-6 gap-4">
          <Statistic
            title={t('severity.critical')}
            value={scan.critical_count || 0}
            valueClassName={scan.critical_count ? 'text-critical' : ''}
          />
          <Statistic
            title={t('severity.high')}
            value={scan.high_count || 0}
            valueClassName={scan.high_count ? 'text-warning' : ''}
          />
          <Statistic
            title={t('severity.medium')}
            value={scan.medium_count || 0}
            valueClassName={scan.medium_count ? 'text-yellow-500' : ''}
          />
          <Statistic
            title={t('severity.low')}
            value={scan.low_count || 0}
            valueClassName={scan.low_count ? 'text-success' : ''}
          />
          <Statistic
            title={t('severity.info')}
            value={scan.info_count || 0}
            valueClassName={scan.info_count ? 'text-text-secondary' : ''}
          />
          <Statistic
            title={t('scanDetail.verified')}
            value={scan.verified_count || 0}
            valueClassName={scan.verified_count ? 'text-purple-400' : ''}
          />
        </div>
      </Card>

      {/* Real-time Progress */}
      {progress && (
        <Card className="glass-panel mb-6">
          <h3 className="text-cyan font-mono font-bold mb-4">{t('scanDetail.realtimeProgress')}</h3>
          <ScanProgress progress={progress} />
        </Card>
      )}

      {/* Events Log */}
      <Card className="glass-panel">
        <div className="flex items-center gap-2 mb-4">
          <MessageSquare className="h-5 w-5 text-cyan" />
          <h3 className="text-cyan font-mono font-bold">{t('scanDetail.eventLog')}</h3>
        </div>
        <div className="space-y-2 font-mono text-sm max-h-96 overflow-y-auto">
          {eventsLoading ? (
            <div className="text-center text-text-secondary py-8">
              <Loader2 className="h-5 w-5 animate-spin mx-auto mb-2" />
              {t('scanDetail.loadingEvents')}
            </div>
          ) : events.length === 0 ? (
            <div className="text-center text-text-tertiary py-8">{t('scanDetail.noEvents')}</div>
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
                  {getEventTypeName(event.event_type, t)}
                </Badge>
                <div className="flex-1 min-w-0">
                  <div className="text-text-primary">{formatEventMessage(event, t)}</div>
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
