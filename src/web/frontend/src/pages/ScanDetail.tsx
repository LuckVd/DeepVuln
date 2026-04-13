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
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from '@/components/ui';
import {
  ArrowLeft,
  Play,
  Pause,
  Square,
  Check,
  Loader2,
  Clock,
  X,
  ChevronDown,
  Settings,
  Folder,
  GitBranch,
  Cpu,
  Archive,
} from 'lucide-react';
import { useScan, useScanFindings } from '@/hooks/useApi';
import { useScanProgress } from '@/hooks/useScanProgress';
import { useLanguage } from '@/contexts/LanguageContext';
import { LiveTerminal } from '@/components/scan';
import { scansApi } from '@/api/scans';
import { systemSettingsApi } from '@/api/system';
import { formatDateTime, formatDuration, setTimezone } from '@/utils/format';
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
    l1_attack_surface: 'phase.l1_attack_surface',
    L2_semgrep: 'phase.L2_semgrep',
    L2_codeql: 'phase.L2_codeql',
    L3_agent: 'phase.L3_agent',
    L3_adjudication: 'phase.L3_adjudication',
    result_merging: 'phase.result_merging',
    token_statistics: 'phase.token_statistics',
    exploitability_verification: 'phase.exploitability_verification',
    deduplication_adjudication: 'phase.deduplication_adjudication',
    adversarial_verification: 'phase.adversarial_verification',
  };
  const key = phaseMap[phase];
  return key ? t(key) : phase;
};

const getShortPhaseName = (phase: string): string => {
  const shortMap: Record<string, string> = {
    l1_preparation: 'L1准备',
    source_preparation: '源码准备',
    engine_selection: '引擎选择',
    engine_execution: '引擎执行',
    l1_attack_surface: '攻击面',
    L1_preparation: 'L1准备',
    L1_attack_surface: 'L1攻击面',
    L2_semgrep: 'Semgrep',
    L2_codeql: 'CodeQL',
    L3_agent: 'Agent审计',
    L3_adjudication: '裁决',
    result_merging: '结果合并',
    token_statistics: 'Token统计',
    exploitability_verification: '可利用性验证',
    deduplication_adjudication: '去重裁决',
    adversarial_verification: '对抗性验证',
    report_generation: '报告生成',
  };
  return shortMap[phase] || phase.replace(/_/g, ' ');
};

const formatPhaseDuration = (seconds: number | null | undefined): string => {
  if (seconds === null || seconds === undefined) return '';
  if (seconds <= 0) return '0秒';
  return formatDuration(seconds);
};

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { t } = useLanguage();
  const scanId = parseInt(id || '0');
  const STATUS_MAP = getStatusMap(t);

  const { data: scan, isLoading, error, refetch } = useScan(scanId);

  // 加载系统时区设置
  useEffect(() => {
    const loadTimezone = async () => {
      try {
        const response = await systemSettingsApi.get();
        const tz = response.categories?.general?.['general.timezone'];
        if (tz && typeof tz === 'string') {
          setTimezone(tz);
        }
      } catch (error) {
        console.error('Failed to load timezone setting:', error);
      }
    };
    loadTimezone();
  }, []);

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

  // LLM configs from settings
  const [llmConfigs, setLlmConfigs] = useState<{ agent_scan?: any; verification?: any }>({});

  // Load LLM configs from settings
  useEffect(() => {
    const loadLlmConfigs = async () => {
      try {
        const { llmConfigApi } = await import('@/api');
        const response = await llmConfigApi.list();
        const configs: Record<string, any> = {};
        for (const config of response.items) {
          if (config.is_default) {
            configs[config.config_type] = config;
          }
        }
        setLlmConfigs(configs);
      } catch (err) {
        console.error('Failed to load LLM configs:', err);
      }
    };
    loadLlmConfigs();
  }, []);

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
      await refetch();
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

      {/* Status Card - Merged with all information */}
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

        {/* Time Info */}
        <div className="flex items-center gap-6 mb-4 text-sm">
          <span className="text-text-secondary font-mono">
            {t('scanDetail.created')}: {formatDateTime(scan.created_at)}
          </span>
          {(scan.completed_at || scan.started_at) && (
            <span className="text-text-secondary font-mono">
              │ {t('scanDetail.duration')}:{' '}
              {(() => {
                const start = scan.started_at ? new Date(scan.started_at).getTime() : null;
                const end = scan.completed_at ? new Date(scan.completed_at).getTime() : new Date().getTime();
                if (!start) return '--';
                return formatDuration((end - start) / 1000);
              })()}
            </span>
          )}
        </div>

        {/* Phase Progress Bar */}
        {progress?.phases && progress.phases.length > 0 && (
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2 text-xs font-mono">
              <span className="text-text-secondary">扫描进度</span>
              <span className="text-cyan">{progress.progress_percent}%</span>
            </div>

            {/* Progress Line */}
            <Progress
              value={progress.progress_percent}
              variant={currentStatus === 'running' ? 'cyan' : currentStatus === 'completed' ? 'green' : 'default'}
              className="h-2 mb-3"
            />

            {/* Phase List - Single Row */}
            <div className="flex items-center gap-4 text-xs font-mono">
              {progress.phases.map((phase) => {
                const isCompleted = phase.status === 'completed';
                const isRunning = phase.status === 'running';
                const hasProgress = phase.progress_percent > 0;
                const hasDuration = phase.duration_seconds != null;

                return (
                  <div key={phase.name} className="flex items-center gap-1">
                    <span className={isRunning ? 'text-cyan' : isCompleted ? 'text-success' : 'text-text-tertiary'}>
                      {isCompleted && <Check className="h-3 w-3 inline mr-1" />}
                      {isRunning && <Loader2 className="h-3 w-3 inline mr-1 animate-spin" />}
                      {!isCompleted && !isRunning && <Clock className="h-3 w-3 inline mr-1" />}
                      {getShortPhaseName(phase.name)}
                      {hasDuration && (
                        <span className="text-text-tertiary">({formatPhaseDuration(phase.duration_seconds)})</span>
                      )}
                      {isRunning && hasProgress && (
                        <span className="text-cyan">({phase.progress_percent}%)</span>
                      )}
                    </span>
                    <span className="text-text-tertiary">│</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Current Status */}
        {(progress?.current_phase || scan.current_phase) && currentStatus === 'running' && (
          <div className="text-text-secondary font-mono text-sm flex items-center gap-2">
            <Loader2 className="h-4 w-4 animate-spin text-cyan" />
            <span>{getPhaseName(progress?.current_phase || scan.current_phase || '', t)}</span>
            {(progress?.current_step || scan.current_step) && (
              <span className="text-text-tertiary">// {progress?.current_step || scan.current_step}</span>
            )}
          </div>
        )}
        {(progress?.current_phase || scan.current_phase) && currentStatus === 'completed' && (
          <div className="text-text-secondary font-mono text-sm flex items-center gap-2">
            <Check className="h-4 w-4 text-success" />
            <span>{getPhaseName(progress?.current_phase || scan.current_phase || '', t)}</span>
          </div>
        )}

        {/* Scan Details Grid */}
        <div className="grid grid-cols-4 gap-4 mt-4 pt-4 border-t border-border">
          {/* Scan Name */}
          <div className="col-span-2">
            <div className="text-xs text-text-secondary font-mono mb-1">扫描对象</div>
            <span className="text-text-primary font-mono text-sm">{scan.name}</span>
          </div>

          {/* Engines */}
          <div className="col-span-2">
            <div className="text-xs text-text-secondary font-mono mb-1">引擎</div>
            <div className="flex flex-wrap gap-1">
              {(scan.config?.engines && scan.config.engines.length > 0)
                ? scan.config.engines.map((engine: string) => (
                    <Badge key={engine} variant="info" className="font-mono text-xs py-0">
                      {engine.toUpperCase()}
                    </Badge>
                  ))
                : <span className="text-text-tertiary text-sm">--</span>}
            </div>
          </div>

          {/* Agent Model */}
          <div>
            <div className="text-xs text-text-secondary font-mono mb-1">Agent 模型</div>
            <span className="text-cyan font-mono text-sm">
              {llmConfigs.agent_scan?.model || '--'}
            </span>
          </div>

          {/* Verification Model */}
          <div>
            <div className="text-xs text-text-secondary font-mono mb-1">验证模型</div>
            <span className="text-warning font-mono text-sm">
              {llmConfigs.verification?.model || '--'}
            </span>
          </div>
        </div>
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
      {(scan.tokens_used != null || scan.token_usage != null) && (
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

      {/* Live Terminal */}
      <LiveTerminal
        scanId={scanId}
        scanStatus={currentStatus}
        wsState={wsState}
      />

    </div>
  );
}
