/**
 * @deprecated ScanProgress component is not currently used in any page.
 * ScanDetail.tsx renders progress inline instead. This component is kept
 * for potential reuse if a dedicated progress view is needed later.
 */
import React, { useMemo, useState } from 'react';
import { Card, Badge, Progress, Statistic, Timeline, Collapsible, CollapsibleTrigger, CollapsibleContent, Button } from '@/components/ui';
import { Check, Loader2, Clock, X, Pause, ChevronDown, ChevronRight } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import type { ScanProgressResponse, PhaseInfo } from '@/types/models';
import { cn } from '@/shared/utils/cn';

interface ScanProgressProps {
  progress: ScanProgressResponse | null;
  loading?: boolean;
}

// Engine Card Component
interface EngineCardProps {
  name: string;
  status: 'completed' | 'running' | 'pending' | 'failed';
  phase: PhaseInfo | null;
}

function EngineCard({ name, status, phase }: EngineCardProps) {
  const [isOpen, setIsOpen] = useState(false);
  const { t } = useLanguage();

  const statusVariant: Record<string, 'completed' | 'running' | 'pending' | 'failed'> = {
    completed: 'completed',
    running: 'running',
    pending: 'pending',
    failed: 'failed',
  };

  const statusConfig = {
    completed: { icon: <Check className="h-3 w-3" />, text: t('status.completed') },
    running: { icon: <Loader2 className="h-3 w-3 animate-spin" />, text: t('status.running') },
    pending: { icon: <Clock className="h-3 w-3" />, text: t('status.waiting') },
    failed: { icon: <X className="h-3 w-3" />, text: t('status.failed') },
  };

  const config = statusConfig[status];

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <div className="border border-border rounded-md overflow-hidden">
        <CollapsibleTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className="w-full flex items-center justify-between px-3 py-2 h-auto hover:bg-cyan/5"
          >
            <div className="flex items-center gap-2 flex-1">
              <span className="text-text-primary font-medium">{name.toUpperCase()}</span>
              <Badge variant={statusVariant[status]} className="min-w-[70px] justify-center text-xs">
                {config.icon}
                <span className="ml-1">{config.text}</span>
              </Badge>
              {status === 'running' && phase && (
                <span className="text-xs text-text-tertiary">{phase.progress_percent}%</span>
              )}
            </div>
            {isOpen ? <ChevronDown className="h-4 w-4 text-text-secondary" /> : <ChevronRight className="h-4 w-4 text-text-secondary" />}
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="px-3 py-2 bg-background-secondary border-t border-border">
            {phase ? (
              <div className="grid grid-cols-3 gap-3 text-xs">
                {/* Duration */}
                <div>
                  <div className="text-text-tertiary font-mono">{t('scanProgress.duration')}</div>
                  <div className="text-cyan font-mono">
                    {phase.duration_seconds ? `${phase.duration_seconds.toFixed(1)}s` : '--'}
                  </div>
                </div>
                {/* Findings */}
                <div>
                  <div className="text-text-tertiary font-mono">{t('scanProgress.findings')}</div>
                  <div className={phase.findings > 0 ? "text-critical font-mono" : "text-text-secondary font-mono"}>
                    {phase.findings || 0}
                  </div>
                </div>
                {/* Tokens */}
                <div>
                  <div className="text-text-tertiary font-mono">{t('scanProgress.tokens')}</div>
                  <div className={phase.tokens_used > 0 ? "text-warning font-mono" : "text-text-secondary font-mono"}>
                    {phase.tokens_used || 0}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-text-tertiary text-xs">{t('scanProgress.noDetails')}</div>
            )}
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  );
}

export function ScanProgress({ progress, loading }: ScanProgressProps) {
  const { t } = useLanguage();

  // Dynamic phase labels with translations
  const PHASE_LABELS = useMemo<Record<string, string>>(() => ({
    'l1_preparation': t('phase.l1_preparation'),
    'source_preparation': t('phase.source_preparation'),
    'engine_selection': t('phase.engine_selection'),
    'engine_execution': t('phase.engine_execution'),
    'l1_attack_surface': 'L1 ATTACK SURFACE', // Fallback for unmapped phase
    'L2_semgrep': 'L2 SEMGREP', // Fallback for unmapped phase
    'L2_codeql': 'L2 CODEQL', // Fallback for unmapped phase
    'L3_agent': 'L3 AGENT AUDIT', // Fallback for unmapped phase
    'L3_adjudication': 'L3 ADJUDICATION', // Fallback for unmapped phase
    'result_merging': t('phase.result_merging'),
    'token_statistics': t('phase.token_statistics'),
    'exploitability_verification': t('phase.exploitability_verification'),
    'deduplication_adjudication': t('phase.deduplication_adjudication'),
    'adversarial_verification': t('phase.adversarial_verification'),
  }), [t]);

  const STATUS_ICONS: Record<string, React.ReactNode> = {
    completed: <Check className="h-4 w-4" />,
    running: <Loader2 className="h-4 w-4 animate-spin" />,
    pending: <Clock className="h-4 w-4" />,
    failed: <X className="h-4 w-4" />,
    skipped: <Pause className="h-4 w-4" />,
  };

  if (loading || !progress) {
    return (
      <Card className="glass-panel">
        <div className="text-center text-text-secondary font-mono py-8">
          <span className="inline-flex items-center gap-2">
            <Loader2 className="h-5 w-5 animate-spin text-cyan" />
            {t('common.waiting')}
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
          <h3 className="text-cyan font-mono font-bold">{t('scanProgress.scanStatus')}</h3>
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
                  {PHASE_LABELS[phase.name] || phase.name.toUpperCase()}
                </span>
                <Badge variant={getStatusBadge(phase.status)} className="min-w-[80px] justify-center">
                  {t(`status.${phase.status}`)}
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

      {/* Engine Status - Expanded with Details */}
      <Card className="glass-panel">
        <h3 className="text-cyan font-mono font-bold mb-4">{t('scanProgress.engineStatus')}</h3>
        <div className="space-y-2 font-mono text-sm">
          {/* Completed Engines with Details */}
          {progress.engines.completed && progress.engines.completed.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs text-text-secondary">{t('scanProgress.completed')}</div>
              {progress.engines.completed.map((engineName) => {
                const phase = progress.phases.find(p =>
                  p.name.toLowerCase().includes(engineName.toLowerCase()) ||
                  engineName.toLowerCase().includes('semgrep') && p.name.includes('semgrep') ||
                  engineName.toLowerCase().includes('codeql') && p.name.includes('codeql') ||
                  engineName.toLowerCase().includes('agent') && p.name.includes('agent')
                );
                return (
                  <EngineCard
                    key={engineName}
                    name={engineName}
                    status="completed"
                    phase={phase || null}
                  />
                );
              })}
            </div>
          )}

          {/* Running Engine */}
          {progress.engines.running && progress.engines.running.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs text-text-secondary">{t('scanProgress.running')}</div>
              {progress.engines.running.map((engineName) => {
                const phase = progress.phases.find(p => p.status === 'running');
                return (
                  <EngineCard
                    key={engineName}
                    name={engineName}
                    status="running"
                    phase={phase || null}
                  />
                );
              })}
            </div>
          )}

          {/* Pending Engines */}
          {progress.engines.pending && progress.engines.pending.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs text-text-secondary">{t('scanProgress.pending')}</div>
              {progress.engines.pending.map((engineName) => (
                <EngineCard
                  key={engineName}
                  name={engineName}
                  status="pending"
                  phase={null}
                />
              ))}
            </div>
          )}

          {/* No engines */}
          {(!progress.engines.completed || progress.engines.completed.length === 0) &&
           !progress.engines.running &&
           (!progress.engines.pending || progress.engines.pending.length === 0) && (
            <div className="text-text-tertiary text-center py-4">--</div>
          )}
        </div>
      </Card>
    </div>
  );
}

export default ScanProgress;
