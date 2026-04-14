import { useMemo, useEffect, useState } from 'react';
import { Badge, Button, Alert, Tabs, Descriptions, Sheet, Progress } from '@/components/ui';
import {
  Check,
  X,
  HelpCircle,
  Copy,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  Swords,
  Scale,
  ChevronDown,
  ChevronRight,
  Zap,
  Link2,
  Loader2,
  ExternalLink,
  Flame,
} from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { translateDescription, translateRemediation, getVulnTypeName } from '@/utils/ruleTranslations';
import { formatDateTime, setTimezone } from '@/utils/format';
import { systemSettingsApi } from '@/api/system';
import { scansApi } from '@/api/scans';
import type {
  Finding,
  FindingStatus,
  AdversarialDebate,
  AdversarialRound,
  CpgPath,
  FindingExtraMetadata,
  AdversarialVerdictData,
} from '@/types/models';
import CodeHighlight from './CodeHighlight';

interface FindingDrawerProps {
  finding: Finding | null;
  open: boolean;
  onClose: () => void;
  onStatusChange?: (findingId: number, status: FindingStatus) => void;
  isUpdating?: boolean;
}

// Verdict display config
const VERDICT_STYLES: Record<string, { color: string; bg: string; icon: React.ReactNode }> = {
  confirmed: { color: 'text-critical', bg: 'bg-critical/10', icon: <AlertTriangle className="h-4 w-4" /> },
  false_positive: { color: 'text-success', bg: 'bg-success/10', icon: <CheckCircle className="h-4 w-4" /> },
  conditional: { color: 'text-warning', bg: 'bg-warning/10', icon: <HelpCircle className="h-4 w-4" /> },
  needs_review: { color: 'text-cyan', bg: 'bg-cyan/10', icon: <Scale className="h-4 w-4" /> },
};

const STRENGTH_COLORS: Record<string, string> = {
  weak: 'text-text-tertiary',
  moderate: 'text-warning',
  strong: 'text-cyan',
  definitive: 'text-success',
};

const ACTION_LABELS: Record<string, string> = {
  fix: 'fix',
  review: 'review',
  ignore: 'ignore',
  monitor: 'monitor',
};

/**
 * Finding details drawer component with cyberpunk theme
 */
export default function FindingDrawer({
  finding,
  open,
  onClose,
  onStatusChange,
  isUpdating = false,
}: FindingDrawerProps) {
  const { t } = useLanguage();
  const [debateData, setDebateData] = useState<AdversarialDebate | null>(null);
  const [debateLoading, setDebateLoading] = useState(false);
  const [debateError, setDebateError] = useState(false);
  const [expandedRounds, setExpandedRounds] = useState<Record<number, boolean>>({ 1: true });

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

  // Load adversarial debate data when finding changes
  useEffect(() => {
    if (!finding || !open) {
      setDebateData(null);
      setDebateError(false);
      return;
    }
    // Use adversarial_verification from extra_metadata if available
    const advData = finding.extra_metadata?.adversarial_verification;
    if (advData) {
      setDebateData({
        finding_id: finding.id,
        finding_title: finding.title,
        vuln_type: finding.vuln_type,
        status: advData.status,
        confidence: advData.confidence,
        rounds_count: advData.rounds_count ?? (advData.rounds?.length ?? 0),
        rounds: advData.rounds ?? [],
        verdict: advData.verdict,
        reasoning: advData.reasoning,
        timeout: advData.timeout,
      });
      setDebateError(false);
      return;
    }
    // Otherwise fetch from API
    let cancelled = false;
    setDebateLoading(true);
    setDebateError(false);
    scansApi
      .getAdversarialDebate(finding.scan_id, finding.id)
      .then((res) => {
        if (cancelled) return;
        const debate = res.debates.find((d) => d.finding_id === finding.id);
        setDebateData(debate || null);
      })
      .catch(() => {
        if (!cancelled) setDebateError(true);
      })
      .finally(() => {
        if (!cancelled) setDebateLoading(false);
      });
    return () => { cancelled = true; };
  }, [finding, open]);

  // Dynamic status and severity maps with translations
  const STATUS_MAP = useMemo<Record<FindingStatus, { text: string; variant: 'pending' | 'completed' | 'failed' | 'medium'; icon: React.ReactNode }>>(() => ({
    pending: { text: t('status.waiting'), variant: 'pending', icon: <HelpCircle className="h-4 w-4" /> },
    confirmed: { text: t('findings.confirmed'), variant: 'completed', icon: <CheckCircle className="h-4 w-4" /> },
    false_positive: { text: t('findings.falsePositive'), variant: 'failed', icon: <XCircle className="h-4 w-4" /> },
    conditional: { text: t('findings.conditional'), variant: 'medium', icon: <AlertTriangle className="h-4 w-4" /> },
  }), [t]);

  const SEVERITY_MAP = useMemo<Record<string, { text: string; variant: 'critical' | 'high' | 'medium' | 'low' | 'info' }>>(() => ({
    critical: { text: t('severity.critical'), variant: 'critical' },
    high: { text: t('severity.high'), variant: 'high' },
    medium: { text: t('severity.medium'), variant: 'medium' },
    low: { text: t('severity.low'), variant: 'low' },
    info: { text: t('severity.info'), variant: 'info' },
  }), [t]);

  if (!finding) return null;

  const statusConfig = STATUS_MAP[finding.status] || STATUS_MAP.pending;
  const severityConfig = SEVERITY_MAP[finding.severity] || { text: finding.severity, variant: 'info' as const };
  const meta = finding.extra_metadata;
  const metaStr = (key: string): string | undefined => {
    const v = meta?.[key];
    return typeof v === 'string' ? v : undefined;
  };
  const metaBool = (key: string): boolean | undefined => {
    const v = meta?.[key];
    return typeof v === 'boolean' ? v : undefined;
  };

  // Infer language from file path
  const fileExt = finding.file_path.split('.').pop()?.toLowerCase() || '';
  const languageMap: Record<string, string> = {
    py: 'python', js: 'javascript', ts: 'typescript', jsx: 'jsx', tsx: 'tsx',
    java: 'java', go: 'go', c: 'c', cpp: 'cpp', cs: 'csharp',
    php: 'php', rb: 'ruby', rs: 'rust',
  };

  const handleStatusChange = (newStatus: FindingStatus) => {
    if (onStatusChange && !isUpdating) {
      onStatusChange(finding.id, newStatus);
    }
  };

  const copyEvidence = () => {
    if (finding.evidence) {
      navigator.clipboard.writeText(finding.evidence);
    }
  };

  const toggleRound = (n: number) => {
    setExpandedRounds((prev) => ({ ...prev, [n]: !prev[n] }));
  };

  // Parse cpg_path (may be string or object)
  const cpgPath: CpgPath | null = typeof finding.cpg_path === 'string'
    ? (() => { try { return JSON.parse(finding.cpg_path) } catch { return null } })()
    : finding.cpg_path;

  const hasExploitChain = cpgPath && (cpgPath.source || cpgPath.sink || cpgPath.propagation);
  const hasDebate = debateData && debateData.rounds && debateData.rounds.length > 0;

  return (
    <Sheet
      open={open}
      onClose={onClose}
      title={
        <div className="flex items-center gap-3">
          <span className="text-cyan font-mono">VULN #{String(finding.id).padStart(4, '0')}</span>
          <Badge variant={severityConfig.variant}>{severityConfig.text}</Badge>
          <Badge variant={statusConfig.variant} className="flex items-center gap-2">
            {statusConfig.icon}
            {statusConfig.text}
          </Badge>
        </div>
      }
      width={780}
    >
      {/* Status Actions */}
      <div className="mb-6">
        <div className="text-text-secondary font-mono text-sm mb-3">{t('findings.markAs')}</div>
        <div className="flex gap-3">
          <Button size="sm" variant={finding.status === 'confirmed' ? 'success' : 'outline'} onClick={() => handleStatusChange('confirmed')} disabled={isUpdating}>
            <Check className="mr-2 h-4 w-4" />{t('findings.confirmed')}
          </Button>
          <Button size="sm" variant={finding.status === 'false_positive' ? 'destructive' : 'outline'} onClick={() => handleStatusChange('false_positive')} disabled={isUpdating}>
            <X className="mr-2 h-4 w-4" />{t('findings.falsePositive')}
          </Button>
          <Button size="sm" variant={finding.status === 'conditional' ? 'secondary' : 'outline'} onClick={() => handleStatusChange('conditional')} disabled={isUpdating}>
            <HelpCircle className="mr-2 h-4 w-4" />{t('findings.conditional')}
          </Button>
        </div>
      </div>

      <Tabs
        defaultActiveKey="overview"
        items={[
          {
            key: 'overview',
            label: t('findings.overview'),
            children: (
              <>
                <Descriptions
                  items={[
                    {
                      label: t('findings.vulnType'),
                      value: <span className="text-cyan font-mono">{getVulnTypeName(finding.vuln_type)}</span>,
                      span: 2,
                    },
                    {
                      label: t('severity.severity').toUpperCase(),
                      value: (
                        <div className="flex items-center gap-3">
                          <Badge variant={severityConfig.variant}>{severityConfig.text}</Badge>
                          <span className="text-text-secondary">
                            {t('findings.confidence').toUpperCase()}: {(finding.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                      ),
                      span: 2,
                    },
                    {
                      label: t('findings.fileLocation'),
                      value: <code className="text-cyan font-mono text-sm bg-background-tertiary px-2 py-1 rounded">{finding.file_path}</code>,
                      span: 2,
                    },
                    {
                      label: t('findings.lineNumbers'),
                      value: finding.line_start && finding.line_end ? `${finding.line_start} - ${finding.line_end}` : finding.line_start || '-',
                      span: 2,
                    },
                    {
                      label: t('table.function'),
                      value: finding.function_name || '-',
                      span: 2,
                    },
                    {
                      label: t('findings.detectionEngine'),
                      value: finding.engine,
                      span: 2,
                    },
                    ...(meta?.rule_id ? [{ label: t('findings.ruleId'), value: <code className="text-cyan font-mono text-xs">{meta.rule_id}</code>, span: 2 }] : []),
                    ...(meta?.evidence_strength ? [{ label: t('findings.evidenceStrength'), value: <Badge variant="medium">{meta.evidence_strength}</Badge>, span: 2 }] : []),
                  ]}
                  columns={2}
                  bordered
                />

                {/* Description */}
                {finding.description && (
                  <div className="mt-6">
                    <h4 className="text-cyan font-mono font-bold mb-3">{t('findings.description')}</h4>
                    <p className="text-text-secondary leading-relaxed">
                      {translateDescription(finding.vuln_type, finding.description)}
                    </p>
                  </div>
                )}

                {/* References */}
                {meta?.references && meta.references.length > 0 && (
                  <div className="mt-6">
                    <h4 className="text-cyan font-mono font-bold mb-3">{t('findings.references')}</h4>
                    <div className="space-y-1">
                      {meta.references.map((ref, i) => (
                        <div key={i} className="flex items-center gap-2 text-sm">
                          <Link2 className="h-3 w-3 text-cyan flex-shrink-0" />
                          {ref.startsWith('http') ? (
                            <a href={ref} target="_blank" rel="noopener noreferrer" className="text-cyan hover:underline truncate">
                              {ref}
                            </a>
                          ) : (
                            <span className="text-text-secondary">{ref}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Tags */}
                {meta?.tags && meta.tags.length > 0 && (
                  <div className="mt-4 flex flex-wrap gap-2">
                    {meta.tags.map((tag, i) => (
                      <span key={i} className="text-xs font-mono px-2 py-1 rounded bg-cyan/10 text-cyan">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}

                {/* Fix Suggestion */}
                {meta?.fix_suggestion && (
                  <div className="mt-6">
                    <h4 className="text-cyan font-mono font-bold mb-3">{t('findings.fixSuggestion')}</h4>
                    <Alert variant="info">{meta.fix_suggestion}</Alert>
                  </div>
                )}

                {/* Remediation */}
                {(finding.remediation || translateRemediation(finding.vuln_type, null)) && (
                  <div className="mt-6">
                    <h4 className="text-cyan font-mono font-bold mb-3">{t('findings.remediation')}</h4>
                    <Alert variant="info" title={t('findings.recommendedActions')}>
                      {translateRemediation(finding.vuln_type, finding.remediation) || finding.remediation}
                    </Alert>
                  </div>
                )}
              </>
            ),
          },
          {
            key: 'code',
            label: t('findings.codeEvidence'),
            children: finding.evidence ? (
              <>
                <div className="mb-4 flex items-center justify-between">
                  <span className="text-text-secondary font-mono text-sm">{t('findings.affectedCode')}</span>
                  <Button size="sm" variant="outline" onClick={copyEvidence}>
                    <Copy className="mr-2 h-4 w-4" />{t('findings.copy')}
                  </Button>
                </div>
                <CodeHighlight
                  code={finding.evidence}
                  language={languageMap[fileExt] || 'text'}
                  highlightLine={finding.line_start || undefined}
                  startLine={finding.line_start || 1}
                />
              </>
            ) : (
              <div className="space-y-4">
                {/* Show dataflow as fallback when no raw code evidence */}
                {metaStr('dataflow') && (
                  <div>
                    <h4 className="text-cyan font-mono font-bold mb-2">{t('findings.affectedCode')}</h4>
                    <div className="bg-background-secondary border border-border rounded-lg p-3">
                      <div className="flex items-start gap-2">
                        <Zap className="h-4 w-4 text-warning mt-0.5 flex-shrink-0" />
                        <div>
                          <div className="text-text-tertiary font-mono text-xs mb-1">DATA FLOW</div>
                          <p className="text-text-secondary text-sm leading-relaxed">
                            {metaStr('dataflow')}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                {/* Show description as context */}
                {finding.description && !metaStr('dataflow') && (
                  <div>
                    <h4 className="text-cyan font-mono font-bold mb-2">{t('findings.description')}</h4>
                    <p className="text-text-secondary text-sm leading-relaxed">
                      {finding.description}
                    </p>
                  </div>
                )}
                {/* Show attack surface info from metadata */}
                {metaStr('attack_surface') && (
                  <div className="flex items-center gap-2 text-sm">
                    <Flame className="h-4 w-4 text-critical flex-shrink-0" />
                    <span className="text-text-secondary font-mono">Attack Surface:</span>
                    <span className="text-text-primary">{metaStr('attack_surface')}</span>
                  </div>
                )}
                {/* Show exploitation conditions from metadata */}
                {metaStr('exploitation_conditions') && (
                  <div>
                    <div className="text-text-tertiary font-mono text-xs mb-1">{t('findings.exploitationSteps')}:</div>
                    <p className="text-text-secondary text-sm leading-relaxed">
                      {metaStr('exploitation_conditions')}
                    </p>
                  </div>
                )}
                {/* Show user controlled status */}
                {metaBool('user_controlled') !== undefined && (
                  <div className="flex items-center gap-2">
                    <span className="text-text-secondary font-mono text-sm">User Controlled:</span>
                    <Badge variant={metaBool('user_controlled') ? 'critical' : 'info'}>
                      {metaBool('user_controlled') ? 'YES' : 'NO'}
                    </Badge>
                  </div>
                )}
                {!metaStr('dataflow') && !finding.description && (
                  <Alert variant="warning" title={t('findings.noCodeEvidence')}>
                    {t('findings.noCodeEvidenceDesc')}
                  </Alert>
                )}
              </div>
            ),
          },
          {
            key: 'exploit',
            label: t('findings.exploitChain'),
            children: hasExploitChain ? (
              <div className="space-y-4">
                {/* Attack Vector & Exploitability badges */}
                {(cpgPath!.attack_vector || cpgPath!.exploitability) && (
                  <div className="flex flex-wrap gap-3">
                    {cpgPath!.attack_vector && (
                      <div className="flex items-center gap-2">
                        <Flame className="h-4 w-4 text-critical" />
                        <span className="text-text-secondary font-mono text-sm">{t('findings.attackVector')}:</span>
                        <Badge variant="critical">{cpgPath!.attack_vector}</Badge>
                      </div>
                    )}
                    {cpgPath!.exploitability && (
                      <div className="flex items-center gap-2">
                        <Zap className="h-4 w-4 text-warning" />
                        <span className="text-text-secondary font-mono text-sm">{t('findings.exploitability')}:</span>
                        <Badge variant="high">{cpgPath!.exploitability}</Badge>
                      </div>
                    )}
                  </div>
                )}

                {/* Attack Path Flow */}
                <div className="bg-background-secondary border border-border rounded-lg p-4 space-y-3">
                  {/* Source */}
                  {cpgPath!.source && (
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 rounded-full bg-critical/10 border-2 border-critical flex items-center justify-center flex-shrink-0">
                        <span className="text-critical font-mono text-xs font-bold">S</span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-critical font-mono text-sm font-bold mb-1">{t('findings.source')}</div>
                        <code className="text-text-primary font-mono text-xs bg-background-tertiary px-2 py-1 rounded">
                          {cpgPath!.source.file}:{cpgPath!.source.line}
                        </code>
                        {cpgPath!.source.description && (
                          <p className="text-text-secondary text-sm mt-1">{cpgPath!.source.description}</p>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Connector */}
                  {cpgPath!.source && (cpgPath!.propagation || cpgPath!.sink) && (
                    <div className="ml-4 w-0.5 h-4 bg-border" />
                  )}

                  {/* Propagation */}
                  {cpgPath!.propagation && cpgPath!.propagation.length > 0 && cpgPath!.propagation.map((step, i) => (
                    <div key={i}>
                      <div className="flex items-start gap-3">
                        <div className="w-8 h-8 rounded-full bg-warning/10 border-2 border-warning flex items-center justify-center flex-shrink-0">
                          <span className="text-warning font-mono text-xs font-bold">{i + 1}</span>
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="text-warning font-mono text-sm font-bold mb-1">
                            {t('findings.propagation')} #{i + 1}
                          </div>
                          <code className="text-text-primary font-mono text-xs bg-background-tertiary px-2 py-1 rounded">
                            {step.file}:{step.line}
                          </code>
                          {step.description && (
                            <p className="text-text-secondary text-sm mt-1">{step.description}</p>
                          )}
                        </div>
                      </div>
                      <div className="ml-4 w-0.5 h-4 bg-border" />
                    </div>
                  ))}

                  {/* Sink */}
                  {cpgPath!.sink && (
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 rounded-full bg-critical/10 border-2 border-critical flex items-center justify-center flex-shrink-0">
                        <span className="text-critical font-mono text-xs font-bold">E</span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-critical font-mono text-sm font-bold mb-1">{t('findings.sink')}</div>
                        <code className="text-text-primary font-mono text-xs bg-background-tertiary px-2 py-1 rounded">
                          {cpgPath!.sink.file}:{cpgPath!.sink.line}
                        </code>
                        {cpgPath!.sink.description && (
                          <p className="text-text-secondary text-sm mt-1">{cpgPath!.sink.description}</p>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <AttackPathFallback meta={meta} finding={finding} t={t} />
            ),
          },
          {
            key: 'debate',
            label: t('findings.adversarialDebate'),
            children: debateLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-6 w-6 text-cyan animate-spin mr-3" />
                <span className="text-text-secondary font-mono">{t('findings.debateLoading')}</span>
              </div>
            ) : debateError ? (
              <Alert variant="warning" title={t('findings.debateLoadError')}>
                {t('findings.noDebateDesc')}
              </Alert>
            ) : hasDebate ? (
              <div className="space-y-4">
                {/* Verdict Summary */}
                {debateData.verdict && <VerdictSummary verdict={debateData.verdict} t={t} />}

                {/* Debate Rounds */}
                {debateData.rounds.length > 0 && (
                  <div className="space-y-2">
                    {debateData.rounds.map((round) => (
                      <DebateRoundCard
                        key={round.round_number}
                        round={round}
                        expanded={expandedRounds[round.round_number] ?? false}
                        onToggle={() => toggleRound(round.round_number)}
                        t={t}
                      />
                    ))}
                  </div>
                )}

                {/* Timeout indicator */}
                {debateData.timeout && (
                  <Alert variant="warning" title={t('findings.roundTimeout')}>
                    <ClockIcon className="h-4 w-4 mr-2" />
                    {t('findings.roundTimeout')}
                  </Alert>
                )}
              </div>
            ) : debateData && !hasDebate ? (
              /* Verification exists but no full debate rounds */
              <div className="space-y-4">
                <div className="bg-background-secondary border border-border rounded-lg p-4">
                  <div className="flex items-center gap-3 mb-3">
                    <Scale className="h-5 w-5 text-cyan" />
                    <span className="font-mono font-bold text-text-primary">
                      {t('findings.adversarialDebate')} — {debateData.status?.toUpperCase() || 'UNKNOWN'}
                    </span>
                    {debateData.confidence !== undefined && (
                      <span className="text-text-tertiary font-mono text-sm">
                        ({(debateData.confidence * 100).toFixed(0)}% confidence)
                      </span>
                    )}
                  </div>
                  <p className="text-text-secondary text-sm">
                    {debateData.reasoning || 'Adversarial verification was performed but did not produce a full multi-round debate. The finding status is based on automated assessment.'}
                  </p>
                </div>
                {debateData.verdict && <VerdictSummary verdict={debateData.verdict} t={t} />}
              </div>
            ) : (
              <Alert variant="info" title={t('findings.noDebate')}>
                {t('findings.noDebateDesc')}
              </Alert>
            ),
          },
          {
            key: 'metadata',
            label: t('findings.metadata'),
            children: (
              <>
                <Descriptions
                  items={[
                    { label: t('findings.findingId'), value: String(finding.id), span: 1 },
                    { label: t('findings.scanId'), value: String(finding.scan_id), span: 1 },
                    { label: t('findings.createdAt'), value: formatDateTime(finding.created_at), span: 2 },
                    ...(meta?.rule_id ? [{ label: t('findings.ruleId'), value: <code className="text-cyan font-mono text-xs">{meta.rule_id}</code>, span: 2 }] : []),
                  ]}
                  columns={2}
                  bordered
                />

                {/* Score Detail */}
                {meta?.score_detail && (
                  <div className="mt-6">
                    <h4 className="text-cyan font-mono font-bold mb-3">{t('findings.scoreDetail')}</h4>
                    <div className="grid grid-cols-2 gap-3">
                      {meta.score_detail.base_score !== undefined && (
                        <ScoreCard label={t('findings.baseScore')} value={meta.score_detail.base_score} />
                      )}
                      {meta.score_detail.exploitability_score !== undefined && (
                        <ScoreCard label={t('findings.exploitScore')} value={meta.score_detail.exploitability_score} />
                      )}
                      {meta.score_detail.directory_multiplier !== undefined && (
                        <ScoreCard label={t('findings.dirMultiplier')} value={meta.score_detail.directory_multiplier} />
                      )}
                      {meta.score_detail.final_score !== undefined && (
                        <ScoreCard label={t('findings.finalScore')} value={meta.score_detail.final_score} highlight />
                      )}
                    </div>
                  </div>
                )}

                {/* Confidence Factors */}
                {meta?.confidence_factors && Object.keys(meta.confidence_factors).length > 0 && (
                  <div className="mt-6">
                    <h4 className="text-cyan font-mono font-bold mb-3">{t('findings.confidenceFactors')}</h4>
                    <div className="space-y-2">
                      {Object.entries(meta.confidence_factors).map(([key, val]) => (
                        <div key={key} className="flex items-center justify-between text-sm">
                          <span className="text-text-secondary font-mono">{key}</span>
                          <div className="flex items-center gap-2">
                            <Progress value={(val as number) * 100} variant="cyan" className="w-24 h-1.5" />
                            <span className="text-text-primary font-mono text-xs w-10 text-right">{((val as number) * 100).toFixed(0)}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* CPG Path Raw (fallback) */}
                {cpgPath && !hasExploitChain && (
                  <div className="mt-6">
                    <h4 className="text-cyan font-mono font-bold mb-3">{t('findings.cpgPath')}</h4>
                    <pre className="text-xs font-mono bg-background-tertiary p-3 rounded overflow-x-auto border border-border">
                      {JSON.stringify(cpgPath, null, 2)}
                    </pre>
                  </div>
                )}
              </>
            ),
          },
        ]}
      />
    </Sheet>
  );
}

// --- Sub-components ---

function ScoreCard({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div className={`rounded-lg border p-3 ${highlight ? 'border-cyan bg-cyan/5' : 'border-border bg-background-secondary'}`}>
      <div className="text-text-secondary font-mono text-xs mb-1">{label}</div>
      <div className={`font-mono text-lg font-bold ${highlight ? 'text-cyan' : 'text-text-primary'}`}>
        {(value * 100).toFixed(1)}
      </div>
    </div>
  );
}

function VerdictSummary({ verdict, t }: { verdict: AdversarialVerdictData; t: (key: string) => string }) {
  const style = VERDICT_STYLES[verdict.verdict || ''] || VERDICT_STYLES.needs_review;
  return (
    <div className={`rounded-lg border p-4 ${style.bg} border-current/20`}>
      <div className="flex items-center gap-3 mb-3">
        <div className={style.color}>{style.icon}</div>
        <span className={`font-mono font-bold text-sm ${style.color}`}>
          {t('findings.finalVerdict')}: {(verdict.verdict || 'unknown').toUpperCase()}
        </span>
        {verdict.confidence !== undefined && (
          <span className="text-text-secondary font-mono text-sm">
            ({(verdict.confidence * 100).toFixed(0)}%)
          </span>
        )}
      </div>
      {verdict.summary && <p className="text-text-secondary text-sm mb-3">{verdict.summary}</p>}
      <div className="flex flex-wrap gap-4 text-xs font-mono">
        {verdict.attacker_strength !== undefined && (
          <div className="flex items-center gap-1">
            <Swords className="h-3 w-3 text-critical" />
            <span className="text-text-secondary">{t('findings.attackerStrength')}:</span>
            <span className="text-text-primary">{(verdict.attacker_strength * 100).toFixed(0)}%</span>
          </div>
        )}
        {verdict.defender_strength !== undefined && (
          <div className="flex items-center gap-1">
            <Shield className="h-3 w-3 text-success" />
            <span className="text-text-secondary">{t('findings.defenderStrength')}:</span>
            <span className="text-text-primary">{(verdict.defender_strength * 100).toFixed(0)}%</span>
          </div>
        )}
        {verdict.recommended_action && (
          <div className="flex items-center gap-1">
            <span className="text-text-secondary">{t('findings.recommendedAction')}:</span>
            <Badge variant="medium">{ACTION_LABELS[verdict.recommended_action] || verdict.recommended_action}</Badge>
          </div>
        )}
      </div>
      {verdict.key_factors && verdict.key_factors.length > 0 && (
        <div className="mt-3">
          <div className="text-text-secondary font-mono text-xs mb-1">{t('findings.keyFactors')}:</div>
          <div className="flex flex-wrap gap-1">
            {verdict.key_factors.map((f, i) => (
              <span key={i} className="text-xs px-2 py-0.5 rounded bg-background-tertiary text-text-secondary">
                {f}
              </span>
            ))}
          </div>
        </div>
      )}
      {verdict.conditions && verdict.conditions.length > 0 && (
        <div className="mt-2">
          <div className="text-text-secondary font-mono text-xs mb-1">{t('findings.conditions')}:</div>
          <ul className="text-text-secondary text-sm list-disc list-inside">
            {verdict.conditions.map((c, i) => <li key={i}>{c}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

function DebateRoundCard({
  round,
  expanded,
  onToggle,
  t,
}: {
  round: AdversarialRound;
  expanded: boolean;
  onToggle: () => void;
  t: (key: string) => string;
}) {
  const arbiterVerdict = round.arbiter_verdict?.verdict;
  const arbiterStyle = VERDICT_STYLES[arbiterVerdict || ''] || VERDICT_STYLES.needs_review;

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      {/* Round Header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between px-4 py-3 bg-background-secondary hover:bg-background-tertiary transition-colors"
      >
        <div className="flex items-center gap-3">
          {expanded ? <ChevronDown className="h-4 w-4 text-cyan" /> : <ChevronRight className="h-4 w-4 text-text-tertiary" />}
          <span className="font-mono text-sm text-text-primary">
            {t('findings.debateRound').replace('{n}', String(round.round_number))}
          </span>
          {arbiterVerdict && (
            <span className={`text-xs font-mono px-2 py-0.5 rounded ${arbiterStyle.bg} ${arbiterStyle.color}`}>
              {arbiterVerdict.toUpperCase()}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-text-tertiary">
          <Swords className="h-3 w-3 text-critical" />
          <Shield className="h-3 w-3 text-success" />
        </div>
      </button>

      {/* Round Content */}
      {expanded && (
        <div className="p-4 space-y-4">
          {/* Attacker */}
          {round.attacker_argument && (
            <ArgumentCard
              role="attacker"
              data={round.attacker_argument}
              t={t}
            />
          )}
          {/* Defender */}
          {round.defender_argument && (
            <ArgumentCard
              role="defender"
              data={round.defender_argument}
              t={t}
            />
          )}
          {/* Arbiter */}
          {round.arbiter_verdict && (
            <div className="flex items-start gap-3 p-3 rounded bg-background-tertiary">
              <Scale className="h-4 w-4 text-cyan mt-0.5 flex-shrink-0" />
              <div className="flex-1">
                <div className="font-mono text-xs text-cyan mb-1">{t('findings.arbiter')}</div>
                {round.arbiter_verdict.reasoning && (
                  <p className="text-text-secondary text-sm">{round.arbiter_verdict.reasoning}</p>
                )}
                {round.arbiter_verdict.continue_reason && (
                  <p className="text-text-tertiary text-xs mt-1">{round.arbiter_verdict.continue_reason}</p>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ArgumentCard({
  role,
  data,
  t,
}: {
  role: 'attacker' | 'defender';
  data: NonNullable<AdversarialRound['attacker_argument']>;
  t: (key: string) => string;
}) {
  const isAttacker = role === 'attacker';
  const icon = isAttacker ? <Swords className="h-4 w-4" /> : <Shield className="h-4 w-4" />;
  const color = isAttacker ? 'text-critical' : 'text-success';
  const borderColor = isAttacker ? 'border-l-critical' : 'border-l-success';

  return (
    <div className={`border-l-2 ${borderColor} pl-4 space-y-2`}>
      <div className="flex items-center gap-2">
        <span className={color}>{icon}</span>
        <span className={`font-mono text-sm font-bold ${color}`}>
          {t(isAttacker ? 'findings.attacker' : 'findings.defender')}
        </span>
        {data.strength && (
          <span className={`text-xs font-mono ${STRENGTH_COLORS[data.strength] || 'text-text-tertiary'}`}>
            [{data.strength.toUpperCase()}]
          </span>
        )}
        {data.confidence !== undefined && (
          <span className="text-text-tertiary font-mono text-xs">
            {(data.confidence * 100).toFixed(0)}%
          </span>
        )}
      </div>

      {data.claim && <p className="text-text-primary text-sm">{data.claim}</p>}

      {data.evidence && data.evidence.length > 0 && (
        <div>
          <div className="text-text-tertiary font-mono text-xs mb-1">{t('findings.evidence')}:</div>
          <ul className="text-text-secondary text-sm list-disc list-inside space-y-0.5">
            {data.evidence.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </div>
      )}

      {data.reasoning && (
        <div>
          <div className="text-text-tertiary font-mono text-xs mb-1">{t('findings.reasoning')}:</div>
          <p className="text-text-secondary text-sm">{data.reasoning}</p>
        </div>
      )}

      {/* Attacker-specific: PoC and exploitation steps */}
      {isAttacker && (data as any).poc_code && (
        <div>
          <div className="text-text-tertiary font-mono text-xs mb-1">{t('findings.pocCode')}:</div>
          <pre className="text-xs font-mono bg-background-tertiary p-2 rounded overflow-x-auto border border-border">
            {(data as any).poc_code}
          </pre>
        </div>
      )}
      {isAttacker && (data as any).exploitation_steps && (data as any).exploitation_steps.length > 0 && (
        <div>
          <div className="text-text-tertiary font-mono text-xs mb-1">{t('findings.exploitationSteps')}:</div>
          <ol className="text-text-secondary text-sm list-decimal list-inside space-y-0.5">
            {(data as any).exploitation_steps.map((s: string, i: number) => <li key={i}>{s}</li>)}
          </ol>
        </div>
      )}

      {/* Defender-specific: sanitizers and false positive reasons */}
      {!isAttacker && (data as any).sanitizers_found && (data as any).sanitizers_found.length > 0 && (
        <div>
          <div className="text-text-tertiary font-mono text-xs mb-1">{t('findings.sanitizersFound')}:</div>
          <div className="flex flex-wrap gap-1">
            {(data as any).sanitizers_found.map((s: string, i: number) => (
              <span key={i} className="text-xs px-2 py-0.5 rounded bg-success/10 text-success">{s}</span>
            ))}
          </div>
        </div>
      )}
      {!isAttacker && (data as any).false_positive_reasons && (data as any).false_positive_reasons.length > 0 && (
        <div>
          <div className="text-text-tertiary font-mono text-xs mb-1">{t('findings.fpReasons')}:</div>
          <ul className="text-text-secondary text-sm list-disc list-inside">
            {(data as any).false_positive_reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

function ClockIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  );
}

function AttackPathFallback({
  meta,
  finding,
  t,
}: {
  meta: FindingExtraMetadata | null;
  finding: Finding;
  t: (key: string) => string;
}) {
  const dataflow = (meta?.dataflow as string) || undefined;
  const attackSurface = (meta?.attack_surface as string) || undefined;
  const exploitationConditions = (meta?.exploitation_conditions as string) || undefined;
  const userControlled = typeof meta?.user_controlled === 'boolean' ? meta.user_controlled : undefined;
  const hasAny = dataflow || attackSurface || exploitationConditions;

  if (!hasAny) {
    return (
      <Alert variant="warning" title={t('findings.noExploitChain')}>
        {t('findings.noExploitChainDesc')}
      </Alert>
    );
  }

  // Parse dataflow steps (separated by ->)
  const flowSteps = dataflow
    ? dataflow.split(/\s*->\s*/).map((s: string) => s.trim()).filter(Boolean)
    : [];

  return (
    <div className="space-y-4">
      {/* Attack Surface badge */}
      {attackSurface && (
        <div className="flex items-center gap-2">
          <Flame className="h-4 w-4 text-critical" />
          <span className="text-text-secondary font-mono text-sm">{t('findings.attackVector')}:</span>
          <Badge variant="critical">{attackSurface.toUpperCase()}</Badge>
          {userControlled !== undefined && (
            <Badge variant={userControlled ? 'critical' : 'info'}>
              USER CONTROLLED: {userControlled ? 'YES' : 'NO'}
            </Badge>
          )}
        </div>
      )}

      {/* Data Flow visual chain */}
      {flowSteps.length > 0 && (
        <div className="bg-background-secondary border border-border rounded-lg p-4">
          <div className="text-text-tertiary font-mono text-xs mb-3">DATA FLOW</div>
          <div className="space-y-2">
            {flowSteps.map((step: string, i: number) => (
              <div key={i} className="flex items-start gap-3">
                <div className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 border-2 text-xs font-bold font-mono
                  ${i === 0 ? 'bg-critical/10 border-critical text-critical' : i === flowSteps.length - 1 ? 'bg-critical/10 border-critical text-critical' : 'bg-warning/10 border-warning text-warning'}`}>
                  {i === 0 ? 'S' : i === flowSteps.length - 1 ? 'E' : i}
                </div>
                <div className="flex-1 min-w-0 pt-1">
                  <span className="text-text-primary text-sm font-mono">{step}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Exploitation Conditions / Steps */}
      {exploitationConditions && (
        <div>
          <h4 className="text-cyan font-mono font-bold mb-2">{t('findings.exploitationSteps')}</h4>
          <div className="bg-background-secondary border border-border rounded-lg p-3">
            <p className="text-text-secondary text-sm leading-relaxed">{exploitationConditions}</p>
          </div>
        </div>
      )}

      {/* Example PoC hint based on vuln type */}
      {userControlled && finding.vuln_type === 'command_injection' && (
        <div className="bg-critical/5 border border-critical/30 rounded-lg p-3">
          <div className="text-critical font-mono text-xs mb-1">EXAMPLE PAYLOAD</div>
          <code className="text-text-primary text-sm font-mono">
            /ping?ip=127.0.0.1;cat /etc/passwd
          </code>
          <div className="text-text-tertiary text-xs mt-1">
            /ping?ip=$(whoami)
          </div>
        </div>
      )}
    </div>
  );
}
