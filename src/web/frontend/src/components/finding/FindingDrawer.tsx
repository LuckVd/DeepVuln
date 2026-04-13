import { useMemo, useEffect } from 'react';
import { Badge, Button, Alert, Tabs, Descriptions, Sheet, Progress } from '@/components/ui';
import {
  Check,
  X,
  HelpCircle,
  Copy,
  CheckCircle,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { translateDescription, translateRemediation, getVulnTypeName } from '@/utils/ruleTranslations';
import { formatDateTime, setTimezone } from '@/utils/format';
import { systemSettingsApi } from '@/api/system';
import type { Finding, FindingStatus } from '@/types/models';
import CodeHighlight from './CodeHighlight';

interface FindingDrawerProps {
  finding: Finding | null;
  open: boolean;
  onClose: () => void;
  onStatusChange?: (findingId: number, status: FindingStatus) => void;
  isUpdating?: boolean;
}

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

  // Infer language from file path
  const fileExt = finding.file_path.split('.').pop()?.toLowerCase() || '';
  const languageMap: Record<string, string> = {
    py: 'python',
    js: 'javascript',
    ts: 'typescript',
    jsx: 'jsx',
    tsx: 'tsx',
    java: 'java',
    go: 'go',
    c: 'c',
    cpp: 'cpp',
    cs: 'csharp',
    php: 'php',
    rb: 'ruby',
    rs: 'rust',
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
      width={720}
    >
      {/* Status Actions */}
      <div className="mb-6">
        <div className="text-text-secondary font-mono text-sm mb-3">{t('findings.markAs')}</div>
        <div className="flex gap-3">
          <Button
            size="sm"
            variant={finding.status === 'confirmed' ? 'success' : 'outline'}
            onClick={() => handleStatusChange('confirmed')}
            disabled={isUpdating}
          >
            <Check className="mr-2 h-4 w-4" />
            {t('findings.confirmed')}
          </Button>
          <Button
            size="sm"
            variant={finding.status === 'false_positive' ? 'destructive' : 'outline'}
            onClick={() => handleStatusChange('false_positive')}
            disabled={isUpdating}
          >
            <X className="mr-2 h-4 w-4" />
            {t('findings.falsePositive')}
          </Button>
          <Button
            size="sm"
            variant={finding.status === 'conditional' ? 'secondary' : 'outline'}
            onClick={() => handleStatusChange('conditional')}
            disabled={isUpdating}
          >
            <HelpCircle className="mr-2 h-4 w-4" />
            {t('findings.conditional')}
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
                {/* Basic Info */}
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
                      value: finding.line_start && finding.line_end
                        ? `${finding.line_start} - ${finding.line_end}`
                        : finding.line_start || '-',
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
                    <Copy className="mr-2 h-4 w-4" />
                    {t('findings.copy')}
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
              <Alert variant="warning" title={t('findings.noCodeEvidence')}>
                {t('findings.noCodeEvidenceDesc')}
              </Alert>
            ),
          },
          {
            key: 'metadata',
            label: t('findings.metadata'),
            children: (
              <Descriptions
                items={[
                  { label: t('findings.findingId'), value: String(finding.id), span: 1 },
                  { label: t('findings.scanId'), value: String(finding.scan_id), span: 1 },
                  {
                    label: t('findings.createdAt'),
                    value: formatDateTime(finding.created_at),
                    span: 2,
                  },
                  ...(finding.cpg_path
                    ? [
                        {
                          label: t('findings.cpgPath'),
                          value: (
                            <pre className="text-xs font-mono bg-background-tertiary p-2 rounded overflow-x-auto">
                              {JSON.stringify(finding.cpg_path, null, 2)}
                            </pre>
                          ),
                          span: 2,
                        },
                      ]
                    : []),
                ]}
                columns={2}
                bordered
              />
            ),
          },
        ]}
      />
    </Sheet>
  );
}
