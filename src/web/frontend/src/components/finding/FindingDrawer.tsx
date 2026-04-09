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
import type { Finding, FindingStatus } from '@/types/models';
import CodeHighlight from './CodeHighlight';

interface FindingDrawerProps {
  finding: Finding | null;
  open: boolean;
  onClose: () => void;
  onStatusChange?: (findingId: number, status: FindingStatus) => void;
  isUpdating?: boolean;
}

const STATUS_MAP: Record<
  FindingStatus,
  { text: string; variant: 'pending' | 'completed' | 'failed' | 'medium'; icon: React.ReactNode }
> = {
  pending: { text: 'PENDING', variant: 'pending', icon: <HelpCircle className="h-4 w-4" /> },
  confirmed: { text: 'CONFIRMED', variant: 'completed', icon: <CheckCircle className="h-4 w-4" /> },
  false_positive: { text: 'FALSE POSITIVE', variant: 'failed', icon: <XCircle className="h-4 w-4" /> },
  conditional: { text: 'CONDITIONAL', variant: 'medium', icon: <AlertTriangle className="h-4 w-4" /> },
};

const SEVERITY_MAP: Record<string, { text: string; variant: 'critical' | 'high' | 'medium' | 'low' | 'info' }> = {
  critical: { text: 'CRITICAL', variant: 'critical' },
  high: { text: 'HIGH', variant: 'high' },
  medium: { text: 'MEDIUM', variant: 'medium' },
  low: { text: 'LOW', variant: 'low' },
  info: { text: 'INFO', variant: 'info' },
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
        <div className="text-text-secondary font-mono text-sm mb-3">MARK AS:</div>
        <div className="flex gap-3">
          <Button
            size="sm"
            variant={finding.status === 'confirmed' ? 'success' : 'outline'}
            onClick={() => handleStatusChange('confirmed')}
            disabled={isUpdating}
          >
            <Check className="mr-2 h-4 w-4" />
            CONFIRMED
          </Button>
          <Button
            size="sm"
            variant={finding.status === 'false_positive' ? 'destructive' : 'outline'}
            onClick={() => handleStatusChange('false_positive')}
            disabled={isUpdating}
          >
            <X className="mr-2 h-4 w-4" />
            FALSE POSITIVE
          </Button>
          <Button
            size="sm"
            variant={finding.status === 'conditional' ? 'secondary' : 'outline'}
            onClick={() => handleStatusChange('conditional')}
            disabled={isUpdating}
          >
            <HelpCircle className="mr-2 h-4 w-4" />
            CONDITIONAL
          </Button>
        </div>
      </div>

      <Tabs
        defaultActiveKey="overview"
        items={[
          {
            key: 'overview',
            label: 'OVERVIEW',
            children: (
              <>
                {/* Basic Info */}
                <Descriptions
                  items={[
                    {
                      label: 'VULNERABILITY TYPE',
                      value: <span className="text-cyan font-mono">{finding.vuln_type}</span>,
                      span: 2,
                    },
                    {
                      label: 'SEVERITY',
                      value: (
                        <div className="flex items-center gap-3">
                          <Badge variant={severityConfig.variant}>{severityConfig.text}</Badge>
                          <span className="text-text-secondary">
                            CONFIDENCE: {(finding.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                      ),
                      span: 2,
                    },
                    {
                      label: 'FILE LOCATION',
                      value: <code className="text-cyan font-mono text-sm bg-background-tertiary px-2 py-1 rounded">{finding.file_path}</code>,
                      span: 2,
                    },
                    {
                      label: 'LINE NUMBERS',
                      value: finding.line_start && finding.line_end
                        ? `${finding.line_start} - ${finding.line_end}`
                        : finding.line_start || '-',
                      span: 2,
                    },
                    {
                      label: 'FUNCTION',
                      value: finding.function_name || '-',
                      span: 2,
                    },
                    {
                      label: 'DETECTION ENGINE',
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
                    <h4 className="text-cyan font-mono font-bold mb-3">DESCRIPTION</h4>
                    <p className="text-text-secondary leading-relaxed">{finding.description}</p>
                  </div>
                )}

                {/* Remediation */}
                {finding.remediation && (
                  <div className="mt-6">
                    <h4 className="text-cyan font-mono font-bold mb-3">REMEDIATION</h4>
                    <Alert variant="info" title="RECOMMENDED ACTIONS">
                      {finding.remediation}
                    </Alert>
                  </div>
                )}
              </>
            ),
          },
          {
            key: 'code',
            label: 'CODE EVIDENCE',
            children: finding.evidence ? (
              <>
                <div className="mb-4 flex items-center justify-between">
                  <span className="text-text-secondary font-mono text-sm">AFFECTED CODE SNIPPET</span>
                  <Button size="sm" variant="outline" onClick={copyEvidence}>
                    <Copy className="mr-2 h-4 w-4" />
                    COPY
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
              <Alert variant="warning" title="NO CODE EVIDENCE">
                This finding does not include code evidence.
              </Alert>
            ),
          },
          {
            key: 'metadata',
            label: 'METADATA',
            children: (
              <Descriptions
                items={[
                  { label: 'FINDING ID', value: String(finding.id), span: 1 },
                  { label: 'SCAN ID', value: String(finding.scan_id), span: 1 },
                  {
                    label: 'CREATED AT',
                    value: new Date(finding.created_at).toLocaleString('zh-CN'),
                    span: 2,
                  },
                  ...(finding.cpg_path
                    ? [
                        {
                          label: 'CPG PATH',
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
