import { useMemo } from 'react';
import { Badge, Progress, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, Button } from '@/components/ui';
import { Eye } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { getVulnTypeName } from '@/utils/ruleTranslations';
import type { Finding, SeverityLevel, FindingStatus } from '@/types/models';

interface FindingListProps {
  findings: Finding[]
  loading?: boolean
  total: number
  page: number
  pageSize: number
  onPageChange: (page: number, pageSize: number) => void
  onViewDetail: (finding: Finding) => void
  sortField?: 'severity' | 'confidence' | 'engine' | null
  sortDir?: 'asc' | 'desc'
  onSort?: (field: 'severity' | 'confidence' | 'engine') => void
}

/** Sortable table header helper */
function SortHead({ label, field, sortField, sortDir, onSort, className }: {
  label: string; field: 'severity' | 'confidence' | 'engine';
  sortField?: string | null; sortDir?: string; onSort?: (f: any) => void;
  className?: string;
}) {
  const active = sortField === field;
  const arrow = active ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '';
  return (
    <TableHead
      className={`cursor-pointer select-none hover:text-cyan transition-colors ${className || ''}`}
      onClick={() => onSort?.(field)}
    >
      {label}{arrow}
    </TableHead>
  );
}

/**
 * Finding list component with cyberpunk theme
 */
export default function FindingList({
  findings,
  loading = false,
  total,
  page,
  pageSize,
  onPageChange,
  onViewDetail,
  sortField,
  sortDir,
  onSort,
}: FindingListProps) {
  const { t } = useLanguage();

  // Dynamic status and severity maps with translations
  const STATUS_MAP = useMemo<Record<FindingStatus, { text: string; variant: 'pending' | 'running' | 'completed' | 'failed' | 'high' | 'medium' | 'low' }>>(() => ({
    pending: { text: t('status.waiting'), variant: 'pending' },
    confirmed: { text: t('status.complete'), variant: 'completed' },
    false_positive: { text: t('findings.falsePositive'), variant: 'failed' },
    conditional: { text: t('status.conditional'), variant: 'medium' },
  }), [t]);

  const SEVERITY_MAP = useMemo<Record<SeverityLevel, { text: string; variant: 'critical' | 'high' | 'medium' | 'low' | 'info' }>>(() => ({
    critical: { text: t('severity.critical'), variant: 'critical' },
    high: { text: t('severity.high'), variant: 'high' },
    medium: { text: t('severity.medium'), variant: 'medium' },
    low: { text: t('severity.low'), variant: 'low' },
    info: { text: t('severity.info'), variant: 'info' },
  }), [t]);

  return (
    <div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-20 text-cyan">{t('table.id')}</TableHead>
            <TableHead>{t('table.vulnType')}</TableHead>
            <SortHead label={t('table.severity')} field="severity" sortField={sortField} sortDir={sortDir} onSort={onSort} className="w-28" />
            <SortHead label={t('table.confidence')} field="confidence" sortField={sortField} sortDir={sortDir} onSort={onSort} className="w-32" />
            <TableHead className="w-28">{t('findings.status')}</TableHead>
            <TableHead>{t('table.location')}</TableHead>
            <TableHead className="w-28">{t('table.function')}</TableHead>
            <SortHead label={t('table.engine')} field="engine" sortField={sortField} sortDir={sortDir} onSort={onSort} className="w-20" />
            <TableHead className="w-20 text-right">{t('table.action')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading ? (
            <TableRow>
              <TableCell colSpan={9} className="text-center text-text-secondary font-mono">
                <span className="inline-flex items-center gap-2">
                  <span className="w-2 h-2 bg-cyan rounded-full animate-ping" />
                  {t('common.loading')}
                </span>
              </TableCell>
            </TableRow>
          ) : findings.length === 0 ? (
            <TableRow>
              <TableCell colSpan={9} className="text-center text-text-tertiary font-mono py-8">
                {t('findings.noCodeEvidence')}
              </TableCell>
            </TableRow>
          ) : (
            findings.map((finding) => {
              const statusConfig = STATUS_MAP[finding.status];
              const severityConfig = SEVERITY_MAP[finding.severity];
              const confidence = Math.round(finding.confidence * 100);
              const filePath = finding.file_path.split('/').slice(-2).join('/');

              return (
                <TableRow
                  key={finding.id}
                  onClick={() => onViewDetail(finding)}
                  className="cursor-pointer"
                >
                  <TableCell className="font-mono text-cyan">#{String(finding.id).padStart(4, '0')}</TableCell>
                  <TableCell className="font-medium text-text-primary">{getVulnTypeName(finding.vuln_type)}</TableCell>
                  <TableCell>
                    <Badge variant={severityConfig.variant} className="min-w-[90px] justify-center">
                      {severityConfig.text}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Progress
                      value={confidence}
                      variant={confidence > 80 ? 'critical' : 'cyan'}
                      className="h-2"
                    />
                  </TableCell>
                  <TableCell>
                    <Badge variant={statusConfig.variant} className="min-w-[90px] justify-center">
                      {statusConfig.text}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-text-secondary font-mono text-xs">
                    {filePath}:{finding.line_start}
                  </TableCell>
                  <TableCell className="text-text-secondary font-mono text-xs">
                    {finding.function_name || '-'}
                  </TableCell>
                  <TableCell className="text-text-tertiary font-mono text-xs">
                    {finding.engine}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={(e) => {
                        e.stopPropagation();
                        onViewDetail(finding);
                      }}
                    >
                      <Eye className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })
          )}
        </TableBody>
      </Table>

      {/* Pagination */}
      {total > 0 && (() => {
        const totalPages = Math.ceil(total / pageSize);
        // Build page numbers to display (max 7 visible)
        const buildPages = (): (number | '...')[] => {
          if (totalPages <= 7) return Array.from({ length: totalPages }, (_, i) => i + 1);
          const pages: (number | '...')[] = [1];
          if (page > 3) pages.push('...');
          const start = Math.max(2, page - 1);
          const end = Math.min(totalPages - 1, page + 1);
          for (let i = start; i <= end; i++) pages.push(i);
          if (page < totalPages - 2) pages.push('...');
          pages.push(totalPages);
          return pages;
        };

        return (
          <div className="flex items-center justify-between border-t border-border p-4 mt-4">
            <span className="text-sm text-text-secondary font-mono">
              {t('common.total')}: {total}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="icon"
                disabled={page === 1}
                onClick={() => onPageChange(page - 1, pageSize)}
                className="w-8 h-8 text-xs"
              >
                &larr;
              </Button>
              {buildPages().map((p, i) =>
                p === '...' ? (
                  <span key={`dots-${i}`} className="text-text-tertiary text-xs px-1 select-none">...</span>
                ) : (
                  <Button
                    key={p}
                    variant={p === page ? 'default' : 'outline'}
                    size="icon"
                    onClick={() => onPageChange(p, pageSize)}
                    className={`w-8 h-8 text-xs ${p === page ? 'bg-cyan text-background-primary' : ''}`}
                  >
                    {p}
                  </Button>
                )
              )}
              <Button
                variant="outline"
                size="icon"
                disabled={page >= totalPages}
                onClick={() => onPageChange(page + 1, pageSize)}
                className="w-8 h-8 text-xs"
              >
                &rarr;
              </Button>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
