import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card,
  Badge,
  Button,
  Input,
  CustomSelect,
  Statistic,
  LoadingPage,
} from '@/components/ui';
import { Search, Filter, Eye } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { useGlobalVulns, useGlobalVulnsSummary, useUpdateFindingStatus } from '@/hooks/useGlobalVulns';
import type { Finding, FindingStatus, SeverityLevel } from '@/types/models';
import { getVulnTypeName } from '@/utils/ruleTranslations';

/**
 * Global vulnerabilities page with cyberpunk theme
 */
export default function VulnerabilitiesPage() {
  const navigate = useNavigate();
  const { t } = useLanguage();

  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | undefined>();
  const [statusFilter, setStatusFilter] = useState<FindingStatus | undefined>();
  const [searchText, setSearchText] = useState('');

  // Dynamic options with translations
  const SEVERITY_OPTIONS = useMemo(() => [
    { value: 'critical' as SeverityLevel, label: t('severity.critical') },
    { value: 'high' as SeverityLevel, label: t('severity.high') },
    { value: 'medium' as SeverityLevel, label: t('severity.medium') },
    { value: 'low' as SeverityLevel, label: t('severity.low') },
    { value: 'info' as SeverityLevel, label: t('severity.info') },
  ], [t]);

  const STATUS_OPTIONS = useMemo(() => [
    { value: 'pending' as FindingStatus, label: t('status.waiting') },
    { value: 'confirmed' as FindingStatus, label: t('status.complete') },
    { value: 'false_positive' as FindingStatus, label: t('findings.falsePositive') },
    { value: 'conditional' as FindingStatus, label: t('status.conditional') },
  ], [t]);

  const {
    data,
    isLoading,
    refetch,
  } = useGlobalVulns({
    page,
    page_size: pageSize,
    severity: severityFilter,
    status: statusFilter,
    search: searchText,
  });

  const { data: summary, isLoading: summaryLoading } = useGlobalVulnsSummary();
  const { mutate: updateStatus, isPending: isUpdating } = useUpdateFindingStatus();

  const handlePageChange = (newPage: number) => {
    setPage(newPage);
  };

  const handleViewDetail = (finding: Finding) => {
    navigate(`/scans/${finding.scan_id}/findings`);
  };

  const handleStatusChange = (finding: Finding & { scan_name: string }, newStatus: FindingStatus) => {
    updateStatus(
      { scanId: finding.scan_id, findingId: finding.id, status: newStatus },
      {
        onSuccess: () => {
          refetch();
        },
      }
    );
  };

  const handleSearch = () => {
    setPage(1);
    refetch();
  };

  const totalPages = data ? Math.ceil(data.total / pageSize) : 0;

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-text-primary font-mono tracking-wider">
            {t('vuln.title')}
          </h1>
          <span className="text-cyan">//</span>
          <span className="text-cyan font-mono">{t('vuln.globalView')}</span>
        </div>
        <p className="text-text-secondary font-sans">{t('vuln.subtitle')}</p>
      </div>

      {/* Statistics Cards */}
      {!summaryLoading && summary && (
        <div className="grid grid-cols-5 gap-4 mb-6">
          <Statistic title={t('dashboard.totalVulns')} value={summary.total} />
          <Statistic
            title={t('findings.verified')}
            value={summary.verified}
            valueClassName="text-success"
          />
          <Statistic
            title={t('findings.falsePositive')}
            value={summary.false_positive}
            valueClassName="text-critical"
          />
          <Statistic
            title={t('severity.critical')}
            value={summary.by_severity.critical || 0}
            valueClassName={summary.by_severity.critical ? 'text-critical' : ''}
          />
          <Statistic
            title={t('severity.high')}
            value={summary.by_severity.high || 0}
            valueClassName={summary.by_severity.high ? 'text-warning' : ''}
          />
        </div>
      )}

      {/* Toolbar */}
      <Card className="glass-panel mb-6">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <Input
              placeholder={t('vuln.searchPlaceholder')}
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              className="font-mono"
            />
          </div>
          <CustomSelect
            value={severityFilter || ''}
            onChange={(val) => {
              setSeverityFilter(val as SeverityLevel | undefined);
              setPage(1);
            }}
            options={[
              { value: '', label: t('vuln.allSeverities') },
              ...SEVERITY_OPTIONS.map((opt) => ({ value: opt.value, label: opt.label })),
            ]}
            className="w-40"
          />
          <CustomSelect
            value={statusFilter || ''}
            onChange={(val) => {
              setStatusFilter(val as FindingStatus | undefined);
              setPage(1);
            }}
            options={[
              { value: '', label: t('findings.allStatus') },
              ...STATUS_OPTIONS.map((opt) => ({ value: opt.value, label: opt.label })),
            ]}
            className="w-40"
          />
          <Button variant="outline" size="sm" onClick={handleSearch}>
            <Search className="mr-2 h-4 w-4" />
            {t('common.search')}
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <Filter className="mr-2 h-4 w-4" />
            {t('common.refresh')}
          </Button>
        </div>
      </Card>

      {/* Vulnerabilities Table */}
      <Card className="glass-panel overflow-hidden">
        {isLoading ? (
          <div className="text-center text-text-secondary font-mono py-16">
            <span className="inline-flex items-center gap-2">
              <span className="w-2 h-2 bg-cyan rounded-full animate-ping" />
              {t('common.loading')}
            </span>
          </div>
        ) : !data || data.items.length === 0 ? (
          <div className="text-center text-text-tertiary font-mono py-16">
            <p>{t('findings.noCodeEvidence')}</p>
          </div>
        ) : (
          <>
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left p-4 font-mono text-cyan text-sm w-20">{t('common.id')}</th>
                  <th className="text-left p-4 font-mono text-sm">{t('table.vulnType')}</th>
                  <th className="text-left p-4 font-mono text-sm w-28">{t('table.severity')}</th>
                  <th className="text-left p-4 font-mono text-sm w-24">{t('findings.status')}</th>
                  <th className="text-left p-4 font-mono text-sm">{t('table.location')}</th>
                  <th className="text-left p-4 font-mono text-sm w-32">{t('scanDetail.scan')}</th>
                  <th className="text-left p-4 font-mono text-sm w-20">{t('table.engine')}</th>
                  <th className="text-right p-4 font-mono text-sm w-24">{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((finding) => {
                  const severityClass = {
                    critical: 'text-critical',
                    high: 'text-warning',
                    medium: 'text-yellow-500',
                    low: 'text-success',
                    info: 'text-text-secondary',
                  }[finding.severity] || 'text-text-secondary';

                  const statusVariant = {
                    pending: 'pending',
                    confirmed: 'completed',
                    false_positive: 'failed',
                    conditional: 'medium',
                  }[finding.status] || 'pending';

                  return (
                    <tr
                      key={finding.id}
                      className="border-b border-border hover:bg-cyan/5 transition-colors cursor-pointer"
                      onClick={() => handleViewDetail(finding)}
                    >
                      <td className="p-4 font-mono text-cyan">#{String(finding.id).padStart(4, '0')}</td>
                      <td className="p-4 text-text-primary">{getVulnTypeName(finding.vuln_type)}</td>
                      <td className="p-4">
                        <Badge variant={finding.severity as any} className="min-w-[90px] justify-center">
                          {t(`severity.${finding.severity}`)}
                        </Badge>
                      </td>
                      <td className="p-4">
                        <Badge variant={statusVariant as any} className="min-w-[90px] justify-center">
                          {t(`status.${finding.status === 'false_positive' ? 'failed' : finding.status}`)}
                        </Badge>
                      </td>
                      <td className="p-4 text-text-secondary font-mono text-xs">
                        {finding.file_path.split('/').slice(-2).join('/')}:{finding.line_start}
                      </td>
                      <td className="p-4 text-text-dim font-mono text-xs">
                        {(finding as any).scan_name || `#${finding.scan_id}`}
                      </td>
                      <td className="p-4 text-text-tertiary font-mono text-xs">
                        {finding.engine}
                      </td>
                      <td className="p-4 text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleViewDetail(finding);
                          }}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {/* Pagination */}
            {data.total > 0 && (
              <div className="flex items-center justify-between border-t border-border p-4">
                <span className="text-sm text-text-secondary font-mono">
                  {t('common.total')}: {String(data.total).padStart(3, '0')}
                </span>
                <div className="flex items-center gap-4">
                  <Button
                    variant="outline"
                    size="icon"
                    disabled={page === 1}
                    onClick={() => handlePageChange(page - 1)}
                    className="w-10 h-10"
                  >
                    &larr;
                  </Button>
                  <span className="font-mono text-cyan text-sm">
                    {String(page).padStart(2, '0')} {t('common.of')} {String(totalPages).padStart(2, '0')}
                  </span>
                  <Button
                    variant="outline"
                    size="icon"
                    disabled={page >= totalPages}
                    onClick={() => handlePageChange(page + 1)}
                    className="w-10 h-10"
                  >
                    &rarr;
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>
    </div>
  );
}
