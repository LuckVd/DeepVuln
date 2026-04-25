import { useState, useMemo, useRef, useCallback, useEffect } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import {
  Card,
  Button,
  Select,
  CustomSelect,
  Input,
  Statistic,
  Badge,
  LoadingInline,
} from '@/components/ui';
import { ArrowLeft, RefreshCw, Search } from 'lucide-react';
import { useFindings } from '@/hooks/useFindings';
import { useLanguage } from '@/contexts/LanguageContext';
import type { Finding, FindingStatus, SeverityLevel } from '@/types/models';
import FindingList from '@/components/finding/FindingList';
import FindingDrawer from '@/components/finding/FindingDrawer';

/**
 * Findings list page with cyberpunk theme
 */
export default function FindingsPage() {
  const { id: scanId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { t } = useLanguage();
  const id = parseInt(scanId || '0');

  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [statusFilter, setStatusFilter] = useState<FindingStatus | undefined>();
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | undefined>();
  const [engineFilter, setEngineFilter] = useState<string | undefined>();
  const [searchText, setSearchText] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [sortField, setSortField] = useState<'severity' | 'confidence' | 'engine' | null>(null);
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  // Dynamic options with translations
  const STATUS_OPTIONS = useMemo(() => [
    { value: 'pending' as FindingStatus, label: t('status.waiting') },
    { value: 'confirmed' as FindingStatus, label: t('status.complete') },
    { value: 'false_positive' as FindingStatus, label: t('findings.falsePositive') },
    { value: 'conditional' as FindingStatus, label: t('status.conditional') },
  ], [t]);

  const SEVERITY_OPTIONS = useMemo(() => [
    { value: 'critical' as SeverityLevel, label: t('severity.critical') },
    { value: 'high' as SeverityLevel, label: t('severity.high') },
    { value: 'medium' as SeverityLevel, label: t('severity.medium') },
    { value: 'low' as SeverityLevel, label: t('severity.low') },
    { value: 'info' as SeverityLevel, label: t('severity.info') },
  ], [t]);

  const {
    data,
    isLoading,
    refetch,
    updateStatus,
    isUpdating,
  } = useFindings({
    scanId: id,
    page,
    page_size: pageSize,
    status: statusFilter,
    severity: severityFilter,
    engine: engineFilter,
    search: searchText || undefined,
    sort_field: sortField || undefined,
    sort_dir: sortField ? sortDir : undefined,
    enabled: !isNaN(id),
  });

  // Collect unique engines from current data for the filter dropdown
  const engineOptions = useMemo(() => {
    const engines = new Set<string>();
    data?.findings.forEach(f => { if (f.engine) engines.add(f.engine) });
    // Also add known engines
    ['agent', 'semgrep', 'codeql', 'ast'].forEach(e => engines.add(e));
    return Array.from(engines).sort();
  }, [data?.findings]);

  // Search is now handled server-side — no client-side filter needed
  const sortedFindings = data?.findings || [];

  const toggleSort = (field: 'severity' | 'confidence' | 'engine') => {
    if (sortField === field) {
      setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const scrollRef = useRef<number>(0);

  const handlePageChange = useCallback((newPage: number, newPageSize?: number) => {
    scrollRef.current = window.scrollY;
    setPage(newPage);
    requestAnimationFrame(() => window.scrollTo(0, scrollRef.current));
  }, []);

  const handleViewDetail = (finding: Finding) => {
    setSelectedFinding(finding);
    setDrawerOpen(true);
  };

  const handleStatusChange = (findingId: number, newStatus: FindingStatus) => {
    updateStatus(findingId, newStatus);
    // Brief success feedback could be added here
  };

  // Auto-open drawer when navigating from Vulnerabilities page with ?highlight=<id>
  useEffect(() => {
    const highlightId = searchParams.get('highlight');
    if (highlightId && data?.findings) {
      const target = data.findings.find(f => String(f.id) === highlightId);
      if (target) {
        setSelectedFinding(target);
        setDrawerOpen(true);
        // Clear the highlight param so it doesn't re-trigger
        setSearchParams({}, { replace: true });
      }
    }
  }, [searchParams, data?.findings, setSearchParams]);

  if (isNaN(id)) {
    navigate('/scans');
    return null;
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <Button variant="outline" size="sm" onClick={() => navigate(`/scans/${id}`)}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          {t('findings.returnToList')}
        </Button>
      </div>

      {/* Statistics Cards */}
      {data?.summary && (
        <div className="grid grid-cols-5 gap-4 mb-6">
          <Statistic title={t('findings.totalFindings')} value={data.summary.total} />
          <Statistic
            title={t('findings.verified')}
            value={data.summary.verified}
            valueClassName="text-success"
          />
          <Statistic
            title={t('findings.falsePositive')}
            value={data.summary.false_positive}
            valueClassName="text-critical"
          />
          <Statistic
            title={t('findings.critical')}
            value={data.summary.by_severity.critical || 0}
            valueClassName={data.summary.by_severity.critical ? 'text-critical' : ''}
          />
          <Statistic
            title={t('findings.high')}
            value={data.summary.by_severity.high || 0}
            valueClassName={data.summary.by_severity.high ? 'text-warning' : ''}
          />
        </div>
      )}

      {/* Toolbar */}
      <Card className="glass-panel mb-6 overflow-visible">
        <div className="flex items-end gap-4 flex-wrap">
          <CustomSelect
            label={t('findings.status')}
            value={statusFilter || ''}
            onChange={(val) => setStatusFilter(val as FindingStatus | undefined)}
            options={[
              { value: '', label: t('findings.allStatus') },
              ...STATUS_OPTIONS.map((opt) => ({ value: opt.value, label: opt.label })),
            ]}
            className="w-40"
          />
          <CustomSelect
            label={t('findings.severity')}
            value={severityFilter || ''}
            onChange={(val) => setSeverityFilter(val as SeverityLevel | undefined)}
            options={[
              { value: '', label: t('findings.allSeverities') },
              ...SEVERITY_OPTIONS.map((opt) => ({ value: opt.value, label: opt.label })),
            ]}
            className="w-40"
          />
          <CustomSelect
            label={t('p16.engine')}
            value={engineFilter || ''}
            onChange={(val) => setEngineFilter(val || undefined)}
            options={[
              { value: '', label: t('p16.allEngines') },
              ...engineOptions.map((e) => ({ value: e, label: e.toUpperCase() })),
            ]}
            className="w-36"
          />
          <div className="flex-1 min-w-[200px]">
            <Input
              placeholder={t('findings.searchPlaceholder')}
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              className="font-mono"
            />
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            {t('common.refresh')}
          </Button>
        </div>
      </Card>

      {/* Findings List */}
      <Card className="glass-panel">
        <FindingList
          findings={sortedFindings}
          loading={isLoading}
          total={data?.total || 0}
          page={page}
          pageSize={pageSize}
          onPageChange={handlePageChange}
          onViewDetail={handleViewDetail}
          sortField={sortField}
          sortDir={sortDir}
          onSort={toggleSort}
        />
      </Card>

      {/* Details Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onStatusChange={handleStatusChange}
        isUpdating={isUpdating}
      />
    </div>
  );
}
