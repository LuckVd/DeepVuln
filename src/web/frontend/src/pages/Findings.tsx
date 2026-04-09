import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
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
import type { Finding, FindingStatus, SeverityLevel } from '@/types/models';
import FindingList from '@/components/finding/FindingList';
import FindingDrawer from '@/components/finding/FindingDrawer';

const STATUS_OPTIONS: { value: FindingStatus; label: string }[] = [
  { value: 'pending', label: 'PENDING' },
  { value: 'confirmed', label: 'CONFIRMED' },
  { value: 'false_positive', label: 'FALSE POSITIVE' },
  { value: 'conditional', label: 'CONDITIONAL' },
];

const SEVERITY_OPTIONS: { value: SeverityLevel; label: string }[] = [
  { value: 'critical', label: 'CRITICAL' },
  { value: 'high', label: 'HIGH' },
  { value: 'medium', label: 'MEDIUM' },
  { value: 'low', label: 'LOW' },
  { value: 'info', label: 'INFO' },
];

/**
 * Findings list page with cyberpunk theme
 */
export default function FindingsPage() {
  const { id: scanId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const id = parseInt(scanId || '0');

  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [statusFilter, setStatusFilter] = useState<FindingStatus | undefined>();
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | undefined>();
  const [searchText, setSearchText] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

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
    enabled: !isNaN(id),
  });

  // Filter results (client-side search)
  const filteredFindings = data?.findings.filter((finding) => {
    if (!searchText) return true;
    const searchLower = searchText.toLowerCase();
    return (
      finding.vuln_type.toLowerCase().includes(searchLower) ||
      finding.file_path.toLowerCase().includes(searchLower) ||
      finding.title?.toLowerCase().includes(searchLower) ||
      finding.description?.toLowerCase().includes(searchLower)
    );
  }) || [];

  const handlePageChange = (newPage: number, newPageSize?: number) => {
    setPage(newPage);
  };

  const handleViewDetail = (finding: Finding) => {
    setSelectedFinding(finding);
    setDrawerOpen(true);
  };

  const handleStatusChange = (findingId: number, newStatus: FindingStatus) => {
    updateStatus(findingId, newStatus);
    // Brief success feedback could be added here
  };

  if (isNaN(id)) {
    navigate('/scans');
    return null;
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

      {/* Statistics Cards */}
      {data?.summary && (
        <div className="grid grid-cols-5 gap-4 mb-6">
          <Statistic title="TOTAL FINDINGS" value={data.summary.total} />
          <Statistic
            title="VERIFIED"
            value={data.summary.verified}
            valueClassName="text-success"
          />
          <Statistic
            title="FALSE POSITIVE"
            value={data.summary.false_positive}
            valueClassName="text-critical"
          />
          <Statistic
            title="CRITICAL"
            value={data.summary.by_severity.critical || 0}
            valueClassName={data.summary.by_severity.critical ? 'text-critical' : ''}
          />
          <Statistic
            title="HIGH"
            value={data.summary.by_severity.high || 0}
            valueClassName={data.summary.by_severity.high ? 'text-warning' : ''}
          />
        </div>
      )}

      {/* Toolbar */}
      <Card className="glass-panel mb-6">
        <div className="flex items-center gap-4 flex-wrap">
          <CustomSelect
            label="STATUS"
            value={statusFilter || ''}
            onChange={(val) => setStatusFilter(val as FindingStatus | undefined)}
            options={[
              { value: '', label: 'ALL STATUS' },
              ...STATUS_OPTIONS.map((opt) => ({ value: opt.value, label: opt.label })),
            ]}
            className="w-40"
          />
          <CustomSelect
            label="SEVERITY"
            value={severityFilter || ''}
            onChange={(val) => setSeverityFilter(val as SeverityLevel | undefined)}
            options={[
              { value: '', label: 'ALL SEVERITIES' },
              ...SEVERITY_OPTIONS.map((opt) => ({ value: opt.value, label: opt.label })),
            ]}
            className="w-40"
          />
          <div className="flex-1 min-w-[200px]">
            <Input
              placeholder="Search vuln type, file, description..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              className="font-mono"
            />
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            REFRESH
          </Button>
        </div>
      </Card>

      {/* Findings List */}
      <Card className="glass-panel">
        <FindingList
          findings={filteredFindings}
          loading={isLoading}
          total={searchText ? filteredFindings.length : data?.total || 0}
          page={page}
          pageSize={pageSize}
          onPageChange={handlePageChange}
          onViewDetail={handleViewDetail}
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
