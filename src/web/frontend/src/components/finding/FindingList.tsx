import { Badge, Progress, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, Button } from '@/components/ui';
import { Eye } from 'lucide-react';
import type { Finding, SeverityLevel, FindingStatus } from '@/types/models';

const STATUS_MAP: Record<FindingStatus, { text: string; variant: 'pending' | 'running' | 'completed' | 'failed' | 'high' | 'medium' | 'low' }> = {
  pending: { text: 'PENDING', variant: 'pending' },
  confirmed: { text: 'CONFIRMED', variant: 'completed' },
  false_positive: { text: 'FALSE POSITIVE', variant: 'failed' },
  conditional: { text: 'CONDITIONAL', variant: 'medium' },
};

const SEVERITY_MAP: Record<SeverityLevel, { text: string; variant: 'critical' | 'high' | 'medium' | 'low' | 'info' }> = {
  critical: { text: 'CRITICAL', variant: 'critical' },
  high: { text: 'HIGH', variant: 'high' },
  medium: { text: 'MEDIUM', variant: 'medium' },
  low: { text: 'LOW', variant: 'low' },
  info: { text: 'INFO', variant: 'info' },
};

interface FindingListProps {
  findings: Finding[]
  loading?: boolean
  total: number
  page: number
  pageSize: number
  onPageChange: (page: number, pageSize: number) => void
  onViewDetail: (finding: Finding) => void
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
}: FindingListProps) {
  // Sort findings by severity
  const sortedFindings = [...findings].sort((a, b) => {
    const order = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    return order[b.severity] - order[a.severity];
  });

  return (
    <div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-20 text-cyan">ID</TableHead>
            <TableHead>VULN TYPE</TableHead>
            <TableHead className="w-28">SEVERITY</TableHead>
            <TableHead className="w-32">CONFIDENCE</TableHead>
            <TableHead className="w-28">STATUS</TableHead>
            <TableHead>LOCATION</TableHead>
            <TableHead className="w-28">FUNCTION</TableHead>
            <TableHead className="w-20">ENGINE</TableHead>
            <TableHead className="w-20 text-right">ACTION</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading ? (
            <TableRow>
              <TableCell colSpan={9} className="text-center text-text-secondary font-mono">
                <span className="inline-flex items-center gap-2">
                  <span className="w-2 h-2 bg-cyan rounded-full animate-ping" />
                  LOADING...
                </span>
              </TableCell>
            </TableRow>
          ) : sortedFindings.length === 0 ? (
            <TableRow>
              <TableCell colSpan={9} className="text-center text-text-tertiary font-mono py-8">
                NO FINDINGS DETECTED
              </TableCell>
            </TableRow>
          ) : (
            sortedFindings.map((finding) => {
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
                  <TableCell className="font-medium text-text-primary">{finding.vuln_type}</TableCell>
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
      {total > 0 && (
        <div className="flex items-center justify-between border-t border-border p-4 mt-4">
          <span className="text-sm text-text-secondary font-mono">
            TOTAL: {String(total).padStart(3, '0')} FINDINGS
          </span>
          <div className="flex items-center gap-4">
            <Button
              variant="outline"
              size="icon"
              disabled={page === 1}
              onClick={() => onPageChange(page, pageSize)}
              className="w-10 h-10"
            >
              &larr;
            </Button>
            <span className="font-mono text-cyan text-sm">
              {String(page).padStart(2, '0')}
            </span>
            <Button
              variant="outline"
              size="icon"
              disabled={page * pageSize >= total}
              onClick={() => onPageChange(page + 1, pageSize)}
              className="w-10 h-10"
            >
              &rarr;
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
