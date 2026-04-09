import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw, Plus, Upload, Eye, Folder, GitBranch, Archive, Play, X } from 'lucide-react';
import {
  Button,
  Card,
  Badge,
  Progress,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Select,
  CustomSelect,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui';
import { useScans, useCreateScan } from '@/hooks/useApi';
import type { ScanStatus } from '@/types/models';
import axios from 'axios';

// Status mapping with cyberpunk variants
const STATUS_MAP: Record<string, { text: string; variant: 'pending' | 'running' | 'completed' | 'failed' }> = {
  pending: { text: 'WAITING', variant: 'pending' },
  running: { text: 'SCANNING', variant: 'running' },
  paused: { text: 'PAUSED', variant: 'pending' },
  completed: { text: 'COMPLETE', variant: 'completed' },
  failed: { text: 'FAILED', variant: 'failed' },
  cancelled: { text: 'CANCELLED', variant: 'failed' },
};

const SOURCE_ICONS: Record<string, React.ReactNode> = {
  local: <Folder className="h-4 w-4" />,
  git: <GitBranch className="h-4 w-4" />,
  zip: <Archive className="h-4 w-4" />,
};

export default function ScansPage() {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [statusFilter, setStatusFilter] = useState<ScanStatus | undefined>();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    source_type: 'zip' as 'local' | 'git' | 'zip',
    source_path: '',
    scan_type: 'full' as 'full' | 'base',
  });
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const { data, isLoading, refetch } = useScans({
    page,
    page_size: pageSize,
    status: statusFilter,
  });

  const createMutation = useCreateScan();

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Task name required';
    }
    if (formData.source_type !== 'zip' && !formData.source_path.trim()) {
      newErrors.source_path = 'Source path required';
    }
    if (formData.source_type === 'zip' && !uploadedFile) {
      newErrors.file = 'ZIP file required';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleCreate = async () => {
    if (!validateForm()) return;

    try {
      if (formData.source_type === 'zip') {
        const formDataObj = new FormData();
        formDataObj.append('file', uploadedFile!);
        formDataObj.append('name', formData.name);
        formDataObj.append('description', '');
        formDataObj.append('scan_type', formData.scan_type);
        formDataObj.append('config', JSON.stringify({ engines: ['semgrep', 'codeql', 'agent'] }));

        const response = await axios.post('/api/v1/scans/upload-zip', formDataObj, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });

        await axios.post(`/api/v1/scans/${response.data.id}/start`);
      } else {
        const response = await createMutation.mutateAsync(formData);
        await axios.post(`/api/v1/scans/${response.id}/start`);
      }

      setIsDialogOpen(false);
      resetForm();
      refetch();
    } catch (error) {
      console.error('Create scan error:', error);
      setErrors({ form: 'Creation failed. Please try again.' });
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      source_type: 'zip',
      source_path: '',
      scan_type: 'full',
    });
    setUploadedFile(null);
    setErrors({});
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (!file.name.toLowerCase().endsWith('.zip')) {
        setErrors({ file: 'Only ZIP files are supported' });
        return;
      }
      setUploadedFile(file);
      setErrors((prev) => ({ ...prev, file: '' }));
    }
  };

  const totalPages = data ? Math.ceil(data.total / pageSize) : 0;

  return (
    <div className="p-6">
      {/* Ambient particles */}
      {Array.from({ length: 10 }).map((_, i) => (
        <div
          key={i}
          className="particle"
          style={{
            left: `${Math.random() * 100}%`,
            animationDelay: `${Math.random() * 15}s`,
            animationDuration: `${15 + Math.random() * 10}s`,
          }}
        />
      ))}

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-text-primary font-mono tracking-wider">
            SCAN QUEUE
          </h1>
          <span className="text-cyan">//</span>
          <span className="text-cyan font-mono animate-pulse">[LIVE]</span>
          <span className="ml-2 w-3 h-5 bg-cyan/30 rounded-sm relative overflow-hidden">
            <span className="absolute inset-0 bg-cyan animate-blink" />
          </span>
        </div>
        <p className="text-text-secondary font-sans">Manage and monitor security scan tasks</p>
      </div>

      {/* Actions Bar */}
      <div className="mb-6 flex items-center justify-between">
        <CustomSelect
          value={statusFilter || ''}
          onChange={(val) => setStatusFilter(val as ScanStatus | undefined)}
          options={[
            { value: '', label: 'ALL STATUS' },
            { value: 'pending', label: 'WAITING' },
            { value: 'running', label: 'SCANNING' },
            { value: 'paused', label: 'PAUSED' },
            { value: 'completed', label: 'COMPLETE' },
            { value: 'failed', label: 'FAILED' },
            { value: 'cancelled', label: 'CANCELLED' },
          ]}
          className="w-48"
        />
        <div className="flex gap-3">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            REFRESH
          </Button>
          <Button onClick={() => setIsDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            NEW SCAN
          </Button>
        </div>
      </div>

      {/* Scan Tasks Table */}
      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-20 text-cyan">ID</TableHead>
              <TableHead>TASK NAME</TableHead>
              <TableHead className="w-28">STATUS</TableHead>
              <TableHead className="w-20">SOURCE</TableHead>
              <TableHead className="w-32">PROGRESS</TableHead>
              <TableHead className="w-20">VLUNS</TableHead>
              <TableHead className="w-24">ANALYZED</TableHead>
              <TableHead className="w-40">CREATED</TableHead>
              <TableHead className="w-24 text-right">ACTIONS</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center text-text-secondary font-mono">
                  <span className="inline-flex items-center gap-2">
                    <span className="w-2 h-2 bg-cyan rounded-full animate-ping" />
                    INITIALIZING...
                  </span>
                </TableCell>
              </TableRow>
            ) : !data?.items || data.items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center py-16">
                  <div className="flex flex-col items-center gap-4">
                    <pre className="text-cyan/50 font-mono text-sm">
{`
   _____  _____  _____  _____  _____
  /     \\ |  _  | |  _  |/  ___> |     \\
  |     | |     | |     | |___   |     |
  |  _  | |     | |  |  | <   >  |  _  |
  |     | |     | |     | |___   |     |
  \\_____/ |_____| |____| \\_____/ \\_____/

  NO SIGNAL DETECTED
  AWAITING INPUT...
`}
                    </pre>
                    <Button onClick={() => setIsDialogOpen(true)}>INITIATE FIRST SCAN</Button>
                  </div>
                </TableCell>
              </TableRow>
            ) : (
              data.items.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell className="font-mono text-cyan">#{String(scan.id).padStart(4, '0')}</TableCell>
                  <TableCell className="font-medium text-text-primary">{scan.name}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Badge variant={STATUS_MAP[scan.status].variant} className="min-w-[100px] justify-center">
                        {scan.status === 'running' ? (
                          <>
                            <span className="w-2 h-2 bg-cyan rounded-full animate-pulse mr-2" />
                            {STATUS_MAP[scan.status].text}
                          </>
                        ) : scan.status === 'completed' ? (
                          <>
                            <span className="text-success mr-1">OK</span>
                            {STATUS_MAP[scan.status].text}
                          </>
                        ) : (
                          STATUS_MAP[scan.status].text
                        )}
                      </Badge>
                      {scan.status === 'running' && (
                        <span className="text-xs text-cyan font-mono">{scan.progress_percent || 0}%</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center justify-center gap-1 text-text-secondary">
                      {SOURCE_ICONS[scan.source_type]}
                    </div>
                  </TableCell>
                  <TableCell>
                    {scan.status === 'completed' ? (
                      <Badge variant="completed">100%</Badge>
                    ) : scan.status === 'failed' || scan.status === 'cancelled' ? (
                      <span className="text-text-tertiary font-mono">--</span>
                    ) : (
                      <Progress value={scan.progress_percent || 0} variant="cyan" className="h-2 w-full max-w-[120px]" />
                    )}
                  </TableCell>
                  <TableCell className="text-center">
                    <Badge
                      variant={scan.findings_count && scan.findings_count > 0 ? 'critical' : 'info'}
                      className="min-w-[40px] justify-center"
                    >
                      {scan.findings_count || 0}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-text-secondary font-mono text-xs">
                    {scan.total_files
                      ? `${scan.analyzed_files || 0} / ${scan.total_files}`
                      : String(scan.analyzed_files || 0)}
                  </TableCell>
                  <TableCell className="text-text-dim font-mono text-xs">
                    {new Date(scan.created_at).toLocaleString('zh-CN')}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => navigate(`/scans/${scan.id}`)}
                      className="inline-flex"
                    >
                      <Eye className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>

        {/* Pagination */}
        {data && data.total > 0 && (
          <div className="flex items-center justify-between border-t border-border p-4">
            <span className="text-sm text-text-secondary font-mono">
              TOTAL: {String(data.total).padStart(3, '0')} SCANS
            </span>
            <div className="flex items-center gap-4">
              <Button
                variant="outline"
                size="icon"
                disabled={page === 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="w-10 h-10"
              >
                &larr;
              </Button>
              <span className="font-mono text-cyan text-sm">
                {String(page).padStart(2, '0')} / {String(totalPages).padStart(2, '0')}
              </span>
              <Button
                variant="outline"
                size="icon"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="w-10 h-10"
              >
                &rarr;
              </Button>
            </div>
          </div>
        )}
      </Card>

      {/* Floating Action Button */}
      <button
        onClick={() => setIsDialogOpen(true)}
        className="fixed bottom-8 right-8 w-16 h-16 bg-gradient-to-br from-cyan to-magenta rounded-full shadow-glow-cyan hover:shadow-glow-magenta hover:scale-110 transition-all duration-300 flex items-center justify-center group"
      >
        <Plus className="h-8 w-8 text-black group-hover:rotate-90 transition-transform duration-300" />
      </button>

      {/* Create Scan Dialog */}
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-cyan font-mono">
              &lt;INITIATE_SCAN/&gt;
            </DialogTitle>
            <DialogDescription>Configure and launch a new security scan</DialogDescription>
          </DialogHeader>

          <div className="space-y-5 py-4">
            {errors.form && (
              <div className="p-3 rounded bg-critical/10 border border-critical/30">
                <p className="text-sm text-critical font-mono">⚠ {errors.form}</p>
              </div>
            )}

            <Input
              label="TASK NAME"
              placeholder="e.g., my-project-security-scan"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              error={errors.name}
            />

            <CustomSelect
              label="SOURCE TYPE"
              value={formData.source_type}
              onChange={(val) => setFormData({ ...formData, source_type: val as any })}
              options={[
                { value: 'local', label: 'LOCAL DIRECTORY' },
                { value: 'git', label: 'GIT REPOSITORY' },
                { value: 'zip', label: 'ZIP ARCHIVE' },
              ]}
            />

            {formData.source_type !== 'zip' && (
              <Input
                label="SOURCE PATH"
                placeholder="/path/to/project or https://github.com/user/repo"
                value={formData.source_path}
                onChange={(e) => setFormData({ ...formData, source_path: e.target.value })}
                error={errors.source_path}
              />
            )}

            {formData.source_type === 'zip' && (
              <div className="space-y-2">
                <label className="text-sm font-medium text-text-secondary font-sans">
                  ZIP ARCHIVE
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="file"
                    accept=".zip"
                    onChange={handleFileChange}
                    className="hidden"
                    id="file-upload"
                  />
                  <label htmlFor="file-upload">
                    <Button type="button" variant="outline" size="sm" asChild>
                      <span className="cursor-pointer">
                        <Upload className="mr-2 h-4 w-4" />
                        SELECT FILE
                      </span>
                    </Button>
                  </label>
                  {uploadedFile && (
                    <span className="text-sm text-cyan font-mono">
                      {uploadedFile.name} <span className="text-text-tertiary">({(uploadedFile.size / 1024 / 1024).toFixed(2)} MB)</span>
                    </span>
                  )}
                </div>
                {errors.file && <p className="text-xs text-critical font-mono mt-1">⚠ {errors.file}</p>}
              </div>
            )}

            <CustomSelect
              label="SCAN TYPE"
              value={formData.scan_type}
              onChange={(val) => setFormData({ ...formData, scan_type: val as any })}
              options={[
                { value: 'full', label: 'FULL SCAN (All Engines)' },
                { value: 'base', label: 'BASE SCAN (Core Only)' },
              ]}
            />
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setIsDialogOpen(false);
                resetForm();
              }}
            >
              <X className="mr-2 h-4 w-4" />
              CANCEL
            </Button>
            <Button onClick={handleCreate} disabled={createMutation.isPending} className="min-w-[140px]">
              {createMutation.isPending ? (
                <span className="flex items-center">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin mr-2" />
                  PROCESSING
                </span>
              ) : (
                <>
                  <Play className="mr-2 h-4 w-4" />
                  INITIATE
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
