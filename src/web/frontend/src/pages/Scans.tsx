import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw, Plus, Upload, Eye, Folder, GitBranch, Archive, Play, X } from 'lucide-react';
import { formatDateTime, formatDuration, setTimezone } from '@/utils/format';
import { systemSettingsApi } from '@/api/system';
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
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui';
import { useScans, useCreateScan } from '@/hooks/useApi';
import { useLanguage } from '@/contexts/LanguageContext';
import { scansApi } from '@/api/scans';
import type { ScanStatus } from '@/types/models';
import client from '@/api/client';

// Status mapping with cyberpunk variants
const getStatusMap = (t: (key: string) => string) => ({
  pending: { text: t('status.waiting'), variant: 'pending' as const },
  running: { text: t('status.scanning'), variant: 'running' as const },
  paused: { text: t('status.paused'), variant: 'pending' as const },
  completed: { text: t('status.complete'), variant: 'completed' as const },
  failed: { text: t('status.failed'), variant: 'failed' as const },
  cancelled: { text: t('status.cancelled'), variant: 'failed' as const },
});

const SOURCE_ICONS: Record<string, React.ReactNode> = {
  local: <Folder className="h-4 w-4" />,
  git: <GitBranch className="h-4 w-4" />,
  zip: <Archive className="h-4 w-4" />,
};

export default function ScansPage() {
  const navigate = useNavigate();
  const { t } = useLanguage();
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [statusFilter, setStatusFilter] = useState<ScanStatus | undefined>();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    source_type: 'zip' as 'local' | 'git' | 'zip',
    source_path: '',
    scan_type: 'full' as 'full' | 'base',
    enable_adversarial: false,
    engines: ['semgrep', 'codeql', 'agent', 'ast'] as string[],
  });
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isCreating, setIsCreating] = useState(false);

  // 上传进度状态
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadSpeed, setUploadSpeed] = useState(0);
  const [uploadEta, setUploadEta] = useState(0);

  const { data, isLoading, refetch } = useScans({
    page,
    page_size: pageSize,
    status: statusFilter,
  });

  const createMutation = useCreateScan();

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

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = t('scans.dialog.error.name');
    }
    if (formData.source_type !== 'zip' && !formData.source_path.trim()) {
      newErrors.source_path = t('scans.dialog.error.sourcePath');
    }
    if (formData.source_type === 'zip' && !uploadedFile) {
      newErrors.file = t('scans.dialog.error.file');
    }
    if (formData.engines.length === 0) {
      newErrors.engines = '至少选择一个引擎';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleCreate = async () => {
    if (!validateForm()) return;
    if (isCreating) return; // 防止重复提交

    setIsCreating(true);

    try {
      let scanId: number;

      if (formData.source_type === 'zip') {
        const formDataObj = new FormData();
        formDataObj.append('file', uploadedFile!);
        formDataObj.append('name', formData.name);
        formDataObj.append('description', '');
        formDataObj.append('scan_type', formData.scan_type);
        formDataObj.append('config', JSON.stringify({
          engines: formData.engines,
          adversarial: formData.enable_adversarial,
        }));

        // 重置上传进度
        setUploadProgress(0);
        setUploadSpeed(0);
        setUploadEta(0);

        // 用于计算上传速度
        const startTime = Date.now();
        let lastLoaded = 0;
        let lastTime = startTime;

        const response = await client.post('/scans/upload-zip', formDataObj, {
          headers: { 'Content-Type': 'multipart/form-data' },
          onUploadProgress: (progressEvent) => {
            if (progressEvent.total) {
              const loaded = progressEvent.loaded;
              const total = progressEvent.total;
              const currentTime = Date.now();

              // 计算进度百分比
              const percentCompleted = Math.round((loaded * 100) / total);
              setUploadProgress(percentCompleted);

              // 计算上传速度 (bytes/sec)
              const timeDiff = (currentTime - lastTime) / 1000; // 秒
              if (timeDiff > 0.5) { // 每0.5秒更新一次速度
                const bytesDiff = loaded - lastLoaded;
                const speed = bytesDiff / timeDiff;
                setUploadSpeed(speed);

                // 计算预计剩余时间
                const remainingBytes = total - loaded;
                const eta = speed > 0 ? remainingBytes / speed : 0;
                setUploadEta(eta);

                lastLoaded = loaded;
                lastTime = currentTime;
              }
            }
          },
        });
        scanId = response.data.id;
      } else {
        const response = await createMutation.mutateAsync({
          ...formData,
          config: {
            engines: formData.engines,
            adversarial: formData.enable_adversarial,
          },
        });
        scanId = response.id;
      }

      // Close dialog and navigate to scan detail page
      setIsDialogOpen(false);
      resetForm();
      refetch();

      // Navigate to scan detail page where user can manually start the scan
      navigate(`/scans/${scanId}`);
    } catch (error) {
      console.error('Create scan error:', error);
      setErrors({ form: t('scans.dialog.error.form') });
    } finally {
      setIsCreating(false);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      source_type: 'zip',
      source_path: '',
      scan_type: 'full',
      enable_adversarial: false,
      engines: ['semgrep', 'codeql', 'agent', 'ast'],
    });
    setUploadedFile(null);
    setErrors({});
    setUploadProgress(0);
    setUploadSpeed(0);
    setUploadEta(0);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (!file.name.toLowerCase().endsWith('.zip')) {
        setErrors({ file: t('scans.dialog.error.zipOnly') });
        return;
      }
      setUploadedFile(file);
      setErrors((prev) => ({ ...prev, file: '' }));
    }
  };

  const totalPages = data ? Math.ceil(data.total / pageSize) : 0;
  const STATUS_MAP = getStatusMap(t);

  // Handle starting a scan from the list
  const handleStartScan = async (scanId: number) => {
    try {
      await scansApi.start(scanId);
      // 延迟刷新，给后端时间更新状态
      setTimeout(() => refetch(), 500);
    } catch (error) {
      console.error('Failed to start scan:', error);
      // 即使失败也刷新，可能显示错误状态
      setTimeout(() => refetch(), 500);
    }
  };

  // Handle retrying a failed scan
  const handleRetryScan = async (scan: any) => {
    try {
      const retryData = {
        name: `${scan.name} (重试)`,
        source_type: scan.source_type,
        source_path: scan.source_path,
        branch: scan.branch || undefined,
        scan_type: scan.scan_type,
        config: scan.config,
      };
      const newScan = await scansApi.create(retryData);
      refetch();
    } catch (error) {
      console.error('Failed to retry scan:', error);
    }
  };

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
            {t('scans.title')}
          </h1>
          <span className="text-cyan">//</span>
          <span className="text-cyan font-mono animate-pulse">[LIVE]</span>
          <span className="ml-2 w-3 h-5 bg-cyan/30 rounded-sm relative overflow-hidden">
            <span className="absolute inset-0 bg-cyan animate-blink" />
          </span>
        </div>
        <p className="text-text-secondary font-sans">{t('scans.subtitle')}</p>
      </div>

      {/* Actions Bar */}
      <div className="mb-6 flex items-center justify-between">
        <CustomSelect
          value={statusFilter || ''}
          onChange={(val) => { setStatusFilter(val as ScanStatus | undefined); setPage(1); }}
          options={[
            { value: '', label: t('scans.status.all') },
            { value: 'pending', label: t('scans.status.pending') },
            { value: 'running', label: t('scans.status.running') },
            { value: 'paused', label: t('scans.status.paused') },
            { value: 'completed', label: t('scans.status.completed') },
            { value: 'failed', label: t('scans.status.failed') },
            { value: 'cancelled', label: t('scans.status.cancelled') },
          ]}
          className="w-48"
        />
        <div className="flex gap-3">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            {t('common.refresh')}
          </Button>
          <Button onClick={() => setIsDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            {t('scans.new')}
          </Button>
        </div>
      </div>

      {/* Scan Tasks Table */}
      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-20 text-cyan">{t('common.id')}</TableHead>
              <TableHead>{t('scans.table.taskName')}</TableHead>
              <TableHead className="w-28">{t('scans.table.status')}</TableHead>
              <TableHead className="w-20">{t('scans.table.source')}</TableHead>
              <TableHead className="w-32">{t('scans.table.progress')}</TableHead>
              <TableHead className="w-20">{t('scans.table.vulns')}</TableHead>
              <TableHead className="w-24">{t('scans.table.analyzed')}</TableHead>
              <TableHead className="w-40">{t('scans.table.created')}</TableHead>
              <TableHead className="w-40 text-right">{t('common.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center text-text-secondary font-mono">
                  <span className="inline-flex items-center gap-2">
                    <span className="w-2 h-2 bg-cyan rounded-full animate-ping" />
                    {t('scans.initializing')}
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

  ${t('scans.empty.title').toUpperCase()}
  ${t('scans.empty.subtitle').toUpperCase()}
`}
                    </pre>
                    <Button onClick={() => setIsDialogOpen(true)}>{t('scans.empty.button')}</Button>
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
                    {formatDateTime(scan.created_at)}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      {/* Pending: Start button */}
                      {scan.status === 'pending' && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleStartScan(scan.id)}
                          className="h-5 px-2 text-xs whitespace-nowrap"
                        >
                          <Play className="mr-0.5 h-2 w-2" />
                          启动
                        </Button>
                      )}
                      {/* Failed: Retry button */}
                      {scan.status === 'failed' && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleRetryScan(scan)}
                          className="h-5 px-2 text-xs whitespace-nowrap border-warning text-warning hover:bg-warning/10"
                        >
                          <Play className="mr-0.5 h-2 w-2" />
                          重试
                        </Button>
                      )}
                      {/* View button */}
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => navigate(`/scans/${scan.id}`)}
                        className="h-5 px-2 text-xs whitespace-nowrap"
                      >
                        查看
                      </Button>
                    </div>
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
              {t('common.total')}: {String(data.total).padStart(3, '0')} {t('scans.total')}
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
                {String(page).padStart(2, '0')} {t('common.of')} {String(totalPages).padStart(2, '0')}
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
              {t('scans.dialog.title')}
            </DialogTitle>
            <DialogDescription>{t('scans.dialog.description')}</DialogDescription>
          </DialogHeader>

          <div className="space-y-5 py-4">
            {errors.form && (
              <div className="p-3 rounded bg-critical/10 border border-critical/30">
                <p className="text-sm text-critical font-mono">⚠ {errors.form}</p>
              </div>
            )}

            <Input
              label={t('scans.dialog.taskName')}
              placeholder={t('scans.dialog.taskNamePlaceholder')}
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              error={errors.name}
            />

            <CustomSelect
              label={t('scans.dialog.sourceType')}
              value={formData.source_type}
              onChange={(val) => setFormData({ ...formData, source_type: val as any })}
              options={[
                { value: 'local', label: t('scans.source.local') },
                { value: 'git', label: t('scans.source.git') },
                { value: 'zip', label: t('scans.source.zip') },
              ]}
            />

            {formData.source_type !== 'zip' && (
              <Input
                label={t('scans.dialog.sourcePath')}
                placeholder={t('scans.dialog.sourcePathPlaceholder')}
                value={formData.source_path}
                onChange={(e) => setFormData({ ...formData, source_path: e.target.value })}
                error={errors.source_path}
              />
            )}

            {formData.source_type === 'zip' && (
              <div className="space-y-2">
                <label className="text-sm font-medium text-text-secondary font-sans">
                  {t('scans.dialog.zipArchive')}
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="file"
                    accept=".zip"
                    onChange={handleFileChange}
                    className="hidden"
                    id="file-upload"
                  />
                  <label
                    htmlFor="file-upload"
                    className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium border border-border rounded-md hover:bg-cyan/10 hover:text-cyan cursor-pointer transition-colors"
                  >
                    <Upload className="h-4 w-4" />
                    {t('scans.dialog.selectFile')}
                  </label>
                  {uploadedFile && (
                    <span className="text-sm text-cyan font-mono">
                      {uploadedFile.name} <span className="text-text-tertiary">({(uploadedFile.size / 1024 / 1024).toFixed(2)} MB)</span>
                    </span>
                  )}
                </div>
                {errors.file && <p className="text-xs text-critical font-mono mt-1">⚠ {errors.file}</p>}

                {/* 上传进度条 */}
                {isCreating && formData.source_type === 'zip' && uploadProgress > 0 && (
                  <div className="mt-3 p-3 rounded bg-cyan/5 border border-cyan/20">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs text-text-secondary font-mono">
                        上传中...
                      </span>
                      <span className="text-xs text-cyan font-mono">
                        {uploadProgress}%
                      </span>
                    </div>
                    <Progress value={uploadProgress} variant="cyan" className="h-2" />
                    <div className="flex items-center justify-between mt-2 text-xs text-text-tertiary font-mono">
                      <span>
                        {uploadSpeed > 0 ? `${(uploadSpeed / 1024).toFixed(1)} KB/s` : ''}
                      </span>
                      <span>
                        {uploadEta > 0 ? `预计剩余 ${formatDuration(uploadEta)}` : ''}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Engine Selection */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-text-secondary font-sans">
                  {t('scans.dialog.engines')}
                </label>
                <button
                  type="button"
                  onClick={() => {
                    const allEngines = ['semgrep', 'codeql', 'agent', 'ast'] as const;
                    setFormData({
                      ...formData,
                      engines: formData.engines.length === allEngines.length ? [] : allEngines,
                    });
                  }}
                  className="text-xs text-cyan hover:text-cyan/80 font-mono transition-colors"
                >
                  {formData.engines.length === 4 ? t('scans.dialog.deselectAll') : t('scans.dialog.selectAll')}
                </button>
              </div>
              <p className="text-xs text-text-tertiary">{t('scans.dialog.enginesDescription')}</p>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => {
                    const newEngines = formData.engines.includes('semgrep')
                      ? formData.engines.filter((e) => e !== 'semgrep')
                      : [...formData.engines, 'semgrep'];
                    setFormData({ ...formData, engines: newEngines });
                  }}
                  className={`
                    px-4 py-3 rounded-md border transition-all duration-200 text-left
                    ${formData.engines.includes('semgrep')
                      ? 'bg-cyan/20 border-cyan text-cyan shadow-glow-cyan'
                      : 'border-border text-text-secondary hover:border-cyan/50 hover:text-cyan/70'
                    }
                  `}
                >
                  <div className="text-sm font-medium">{t('scans.dialog.engineSemgrep')}</div>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const newEngines = formData.engines.includes('codeql')
                      ? formData.engines.filter((e) => e !== 'codeql')
                      : [...formData.engines, 'codeql'];
                    setFormData({ ...formData, engines: newEngines });
                  }}
                  className={`
                    px-4 py-3 rounded-md border transition-all duration-200 text-left
                    ${formData.engines.includes('codeql')
                      ? 'bg-cyan/20 border-cyan text-cyan shadow-glow-cyan'
                      : 'border-border text-text-secondary hover:border-cyan/50 hover:text-cyan/70'
                    }
                  `}
                >
                  <div className="text-sm font-medium">{t('scans.dialog.engineCodeQL')}</div>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const newEngines = formData.engines.includes('agent')
                      ? formData.engines.filter((e) => e !== 'agent')
                      : [...formData.engines, 'agent'];
                    setFormData({ ...formData, engines: newEngines });
                  }}
                  className={`
                    px-4 py-3 rounded-md border transition-all duration-200 text-left
                    ${formData.engines.includes('agent')
                      ? 'bg-cyan/20 border-cyan text-cyan shadow-glow-cyan'
                      : 'border-border text-text-secondary hover:border-cyan/50 hover:text-cyan/70'
                    }
                  `}
                >
                  <div className="text-sm font-medium">{t('scans.dialog.engineAgent')}</div>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const newEngines = formData.engines.includes('ast')
                      ? formData.engines.filter((e) => e !== 'ast')
                      : [...formData.engines, 'ast'];
                    setFormData({ ...formData, engines: newEngines });
                  }}
                  className={`
                    px-4 py-3 rounded-md border transition-all duration-200 text-left
                    ${formData.engines.includes('ast')
                      ? 'bg-cyan/20 border-cyan text-cyan shadow-glow-cyan'
                      : 'border-border text-text-secondary hover:border-cyan/50 hover:text-cyan/70'
                    }
                  `}
                >
                  <div className="text-sm font-medium">{t('scans.dialog.engineAST')}</div>
                </button>
              </div>
              {formData.engines.length === 0 && (
                <p className="text-xs text-critical font-mono">⚠ 至少选择一个引擎</p>
              )}
            </div>

            <div className="p-4 rounded-md bg-cyan/5 border border-cyan/20">
              <Switch
                label="启用对抗性验证"
                description="使用多轮LLM辩论验证漏洞，提高检测准确性（耗时较长）"
                checked={formData.enable_adversarial}
                onChange={(e) => setFormData({ ...formData, enable_adversarial: e.target.checked })}
              />
            </div>
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
              {t('common.cancel')}
            </Button>
            <Button onClick={handleCreate} disabled={isCreating || createMutation.isPending} className="min-w-[140px]">
              {isCreating || createMutation.isPending ? (
                <span className="flex items-center">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin mr-2" />
                  {t('common.processing')}
                </span>
              ) : (
                <>
                  <Plus className="mr-2 h-4 w-4" />
                  {t('scans.dialog.initiate')}
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
