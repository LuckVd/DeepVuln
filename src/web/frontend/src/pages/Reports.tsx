import { useState } from 'react';
import { Card, Button, CustomSelect, Input, Alert } from '@/components/ui';
import { Download, FileText, Loader2, CheckCircle, Trash2, RotateCw } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { reportsApi } from '@/api/reports';
import { useScans } from '@/hooks/useApi';

interface ReportRecord {
  id: string;
  scanId: number;
  scanName: string;
  format: 'json' | 'csv' | 'html';
  createdAt: string;
}

const STORAGE_KEY = 'deepvuln-recent-reports';

function loadReports(): ReportRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveReports(reports: ReportRecord[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(reports.slice(0, 20)));
}

/**
 * Reports page with export functionality
 */
export default function ReportsPage() {
  const { t } = useLanguage();
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [exportType, setExportType] = useState<'json' | 'csv' | 'html'>('json');
  const [isExporting, setIsExporting] = useState(false);
  const [exportSuccess, setExportSuccess] = useState(false);
  const [recentReports, setRecentReports] = useState<ReportRecord[]>(loadReports);

  // Get scans for selection
  const { data: scansData, isLoading: scansLoading } = useScans({
    page: 1,
    page_size: 100,
    status: 'completed',
  });

  const scanOptions = scansData?.items.map((scan) => ({
    value: String(scan.id),
    label: `#${String(scan.id).padStart(4, '0')} - ${scan.name}`,
  })) || [];

  const getScanName = (scanId: number) =>
    scansData?.items.find((s) => s.id === scanId)?.name || `Scan #${scanId}`;

  const addReportToHistory = (scanId: number, format: 'json' | 'csv' | 'html') => {
    const record: ReportRecord = {
      id: `${scanId}-${format}-${Date.now()}`,
      scanId,
      scanName: getScanName(scanId),
      format,
      createdAt: new Date().toISOString(),
    };
    const updated = [record, ...recentReports].slice(0, 20);
    setRecentReports(updated);
    saveReports(updated);
  };

  const removeReport = (id: string) => {
    const updated = recentReports.filter((r) => r.id !== id);
    setRecentReports(updated);
    saveReports(updated);
  };

  const handleReExport = async (record: ReportRecord) => {
    const timestamp = new Date().toISOString().slice(0, 10);
    const filename = `deepvuln-scan-${record.scanId}-${timestamp}`;
    switch (record.format) {
      case 'json':
        const jsonData = await reportsApi.exportJson(record.scanId);
        const jsonBlob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });
        reportsApi.downloadBlob(jsonBlob, `${filename}.json`);
        break;
      case 'csv':
        const csvData = await reportsApi.exportCsv(record.scanId);
        reportsApi.downloadBlob(csvData, `${filename}.csv`);
        break;
      case 'html':
        const htmlBlob = await reportsApi.exportHtml(record.scanId);
        reportsApi.downloadBlob(htmlBlob, `${filename}.html`);
        break;
    }
  };

  const handleExport = async () => {
    if (!selectedScanId) return;

    setIsExporting(true);
    setExportSuccess(false);

    try {
      const timestamp = new Date().toISOString().slice(0, 10);
      const filename = `deepvuln-scan-${selectedScanId}-${timestamp}`;

      switch (exportType) {
        case 'json':
          const jsonData = await reportsApi.exportJson(selectedScanId);
          const jsonBlob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });
          reportsApi.downloadBlob(jsonBlob, `${filename}.json`);
          break;

        case 'csv':
          const csvData = await reportsApi.exportCsv(selectedScanId);
          reportsApi.downloadBlob(csvData, `${filename}.csv`);
          break;

        case 'html':
          const htmlBlob = await reportsApi.exportHtml(selectedScanId);
          reportsApi.downloadBlob(htmlBlob, `${filename}.html`);
          break;
      }

      setExportSuccess(true);
      addReportToHistory(selectedScanId, exportType);
      setTimeout(() => setExportSuccess(false), 3000);
    } catch (error) {
      console.error('Export failed:', error);
      // Could show an error toast here
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-text-primary font-mono tracking-wider">
            {t('reports.title')}
          </h1>
          <span className="text-cyan">//</span>
          <span className="text-cyan font-mono">{t('reports.exports')}</span>
        </div>
        <p className="text-text-secondary font-sans">{t('reports.subtitle')}</p>
      </div>

      {/* Export Configuration */}
      <Card className="glass-panel mb-6 overflow-visible">
        <h3 className="text-cyan font-mono font-bold mb-4">{t('reports.generate')}</h3>

        <div className="grid grid-cols-2 gap-4 mb-6">
          {/* Scan Selection */}
          <div>
            <label className="text-sm font-medium text-text-secondary mb-2 block">
              {t('p16.selectScan')}
            </label>
            <CustomSelect
              value={selectedScanId ? String(selectedScanId) : ''}
              onChange={(val) => setSelectedScanId(val ? parseInt(val) : null)}
              options={[
                { value: '', label: t('p16.selectCompletedScan') },
                ...scanOptions,
              ]}
              disabled={scansLoading}
              className="w-full"
            />
          </div>

          {/* Export Type */}
          <div>
            <label className="text-sm font-medium text-text-secondary mb-2 block">
              {t('p16.exportFormat')}
            </label>
            <CustomSelect
              value={exportType}
              onChange={(val) => setExportType(val as 'json' | 'csv' | 'html')}
              options={[
                { value: 'json', label: 'JSON' },
                { value: 'csv', label: 'CSV' },
                { value: 'html', label: 'HTML' },
              ]}
              className="w-full"
            />
          </div>
        </div>

        {/* Export Button */}
        <div className="flex items-center gap-4">
          <Button
            onClick={handleExport}
            disabled={!selectedScanId || isExporting}
            className="min-w-[140px]"
          >
            {isExporting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                {t('p16.exporting')}
              </>
            ) : exportSuccess ? (
              <>
                <CheckCircle className="mr-2 h-4 w-4" />
                {t('p16.exportDone')}
              </>
            ) : (
              <>
                <Download className="mr-2 h-4 w-4" />
                {t('reports.generate')}
              </>
            )}
          </Button>

          {exportSuccess && (
            <span className="text-success text-sm font-mono">{t('p16.reportGenerated')}</span>
          )}
        </div>
      </Card>

      {/* Report Type Cards */}
      <div className="grid grid-cols-3 gap-6 mb-6">
        <Card
          className={`glass-panel transition-all cursor-pointer ${
            exportType === 'json' ? 'border-cyan shadow-glow-cyan' : 'hover:border-cyan/50'
          }`}
          onClick={() => setExportType('json')}
        >
          <div className="text-center py-8">
            <FileText className="h-12 w-12 text-success mx-auto mb-4" />
            <h3 className="text-success font-mono font-bold mb-2">{t('reports.json')}</h3>
            <p className="text-text-secondary text-sm mb-4">{t('reports.jsonDesc')}</p>
            <div className="text-xs text-text-tertiary font-mono">
              {t('p16.suitableForData')}
            </div>
          </div>
        </Card>

        <Card
          className={`glass-panel transition-all cursor-pointer ${
            exportType === 'csv' ? 'border-cyan shadow-glow-cyan' : 'hover:border-cyan/50'
          }`}
          onClick={() => setExportType('csv')}
        >
          <div className="text-center py-8">
            <FileText className="h-12 w-12 text-warning mx-auto mb-4" />
            <h3 className="text-warning font-mono font-bold mb-2">{t('reports.csv')}</h3>
            <p className="text-text-secondary text-sm mb-4">{t('reports.csvDesc')}</p>
            <div className="text-xs text-text-tertiary font-mono">
              {t('p16.suitableForExcel')}
            </div>
          </div>
        </Card>

        <Card
          className={`glass-panel transition-all cursor-pointer ${
            exportType === 'html' ? 'border-cyan shadow-glow-cyan' : 'hover:border-cyan/50'
          }`}
          onClick={() => setExportType('html')}
        >
          <div className="text-center py-8">
            <FileText className="h-12 w-12 text-cyan mx-auto mb-4" />
            <h3 className="text-cyan font-mono font-bold mb-2">{t('reports.html')}</h3>
            <p className="text-text-secondary text-sm mb-4">{t('reports.htmlDesc')}</p>
            <div className="text-xs text-text-tertiary font-mono">
              {t('p16.printableToPdf')}
            </div>
          </div>
        </Card>
      </div>

      {/* Recent Reports */}
      <Card className="glass-panel">
        <h3 className="text-cyan font-mono font-bold mb-4">{t('reports.recent')}</h3>
        {recentReports.length === 0 ? (
          <div className="text-center py-12 text-text-tertiary font-mono">
            <p>{t('reports.noReports')}</p>
            <p className="text-xs mt-2">{t('p16.reportHistory')}</p>
          </div>
        ) : (
          <div className="space-y-2">
            {recentReports.map((report) => (
              <div
                key={report.id}
                className="flex items-center justify-between py-3 px-4 rounded-lg bg-dark-800/50 border border-dark-700 hover:border-cyan/30 transition-colors"
              >
                <div className="flex items-center gap-4">
                  <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded uppercase ${
                    report.format === 'json' ? 'bg-success/20 text-success' :
                    report.format === 'csv' ? 'bg-warning/20 text-warning' :
                    'bg-cyan/20 text-cyan'
                  }`}>
                    {report.format}
                  </span>
                  <div>
                    <p className="text-sm text-text-primary font-mono">
                      #{String(report.scanId).padStart(4, '0')} - {report.scanName}
                    </p>
                    <p className="text-xs text-text-tertiary">
                      {new Date(report.createdAt).toLocaleString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleReExport(report)}
                    className="p-1.5 text-text-tertiary hover:text-cyan transition-colors"
                    title={t('p16.redownload')}
                  >
                    <RotateCw className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => removeReport(report.id)}
                    className="p-1.5 text-text-tertiary hover:text-red-400 transition-colors"
                    title={t('p16.deleteRecord')}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
