import { useState } from 'react';
import { Card, Button, CustomSelect, Input, Alert } from '@/components/ui';
import { Download, FileText, Loader2, CheckCircle } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { reportsApi } from '@/api/reports';
import { useScans } from '@/hooks/useApi';

/**
 * Reports page with export functionality
 */
export default function ReportsPage() {
  const { t } = useLanguage();
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [exportType, setExportType] = useState<'json' | 'csv' | 'pdf'>('json');
  const [isExporting, setIsExporting] = useState(false);
  const [exportSuccess, setExportSuccess] = useState(false);

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

        case 'pdf':
          const pdfData = await reportsApi.exportPdf(selectedScanId);
          reportsApi.downloadBlob(pdfData, `${filename}.pdf`);
          break;
      }

      setExportSuccess(true);
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
      <Card className="glass-panel mb-6">
        <h3 className="text-cyan font-mono font-bold mb-4">{t('reports.generate')}</h3>

        <div className="grid grid-cols-2 gap-4 mb-6">
          {/* Scan Selection */}
          <div>
            <label className="text-sm font-medium text-text-secondary mb-2 block">
              选择扫描
            </label>
            <CustomSelect
              value={selectedScanId ? String(selectedScanId) : ''}
              onChange={(val) => setSelectedScanId(val ? parseInt(val) : null)}
              options={[
                { value: '', label: '请选择已完成的扫描...' },
                ...scanOptions,
              ]}
              disabled={scansLoading}
              className="w-full"
            />
          </div>

          {/* Export Type */}
          <div>
            <label className="text-sm font-medium text-text-secondary mb-2 block">
              导出格式
            </label>
            <CustomSelect
              value={exportType}
              onChange={(val) => setExportType(val as 'json' | 'csv' | 'pdf')}
              options={[
                { value: 'json', label: 'JSON' },
                { value: 'csv', label: 'CSV' },
                { value: 'pdf', label: 'PDF' },
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
                导出中...
              </>
            ) : exportSuccess ? (
              <>
                <CheckCircle className="mr-2 h-4 w-4" />
                完成
              </>
            ) : (
              <>
                <Download className="mr-2 h-4 w-4" />
                {t('reports.generate')}
              </>
            )}
          </Button>

          {exportSuccess && (
            <span className="text-success text-sm font-mono">报告已生成</span>
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
              适合数据分析和机器处理
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
              适合 Excel 和电子表格
            </div>
          </div>
        </Card>

        <Card
          className={`glass-panel transition-all cursor-pointer ${
            exportType === 'pdf' ? 'border-cyan shadow-glow-cyan' : 'hover:border-cyan/50'
          }`}
          onClick={() => setExportType('pdf')}
        >
          <div className="text-center py-8">
            <FileText className="h-12 w-12 text-cyan mx-auto mb-4" />
            <h3 className="text-cyan font-mono font-bold mb-2">{t('reports.pdf')}</h3>
            <p className="text-text-secondary text-sm mb-4">{t('reports.pdfDesc')}</p>
            <div className="text-xs text-text-tertiary font-mono">
              适合打印和分享
            </div>
          </div>
        </Card>
      </div>

      {/* Recent Reports */}
      <Card className="glass-panel">
        <h3 className="text-cyan font-mono font-bold mb-4">{t('reports.recent')}</h3>
        <div className="text-center py-12 text-text-tertiary font-mono">
          <p>{t('reports.noReports')}</p>
          <p className="text-xs mt-2">生成报告后将在此显示历史记录</p>
        </div>
      </Card>
    </div>
  );
}
