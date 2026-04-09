import { Card, Button } from '@/components/ui';
import { Download, FileText } from 'lucide-react';

export default function ReportsPage() {
  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-text-primary font-mono tracking-wider">
            REPORTS
          </h1>
          <span className="text-cyan">//</span>
          <span className="text-cyan font-mono">EXPORTS</span>
        </div>
        <p className="text-text-secondary font-sans">Generate and download scan reports</p>
      </div>

      {/* Report Types */}
      <div className="grid grid-cols-3 gap-6">
        <Card className="glass-panel hover:border-cyan/50 transition-colors cursor-pointer">
          <div className="text-center py-8">
            <FileText className="h-12 w-12 text-cyan mx-auto mb-4" />
            <h3 className="text-cyan font-mono font-bold mb-2">PDF REPORT</h3>
            <p className="text-text-secondary text-sm mb-4">Detailed security assessment</p>
            <Button variant="outline" size="sm">
              <Download className="mr-2 h-4 w-4" />
              GENERATE
            </Button>
          </div>
        </Card>
        <Card className="glass-panel hover:border-cyan/50 transition-colors cursor-pointer">
          <div className="text-center py-8">
            <FileText className="h-12 w-12 text-success mx-auto mb-4" />
            <h3 className="text-success font-mono font-bold mb-2">JSON EXPORT</h3>
            <p className="text-text-secondary text-sm mb-4">Machine-readable format</p>
            <Button variant="outline" size="sm">
              <Download className="mr-2 h-4 w-4" />
              EXPORT
            </Button>
          </div>
        </Card>
        <Card className="glass-panel hover:border-cyan/50 transition-colors cursor-pointer">
          <div className="text-center py-8">
            <FileText className="h-12 w-12 text-warning mx-auto mb-4" />
            <h3 className="text-warning font-mono font-bold mb-2">CSV SUMMARY</h3>
            <p className="text-text-secondary text-sm mb-4">Spreadsheet compatible</p>
            <Button variant="outline" size="sm">
              <Download className="mr-2 h-4 w-4" />
              DOWNLOAD
            </Button>
          </div>
        </Card>
      </div>

      {/* Recent Reports */}
      <Card className="glass-panel mt-6">
        <h3 className="text-cyan font-mono font-bold mb-4">RECENT REPORTS</h3>
        <div className="text-center py-12 text-text-tertiary font-mono">
          <p>No reports generated yet</p>
        </div>
      </Card>
    </div>
  );
}
