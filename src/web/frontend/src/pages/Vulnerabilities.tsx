import { Card, Badge, Input, CustomSelect, Button } from '@/components/ui';
import { Search, Filter } from 'lucide-react';

export default function VulnerabilitiesPage() {
  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-text-primary font-mono tracking-wider">
            VULNERABILITIES
          </h1>
          <span className="text-cyan">//</span>
          <span className="text-cyan font-mono">GLOBAL VIEW</span>
        </div>
        <p className="text-text-secondary font-sans">All detected vulnerabilities across all scans</p>
      </div>

      {/* Toolbar */}
      <Card className="glass-panel mb-6">
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <Input
              placeholder="Search vulnerabilities..."
              className="font-mono"
            />
          </div>
          <CustomSelect
            value=""
            onChange={() => {}}
            options={[
              { value: '', label: 'ALL SEVERITIES' },
              { value: 'critical', label: 'CRITICAL' },
              { value: 'high', label: 'HIGH' },
              { value: 'medium', label: 'MEDIUM' },
              { value: 'low', label: 'LOW' },
            ]}
            className="w-48"
          />
          <Button variant="outline" size="sm">
            <Filter className="mr-2 h-4 w-4" />
            FILTERS
          </Button>
        </div>
      </Card>

      {/* Placeholder */}
      <Card className="glass-panel">
        <div className="text-center py-16 text-text-tertiary font-mono">
          <div className="mb-4 text-6xl opacity-20">🛡️</div>
          <p>VULNERABILITIES CONTENT</p>
          <p className="text-sm mt-2">Coming soon...</p>
        </div>
      </Card>
    </div>
  );
}
