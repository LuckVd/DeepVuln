import * as React from 'react';
import { cn } from '@/shared/utils/cn';

interface Tab {
  key: string;
  label: string;
  children: React.ReactNode;
}

export interface TabsProps {
  items: Tab[];
  defaultActiveKey?: string;
  className?: string;
}

export function Tabs({ items, defaultActiveKey, className }: TabsProps) {
  const [activeKey, setActiveKey] = React.useState(defaultActiveKey || items[0]?.key);

  const activeTab = items.find((tab) => tab.key === activeKey);

  return (
    <div className={cn('w-full', className)}>
      {/* Tab Headers */}
      <div className="flex items-center gap-1 border-b-2 border-border mb-4">
        {items.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveKey(tab.key)}
            className={cn(
              'px-4 py-2 font-mono text-sm transition-all duration-200 border-b-2 -mb-0.5',
              activeKey === tab.key
                ? 'text-cyan border-cyan bg-cyan/10'
                : 'text-text-secondary border-transparent hover:text-cyan hover:bg-cyan/5'
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="mt-4">
        {activeTab?.children}
      </div>
    </div>
  );
}
