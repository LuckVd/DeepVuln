import * as React from 'react';
import { cn } from '@/shared/utils/cn';

export interface DescriptionItem {
  label: string;
  value: React.ReactNode;
  span?: number;
}

export interface DescriptionsProps {
  items: DescriptionItem[];
  columns?: number;
  className?: string;
  bordered?: boolean;
}

export function Descriptions({ items, columns = 3, className, bordered = false }: DescriptionsProps) {
  const gridStyle = {
    gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))`,
  };

  return (
    <div
      className={cn(
        'space-y-2 font-mono text-sm',
        bordered && 'border-2 border-border rounded-lg overflow-hidden',
        className
      )}
    >
      {items.map((item, index) => {
        const colSpan = item.span || 1;
        const isLastInRow = (index + colSpan) % columns === 0;

        return (
          <div
            key={index}
            className={cn(
              'grid gap-2 p-3',
              bordered && 'border-b border-border last:border-b-0',
              !isLastInRow && 'border-r-0'
            )}
            style={{
              ...gridStyle,
              gridColumn: `span ${Math.min(colSpan, columns)}`,
            }}
          >
            <div className="text-text-secondary font-medium">{item.label}</div>
            <div className="text-text-primary">{item.value}</div>
          </div>
        );
      })}
    </div>
  );
}
