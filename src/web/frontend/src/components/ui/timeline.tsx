import * as React from 'react';
import { Check, Circle, Loader2, X, Minus } from 'lucide-react';
import { cn } from '@/shared/utils/cn';

export interface TimelineItem {
  icon?: React.ReactNode;
  title: React.ReactNode;
  description?: React.ReactNode;
  status?: 'completed' | 'running' | 'pending' | 'failed';
  progress?: number;
}

export interface TimelineProps {
  items: TimelineItem[];
  className?: string;
}

const statusIcons = {
  completed: <Check className="h-4 w-4 text-success" />,
  running: <Loader2 className="h-4 w-4 text-cyan animate-spin" />,
  pending: <Circle className="h-4 w-4 text-text-tertiary" />,
  failed: <X className="h-4 w-4 text-critical" />,
};

export function Timeline({ items, className }: TimelineProps) {
  return (
    <div className={cn('space-y-4', className)}>
      {items.map((item, index) => (
        <div key={index} className="relative flex gap-4">
          {/* Line (except for last item) */}
          {index < items.length - 1 && (
            <div className="absolute left-[7px] top-8 bottom-[-16px] w-0.5 bg-border" />
          )}

          {/* Icon */}
          <div className="relative z-10 flex-shrink-0">
            <div
              className={cn(
                'w-8 h-8 rounded-full flex items-center justify-center border-2',
                item.status === 'completed' && 'border-success bg-success/10',
                item.status === 'running' && 'border-cyan bg-cyan/10 shadow-glow-cyan',
                item.status === 'pending' && 'border-text-tertiary bg-background-secondary',
                item.status === 'failed' && 'border-critical bg-critical/10'
              )}
            >
              {item.icon || statusIcons[item.status || 'pending']}
            </div>
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0 pb-4">
            <div className="flex items-center justify-between gap-4 mb-1">
              <div className="font-medium text-text-primary">{item.title}</div>
              {item.status && (
                <span
                  className={cn(
                    'text-xs font-mono px-2 py-0.5 rounded',
                    item.status === 'completed' && 'text-success bg-success/10',
                    item.status === 'running' && 'text-cyan bg-cyan/10',
                    item.status === 'pending' && 'text-text-tertiary bg-background-tertiary',
                    item.status === 'failed' && 'text-critical bg-critical/10'
                  )}
                >
                  {item.status.toUpperCase()}
                </span>
              )}
            </div>
            {item.description && (
              <div className="text-text-secondary text-sm">{item.description}</div>
            )}
            {item.progress !== undefined && item.status === 'running' && (
              <div className="mt-2">
                <Progress value={item.progress} variant="cyan" className="h-1" />
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

// Import Progress to avoid circular dependency
import { Progress } from './progress';
