import * as React from 'react';
import { cn } from '@/shared/utils/cn';

export interface StatisticProps extends React.HTMLAttributes<HTMLDivElement> {
  title: string;
  value: number | string;
  suffix?: string;
  prefix?: string;
  valueClassName?: string;
}

const Statistic = React.forwardRef<HTMLDivElement, StatisticProps>(
  ({ className, title, value, suffix, prefix, valueClassName, ...props }, ref) => {
    const displayValue = typeof value === 'number' ? value.toLocaleString() : value;

    return (
      <div
        ref={ref}
        className={cn('glass-panel rounded-lg p-4', className)}
        {...props}
      >
        <div className="text-text-secondary font-mono text-xs uppercase tracking-wider mb-2">
          {title}
        </div>
        <div className="flex items-baseline gap-1">
          {prefix && <span className="text-text-tertiary font-mono text-sm">{prefix}</span>}
          <span className={cn('text-2xl font-bold font-mono text-cyan', valueClassName)}>
            {displayValue}
          </span>
          {suffix && <span className="text-text-tertiary font-mono text-sm">{suffix}</span>}
        </div>
      </div>
    );
  }
);

Statistic.displayName = 'Statistic';

export { Statistic };
