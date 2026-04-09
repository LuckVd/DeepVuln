import * as React from 'react';
import { cn } from '@/shared/utils/cn';

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  error?: string;
  options: Array<{ value: string; label: string }>;
}

const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, label, error, options, ...props }, ref) => {
    return (
      <div className="space-y-2">
        {label && (
          <label className="text-sm font-medium text-text-secondary font-sans">
            {label}
          </label>
        )}
        <select
          ref={ref}
          className={cn(
            'flex h-11 w-full rounded-md border-2 border-border bg-background-secondary px-4 py-2',
            'text-text-primary font-mono text-sm',
            'focus:outline-none focus:border-cyan focus:shadow-glow-cyan',
            'transition-all duration-200 appearance-none cursor-pointer',
            'disabled:cursor-not-allowed disabled:opacity-50',
            'bg-[url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' fill=\'none\' viewBox=\'0 0 20 20\'%3E%3Cpath stroke=\'%2300f0ff\' stroke-linecap=\'round\' stroke-linejoin=\'round\' stroke-width=\'1.5\' d=\'M6 8l4 4 4-4\'/%3E%3C/svg%3E")] bg-[length:1.5rem_1.5rem] bg-[right_0.5rem_center] bg-no-repeat pr-10',
            error && 'border-critical focus:border-critical focus:shadow-glow-critical',
            className
          )}
          {...props}
        >
          {options.map((option) => (
            <option
              key={option.value}
              value={option.value}
              className="bg-background-secondary text-text-primary"
            >
              {option.label}
            </option>
          ))}
        </select>
        {error && <p className="text-xs text-critical font-mono">{error}</p>}
      </div>
    );
  }
);
Select.displayName = 'Select';

export { Select };
