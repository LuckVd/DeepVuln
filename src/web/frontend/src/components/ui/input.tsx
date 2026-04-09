import * as React from 'react';
import { cn } from '@/shared/utils/cn';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, label, error, ...props }, ref) => {
    return (
      <div className="space-y-2">
        {label && (
          <label className="text-sm font-medium text-text-secondary font-sans">
            {label}
          </label>
        )}
        <input
          type={type}
          ref={ref}
          className={cn(
            'flex h-11 w-full rounded-md border-2 border-border bg-background-secondary px-4 py-2',
            'text-text-primary font-mono text-sm placeholder:text-text-tertiary',
            'focus:outline-none focus:border-cyan focus:shadow-glow-cyan',
            'transition-all duration-200',
            'disabled:cursor-not-allowed disabled:opacity-50',
            error && 'border-critical focus:border-critical focus:shadow-glow-critical',
            className
          )}
          {...props}
        />
        {error && <p className="text-xs text-critical font-mono">{error}</p>}
      </div>
    );
  }
);
Input.displayName = 'Input';

export { Input };
