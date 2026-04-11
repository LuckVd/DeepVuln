import * as React from 'react';
import { cn } from '@/shared/utils/cn';

/**
 * Switch - Cyberpunk styled toggle switch
 */

export interface SwitchProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: string;
  description?: string;
}

const Switch = React.forwardRef<HTMLInputElement, SwitchProps>(
  ({ className, label, description, checked, onChange, disabled, ...props }, ref) => {
    const id = React.useId();

    return (
      <div className="flex items-start gap-3">
        <div className="relative flex items-center">
          <input
            type="checkbox"
            ref={ref}
            id={id}
            checked={checked}
            onChange={onChange}
            disabled={disabled}
            className="peer sr-only"
            {...props}
          />
          <button
            type="button"
            onClick={() => {
              if (!disabled && onChange) {
                const event = { target: { checked: !checked } } as React.ChangeEvent<HTMLInputElement>;
                onChange(event);
              }
            }}
            disabled={disabled}
            className={cn(
              'relative h-6 w-11 rounded-full transition-all duration-300',
              'before:content-[""] before:absolute before:top-[2px] before:left-[2px]',
              'before:h-5 before:w-5 before:rounded-full before:transition-all before:duration-300',
              'peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-cyan peer-focus:ring-offset-2',
              disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer',
              checked
                ? 'bg-gradient-to-r from-cyan to-magenta before:translate-x-full before:shadow-glow-cyan'
                : 'bg-border before:translate-x-0'
            )}
            aria-pressed={checked}
          />
        </div>
        {(label || description) && (
          <div className="flex flex-col gap-1">
            {label && (
              <label
                htmlFor={id}
                className={cn(
                  'text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70',
                  checked ? 'text-cyan' : 'text-text-secondary'
                )}
              >
                {label}
              </label>
            )}
            {description && (
              <p className="text-xs text-text-dim">{description}</p>
            )}
          </div>
        )}
      </div>
    );
  }
);

Switch.displayName = 'Switch';

export { Switch };
