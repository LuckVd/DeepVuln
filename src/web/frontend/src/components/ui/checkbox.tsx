import { forwardRef } from 'react';
import { cn } from '@/shared/utils/cn';

export interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: string;
  description?: string;
}

const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, label, description, id, ...props }, ref) => {
    const checkboxId = id || `checkbox-${Math.random().toString(36).substr(2, 9)}`;

    return (
      <div className="flex items-start gap-3">
        <input
          ref={ref}
          type="checkbox"
          id={checkboxId}
          className={cn(
            'mt-0.5 h-4 w-4 rounded border-border text-cyan focus:ring-2 focus:ring-cyan/50 focus:ring-offset-0 cursor-pointer',
            'appearance-none checked:bg-cyan checked:border-cyan',
            'relative transition-all duration-200',
            'before:content-[""] before:absolute before:top-1/2 before:left-1/2 before:-translate-x-1/2 before:-translate-y-1/2',
            'before:w-2 before:h-3.5 before:border-r-2 before:border-b-2 before:border-white before:opacity-0',
            'checked:before:opacity-100 before:rotate-45 before:-translate-y-0.5',
            className
          )}
          {...props}
        />
        {(label || description) && (
          <div className="flex flex-col gap-1">
            {label && (
              <label
                htmlFor={checkboxId}
                className="text-sm font-medium text-text-primary cursor-pointer select-none"
              >
                {label}
              </label>
            )}
            {description && (
              <p className="text-xs text-text-secondary">{description}</p>
            )}
          </div>
        )}
      </div>
    );
  }
);

Checkbox.displayName = 'Checkbox';

export { Checkbox };
