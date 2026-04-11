import * as React from 'react';
import { Check, ChevronDown } from 'lucide-react';
import { cn } from '@/shared/utils/cn';

export interface CustomSelectProps {
  label?: string;
  error?: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
  className?: string;
  disabled?: boolean;
}

export function CustomSelect({
  label,
  error,
  value,
  onChange,
  options,
  className,
  disabled = false,
}: CustomSelectProps) {
  const [isOpen, setIsOpen] = React.useState(false);
  const selectRef = React.useRef<HTMLDivElement>(null);

  const selectedOption = options.find((opt) => opt.value === value);

  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (selectRef.current && !selectRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  return (
    <div className={cn('space-y-2', className)}>
      {label && (
        <label className="text-sm font-medium text-text-secondary font-sans">
          {label}
        </label>
      )}
      <div ref={selectRef} className="relative">
        <button
          type="button"
          onClick={() => !disabled && setIsOpen(!isOpen)}
          disabled={disabled}
          className={cn(
            'flex h-11 w-full items-center justify-between rounded-md border-2 border-border bg-background-secondary px-4 py-2',
            'text-text-primary font-mono text-sm text-left',
            'focus:outline-none focus:border-cyan focus:shadow-glow-cyan',
            'transition-all duration-200',
            disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer',
            error && 'border-critical focus:border-critical focus:shadow-glow-critical'
          )}
        >
          <span className={cn(!selectedOption && 'text-text-tertiary')}>
            {selectedOption?.label || options[0]?.label}
          </span>
          <ChevronDown
            className={cn(
              'h-4 w-4 text-cyan transition-transform duration-200 shrink-0 ml-2',
              isOpen && 'transform rotate-180'
            )}
          />
        </button>

        {isOpen && (
          <div className="absolute z-50 mt-1 w-full rounded-md border-2 border-border bg-background-secondary shadow-glow-cyan max-h-60 overflow-auto">
            <div className="py-1">
              {options.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => {
                    onChange(option.value);
                    setIsOpen(false);
                  }}
                  className={cn(
                    'flex w-full items-center justify-between px-4 py-2.5 font-mono text-sm text-left transition-colors',
                    'hover:bg-cyan/10 hover:text-cyan',
                    option.value === value
                      ? 'bg-cyan/20 text-cyan font-medium'
                      : 'text-text-primary'
                  )}
                >
                  <span>{option.label}</span>
                  {option.value === value && (
                    <Check className="h-4 w-4 text-cyan shrink-0 ml-2" />
                  )}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
      {error && <p className="text-xs text-critical font-mono">{error}</p>}
    </div>
  );
}
