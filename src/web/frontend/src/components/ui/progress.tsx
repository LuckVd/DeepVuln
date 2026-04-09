import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/shared/utils/cn';

/**
 * Progress - LED-style segmented progress bar
 */
const progressVariants = cva(
  'relative h-3 w-full overflow-hidden rounded-full bg-background-tertiary border border-border',
  {
    variants: {
      variant: {
        default: '',
        cyan: 'border-cyan/30',
        magenta: 'border-magenta/30',
        green: 'border-success/30',
        warning: 'border-warning/30',
        critical: 'border-critical/30',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
);

export interface ProgressProps
  extends React.ComponentPropsWithoutRef<'div'>,
    VariantProps<typeof progressVariants> {
  value?: number;
  max?: number;
}

const Progress = React.forwardRef<HTMLDivElement, ProgressProps>(
  ({ className, value = 0, max = 100, variant, ...props }, ref) => {
    const percentage = Math.min(Math.max((value / max) * 100, 0), 100);

    // Determine color based on variant
    const getColorClass = () => {
      switch (variant) {
        case 'cyan': return 'bg-gradient-to-r from-cyan to-cyan/80 shadow-glow-cyan';
        case 'magenta': return 'bg-gradient-to-r from-magenta to-magenta/80 shadow-glow-magenta';
        case 'green': return 'bg-gradient-to-r from-success to-success/80 shadow-glow-green';
        case 'warning': return 'bg-gradient-to-r from-warning to-warning/80';
        case 'critical': return 'bg-gradient-to-r from-critical to-critical/80 shadow-glow-critical';
        default: return 'bg-gradient-to-r from-cyan to-magenta';
      }
    };

    return (
      <div
        ref={ref}
        className={cn(progressVariants({ variant }), className)}
        {...props}
      >
        {/* LED segments background */}
        <div className="absolute inset-0 flex">
          {Array.from({ length: 20 }).map((_, i) => (
            <div
              key={i}
              className="flex-1 border-r border-border/50 last:border-r-0"
            />
          ))}
        </div>
        {/* Animated progress fill */}
        <div
          className={cn(
            'h-full transition-all duration-300 relative',
            getColorClass()
          )}
          style={{ width: `${percentage}%` }}
        >
          {/* LED segments overlay on fill */}
          <div className="absolute inset-0 flex">
            {Array.from({ length: 20 }).map((_, i) => (
              <div
                key={i}
                className="flex-1 border-r border-white/20 last:border-r-0"
              />
            ))}
          </div>
        </div>
      </div>
    );
  }
);
Progress.displayName = 'Progress';

export { Progress, progressVariants };
