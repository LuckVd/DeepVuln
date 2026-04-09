import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/shared/utils/cn';

/**
 * Badge - Vulnerability and status badges with glow effects
 */
const badgeVariants = cva(
  'inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold min-h-[28px] transition-all duration-200',
  {
    variants: {
      variant: {
        default: 'bg-cyan/20 text-cyan border border-cyan/30',
        pending: 'bg-warning/20 text-warning border border-warning/30 animate-pulse-slow',
        running: 'bg-cyan/20 text-cyan border border-cyan/30',
        completed: 'bg-success/20 text-success border border-success/30 shadow-[0_0_10px_rgba(57,255,20,0.3)]',
        failed: 'bg-critical/20 text-critical border border-critical/30 shadow-[0_0_10px_rgba(255,0,60,0.3)]',
        critical: 'bg-critical/20 text-critical border border-critical/30 shadow-glow-critical',
        high: 'bg-warning/40 text-warning border border-warning/50',
        medium: 'bg-cyan/20 text-cyan border border-cyan/30',
        low: 'bg-success/20 text-success border border-success/30',
        info: 'bg-background-tertiary text-text-tertiary border border-border',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
