import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/shared/utils/cn';

/**
 * Button - Cyberpunk styled buttons with gradient and glow effects
 */
const buttonVariants = cva(
  'inline-flex items-center justify-center rounded-md text-sm font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan focus-visible:ring-offset-2 focus-visible:ring-offset-background-primary disabled:pointer-events-none disabled:opacity-50 disabled:cursor-not-allowed min-h-[44px] px-4',
  {
    variants: {
      variant: {
        default: 'bg-gradient-to-r from-cyan to-magenta text-white hover:shadow-glow-cyan hover:scale-105 active:scale-95',
        destructive: 'bg-critical text-white hover:shadow-glow-critical hover:scale-105',
        outline: 'border-2 border-cyan/30 text-cyan hover:bg-cyan/10 hover:border-cyan hover:shadow-glow-cyan',
        secondary: 'bg-background-tertiary text-text-primary border border-border hover:border-cyan/50',
        ghost: 'text-text-secondary hover:text-cyan hover:bg-cyan/10',
        link: 'text-cyan underline-offset-4 hover:underline',
        success: 'bg-success text-black hover:shadow-glow-green hover:scale-105 font-semibold',
      },
      size: {
        default: 'h-11 px-6',
        sm: 'h-9 px-4 text-xs',
        lg: 'h-14 px-8 text-base',
        icon: 'h-11 w-11',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => {
    return (
      <button
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = 'Button';

export { Button, buttonVariants };
