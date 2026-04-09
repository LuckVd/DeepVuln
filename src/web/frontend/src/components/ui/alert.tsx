import * as React from 'react';
import { AlertTriangle, Info, CheckCircle, XCircle, X } from 'lucide-react';
import { cn } from '@/shared/utils/cn';

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'info' | 'warning' | 'critical' | 'success';
  title?: string;
  icon?: boolean;
}

const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
  ({ className, variant = 'info', title, icon = true, children, ...props }, ref) => {
    const variantStyles = {
      info: 'border-cyan/30 bg-cyan/10 text-cyan',
      warning: 'border-warning/30 bg-warning/10 text-warning',
      critical: 'border-critical/30 bg-critical/10 text-critical',
      success: 'border-success/30 bg-success/10 text-success',
    };

    const icons = {
      info: <Info className="h-5 w-5" />,
      warning: <AlertTriangle className="h-5 w-5" />,
      critical: <XCircle className="h-5 w-5" />,
      success: <CheckCircle className="h-5 w-5" />,
    };

    return (
      <div
        ref={ref}
        className={cn(
          'relative rounded-lg border-2 p-4 font-mono text-sm',
          variantStyles[variant],
          className
        )}
        {...props}
      >
        <div className="flex items-start gap-3">
          {icon && <span className="flex-shrink-0 mt-0.5">{icons[variant]}</span>}
          <div className="flex-1 space-y-1">
            {title && <p className="font-bold text-base">{title}</p>}
            <div className="text-text-secondary">{children}</div>
          </div>
        </div>
      </div>
    );
  }
);

Alert.displayName = 'Alert';

export { Alert };
