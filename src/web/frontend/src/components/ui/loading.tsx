import { cn } from '@/shared/utils/cn';

export interface LoadingProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function Loading({ size = 'md', className }: LoadingProps) {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
  };

  return (
    <div className={cn('flex items-center justify-center', className)}>
      <div
        className={cn(
          'border-2 border-cyan/30 border-t-cyan rounded-full animate-spin',
          sizeClasses[size]
        )}
      />
    </div>
  );
}

export function LoadingPage({ message = 'LOADING...' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-32 gap-4">
      <Loading size="lg" />
      <p className="text-cyan font-mono animate-pulse">{message}</p>
    </div>
  );
}

export function LoadingInline({ message }: { message?: string }) {
  return (
    <div className="flex items-center gap-3 text-text-secondary font-mono">
      <Loading size="sm" />
      {message && <span className="text-sm">{message}</span>}
    </div>
  );
}
