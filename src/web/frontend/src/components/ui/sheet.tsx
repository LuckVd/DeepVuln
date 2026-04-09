import * as React from 'react';
import { X } from 'lucide-react';
import { cn } from '@/shared/utils/cn';

export interface SheetProps {
  open?: boolean;
  onClose?: () => void;
  title?: React.ReactNode;
  children: React.ReactNode;
  width?: string | number;
}

export function Sheet({ open = false, onClose, title, children, width = 560 }: SheetProps) {
  React.useEffect(() => {
    if (open) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [open]);

  if (!open) return null;

  return (
    <>
      {/* Overlay */}
      <div
        className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Sheet */}
      <div
        className={cn(
          'fixed right-0 top-0 z-50 h-screen bg-background-secondary border-l-2 border-border shadow-glow-cyan',
          'transition-transform duration-300 ease-in-out'
        )}
        style={{ width: typeof width === 'number' ? `${width}px` : width }}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b-2 border-border p-6">
          <h2 className="text-lg font-bold font-mono text-cyan">{title}</h2>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-cyan/10 text-cyan transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto" style={{ height: 'calc(100vh - 73px)' }}>
          {children}
        </div>
      </div>
    </>
  );
}
