import { useLanguage } from '@/contexts/LanguageContext';
import { Globe } from 'lucide-react';
import { cn } from '@/shared/utils/cn';

export function LanguageSwitcher({ className }: { className?: string }) {
  const { language, setLanguage } = useLanguage();

  return (
    <div className={cn('flex items-center gap-2', className)}>
      <Globe className="h-5 w-5 text-cyan" />
      <div className="flex bg-background-tertiary border border-border rounded-md p-1">
        <button
          onClick={() => setLanguage('zh')}
          className={cn(
            'px-3 py-1.5 rounded text-sm font-mono transition-all',
            language === 'zh'
              ? 'bg-cyan text-black font-semibold shadow-glow-cyan'
              : 'text-text-secondary hover:text-cyan'
          )}
        >
          中文
        </button>
        <button
          onClick={() => setLanguage('en')}
          className={cn(
            'px-3 py-1.5 rounded text-sm font-mono transition-all',
            language === 'en'
              ? 'bg-cyan text-black font-semibold shadow-glow-cyan'
              : 'text-text-secondary hover:text-cyan'
          )}
        >
          EN
        </button>
      </div>
    </div>
  );
}
