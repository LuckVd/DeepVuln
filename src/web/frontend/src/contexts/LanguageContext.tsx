import { createContext, useContext, useMemo, ReactNode } from 'react';
import { translations } from '@/i18n/translations';

// 固定使用中文
const LANGUAGE = 'zh' as const;

interface LanguageContextType {
  language: typeof LANGUAGE;
  t: (key: string) => string;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

export function LanguageProvider({ children }: { children: ReactNode }) {
  // 设置 HTML lang 属性为中文
  useMemo(() => {
    document.documentElement.lang = LANGUAGE;
  }, []);

  // 翻译函数，仅支持中文
  const t = useMemo(() => (key: string): string => {
    return translations[LANGUAGE]?.[key as keyof typeof translations.zh] || key;
  }, []);

  const contextValue = useMemo(() => ({
    language: LANGUAGE,
    t
  }), [t]);

  return (
    <LanguageContext.Provider value={contextValue}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useLanguage must be used within LanguageProvider');
  }
  return context;
}
