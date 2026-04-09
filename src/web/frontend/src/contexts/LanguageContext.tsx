import { createContext, useContext, useState, useEffect, ReactNode, useMemo } from 'react';
import { translations, Language } from '@/i18n/translations';

interface LanguageContextType {
  language: Language;
  setLanguage: (lang: Language) => void;
  t: (key: string) => string;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

const LANGUAGE_STORAGE_KEY = 'deepvuln_language';

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<Language>(() => {
    // Get from localStorage or default to 'zh'
    const stored = localStorage.getItem(LANGUAGE_STORAGE_KEY);
    return (stored === 'zh' || stored === 'en') ? stored : 'zh';
  });

  useEffect(() => {
    // Save to localStorage when language changes
    localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
    // Update HTML lang attribute
    document.documentElement.lang = language;
  }, [language]);

  const setLanguage = (lang: Language) => {
    setLanguageState(lang);
  };

  // Translation function with direct key lookup
  const t = useMemo(() => (key: string): string => {
    return translations[language]?.[key as keyof typeof translations.zh] || key;
  }, [language]);

  const contextValue = useMemo(() => ({
    language,
    setLanguage,
    t
  }), [language, setLanguage, t]);

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
