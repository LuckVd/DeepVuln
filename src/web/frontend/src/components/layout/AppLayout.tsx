import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Scan as ScanIcon,
  ShieldAlert,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { cn } from '@/shared/utils/cn';
import { useState, useEffect, useRef } from 'react';
import { useLanguage } from '@/contexts/LanguageContext';

export default function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [uptime, setUptime] = useState('--:--:--');
  const { t } = useLanguage();

  // Update uptime every second
  useEffect(() => {
    const updateUptime = () => {
      const now = new Date();
      const hours = String(now.getHours()).padStart(2, '0');
      const minutes = String(now.getMinutes()).padStart(2, '0');
      const seconds = String(now.getSeconds()).padStart(2, '0');
      setUptime(`${hours}:${minutes}:${seconds}`);
    };

    updateUptime();
    const interval = setInterval(updateUptime, 1000);
    return () => clearInterval(interval);
  }, []);

  const menuItems = [
    { path: '/dashboard', label: t('nav.dashboard'), icon: LayoutDashboard },
    { path: '/scans', label: t('nav.scans'), icon: ScanIcon },
    { path: '/vulnerabilities', label: t('nav.vulnerabilities'), icon: ShieldAlert },
    { path: '/reports', label: t('nav.reports'), icon: FileText },
    { path: '/settings', label: t('nav.settings'), icon: Settings },
  ];

  const isActive = (path: string) => {
    return location.pathname.startsWith(path);
  };

  return (
    <div className="flex min-h-screen bg-background-primary">
      {/* Sidebar */}
      <aside
        className={cn(
          'fixed left-0 top-0 z-40 h-screen border-r border-border bg-background-secondary transition-all duration-300',
          isCollapsed ? 'w-16' : 'w-64'
        )}
      >
        {/* Header */}
        <div className="flex h-16 items-center justify-between border-b border-border px-4">
          {!isCollapsed && (
            <h1 className="text-xl font-bold text-cyan font-mono tracking-wider drop-shadow-[0_0_10px_rgba(0,240,255,0.5)]">
              &lt;DEEPVULN/&gt;
            </h1>
          )}
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="p-1 rounded hover:bg-cyan/10 text-cyan transition-colors"
          >
            {isCollapsed ? <ChevronRight className="h-5 w-5" /> : <ChevronLeft className="h-5 w-5" />}
          </button>
        </div>

        {/* Navigation */}
        <nav className="space-y-1 p-3">
          {menuItems.map((item) => (
            <button
              key={item.path}
              onClick={() => navigate(item.path)}
              className={cn(
                'flex w-full items-center gap-3 rounded-md px-3 py-3 transition-all duration-200',
                'font-mono text-sm font-medium',
                isActive(item.path)
                  ? 'bg-cyan/20 text-cyan border border-cyan/30 shadow-glow-cyan'
                  : 'text-text-secondary hover:bg-cyan/10 hover:text-cyan',
                isCollapsed && 'justify-center px-3'
              )}
            >
              <item.icon className="h-5 w-5 flex-shrink-0" />
              {!isCollapsed && <span>{item.label}</span>}
            </button>
          ))}
        </nav>

        {/* Footer */}
        {!isCollapsed && (
          <div className="absolute bottom-0 left-0 right-0 p-3 border-t border-border">
            <div className="rounded bg-background-tertiary p-3 font-mono text-xs">
              <div className="flex items-center gap-2 text-success mb-1">
                <span className="w-2 h-2 rounded-full bg-success animate-pulse"></span>
                <span>{t('layout.systemReady')}</span>
              </div>
              <div className="text-text-tertiary">
                v2.0.4 | {t('layout.uptime')}: <span className="text-cyan">{uptime}</span>
              </div>
            </div>
          </div>
        )}
      </aside>

      {/* Main Content */}
      <main
        className={cn(
          'flex-1 transition-all duration-300',
          isCollapsed ? 'ml-16' : 'ml-64'
        )}
      >
        <Outlet />
      </main>
    </div>
  );
}
