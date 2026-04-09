import { Card, Input, CustomSelect, Button, LanguageSwitcher } from '@/components/ui';
import { Save, Server, Database, Bell, Monitor, Globe } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';

export default function SettingsPage() {
  const { t } = useLanguage();

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-text-primary font-mono tracking-wider">
            {t('settings.title')}
          </h1>
          <span className="text-cyan">//</span>
          <span className="text-cyan font-mono">CONFIGURATION</span>
        </div>
        <p className="text-text-secondary font-sans">Configure system preferences and options</p>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Language Settings */}
        <Card className="glass-panel">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <Globe className="h-5 w-5 text-cyan" />
              <h3 className="text-cyan font-mono font-bold">{t('settings.language')}</h3>
            </div>
            <LanguageSwitcher />
          </div>
          <div className="text-text-secondary font-mono text-sm">
            {t('settings.language') === '语言'
              ? '选择界面显示语言 / Select interface language'
              : 'Select interface display language'}
          </div>
        </Card>

        {/* Scan Settings */}
        <Card className="glass-panel">
          <div className="flex items-center gap-3 mb-6">
            <Server className="h-5 w-5 text-cyan" />
            <h3 className="text-cyan font-mono font-bold">{t('settings.scan')}</h3>
          </div>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium text-text-secondary mb-2 block">
                Default Scan Type
              </label>
              <CustomSelect
                value="full"
                onChange={() => {}}
                options={[
                  { value: 'full', label: 'FULL SCAN' },
                  { value: 'base', label: 'BASE SCAN' },
                ]}
              />
            </div>
            <div>
              <label className="text-sm font-medium text-text-secondary mb-2 block">
                Max Threads
              </label>
              <Input type="number" value="4" className="font-mono" />
            </div>
          </div>
        </Card>

        {/* Database Settings */}
        <Card className="glass-panel">
          <div className="flex items-center gap-3 mb-6">
            <Database className="h-5 w-5 text-cyan" />
            <h3 className="text-cyan font-mono font-bold">{t('settings.database')}</h3>
          </div>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium text-text-secondary mb-2 block">
                Connection String
              </label>
              <Input
                value="postgresql://localhost:5432/deepvuln"
                className="font-mono text-sm"
              />
            </div>
            <div>
              <label className="text-sm font-medium text-text-secondary mb-2 block">
                Retention Days
              </label>
              <Input type="number" value="30" className="font-mono" />
            </div>
          </div>
        </Card>

        {/* Notification Settings */}
        <Card className="glass-panel">
          <div className="flex items-center gap-3 mb-6">
            <Bell className="h-5 w-5 text-cyan" />
            <h3 className="text-cyan font-mono font-bold">{t('settings.notifications')}</h3>
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-text-primary">{t('settings.emailAlerts')}</span>
              <div className="w-12 h-6 bg-cyan/20 rounded-full relative cursor-pointer">
                <div className="absolute right-1 top-1 w-4 h-4 bg-cyan rounded-full" />
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-text-primary">{t('settings.criticalOnly')}</span>
              <div className="w-12 h-6 bg-cyan/20 rounded-full relative cursor-pointer">
                <div className="absolute right-1 top-1 w-4 h-4 bg-cyan rounded-full" />
              </div>
            </div>
          </div>
        </Card>

        {/* System Info */}
        <Card className="glass-panel col-span-2">
          <div className="flex items-center gap-3 mb-6">
            <Monitor className="h-5 w-5 text-cyan" />
            <h3 className="text-cyan font-mono font-bold">{t('settings.system')}</h3>
          </div>
          <div className="grid grid-cols-4 gap-6 font-mono text-sm">
            <div className="space-y-2">
              <div className="text-text-secondary">{t('settings.version')}</div>
              <div className="text-cyan">v2.0.4</div>
            </div>
            <div className="space-y-2">
              <div className="text-text-secondary">{t('settings.backend')}</div>
              <div className="text-success">{t('settings.connected')}</div>
            </div>
            <div className="space-y-2">
              <div className="text-text-secondary">{t('settings.websocket')}</div>
              <div className="text-success">{t('settings.active')}</div>
            </div>
            <div className="space-y-2">
              <div className="text-text-secondary">Uptime</div>
              <div className="text-cyan" id="settings-uptime">--:--:--</div>
            </div>
          </div>
        </Card>
      </div>

      {/* Save Button */}
      <div className="mt-6 flex justify-end">
        <Button>
          <Save className="mr-2 h-4 w-4" />
          {t('common.save')}
        </Button>
      </div>

      {/* Uptime script */}
      <script dangerouslySetInnerHTML={{
        __html: `
          function updateSettingsUptime() {
            const now = new Date();
            const hours = String(now.getHours()).padStart(2, '0');
            const minutes = String(now.getMinutes()).padStart(2, '0');
            const seconds = String(now.getSeconds()).padStart(2, '0');
            const el = document.getElementById('settings-uptime');
            if (el) el.textContent = \`\${hours}:\${minutes}:\${seconds}\`;
          }
          setInterval(updateSettingsUptime, 1000);
          updateSettingsUptime();
        `
      }} />
    </div>
  );
}
