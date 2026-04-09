export const translations = {
  zh: {
    // Navigation
    'nav.dashboard': '仪表盘',
    'nav.scans': '扫描任务',
    'nav.vulnerabilities': '漏洞',
    'nav.reports': '报告',
    'nav.settings': '设置',

    // Common
    'common.loading': '加载中...',
    'common.refresh': '刷新',
    'common.save': '保存',
    'common.cancel': '取消',
    'common.confirm': '确认',
    'common.delete': '删除',
    'common.edit': '编辑',
    'common.view': '查看',
    'common.search': '搜索',
    'common.filter': '筛选',
    'common.export': '导出',
    'common.total': '总计',

    // Scans
    'scans.title': '扫描队列',
    'scans.new': '新建扫描',
    'scans.status.all': '全部状态',
    'scans.status.pending': '等待中',
    'scans.status.running': '扫描中',
    'scans.status.paused': '已暂停',
    'scans.status.completed': '已完成',
    'scans.status.failed': '失败',
    'scans.status.cancelled': '已取消',
    'scans.source.local': '本地目录',
    'scans.source.git': 'Git 仓库',
    'scans.source.zip': 'ZIP 压缩包',

    // Dashboard
    'dashboard.title': '仪表盘',
    'dashboard.overview': '概览',
    'dashboard.totalScans': '总扫描数',
    'dashboard.activeScans': '活跃扫描',
    'dashboard.totalVulns': '总漏洞数',
    'dashboard.criticalVulns': '严重漏洞',
    'dashboard.recentScans': '最近扫描',
    'dashboard.quickActions': '快捷操作',
    'dashboard.vulnBreakdown': '漏洞分布',

    // Vulnerabilities
    'vuln.title': '漏洞',
    'vuln.severity.critical': '严重',
    'vuln.severity.high': '高危',
    'vuln.severity.medium': '中危',
    'vuln.severity.low': '低危',
    'vuln.severity.info': '信息',

    // Reports
    'reports.title': '报告',
    'reports.pdf': 'PDF 报告',
    'reports.json': 'JSON 导出',
    'reports.csv': 'CSV 摘要',
    'reports.generate': '生成',
    'reports.download': '下载',

    // Settings
    'settings.title': '设置',
    'settings.language': '语言',
    'settings.theme': '主题',
    'settings.notifications': '通知',
    'settings.scan': '扫描设置',
    'settings.database': '数据库',
    'settings.system': '系统信息',
    'settings.version': '版本',
    'settings.backend': '后端',
    'settings.websocket': 'WebSocket',
    'settings.connected': '已连接',
    'settings.active': '活动',
    'settings.emailAlerts': '邮件警报',
    'settings.criticalOnly': '仅严重',
  },
  en: {
    // Navigation
    'nav.dashboard': 'Dashboard',
    'nav.scans': 'Scan Tasks',
    'nav.vulnerabilities': 'Vulnerabilities',
    'nav.reports': 'Reports',
    'nav.settings': 'Settings',

    // Common
    'common.loading': 'Loading...',
    'common.refresh': 'Refresh',
    'common.save': 'Save',
    'common.cancel': 'Cancel',
    'common.confirm': 'Confirm',
    'common.delete': 'Delete',
    'common.edit': 'Edit',
    'common.view': 'View',
    'common.search': 'Search',
    'common.filter': 'Filter',
    'common.export': 'Export',
    'common.total': 'Total',

    // Scans
    'scans.title': 'Scan Queue',
    'scans.new': 'New Scan',
    'scans.status.all': 'All Status',
    'scans.status.pending': 'Waiting',
    'scans.status.running': 'Scanning',
    'scans.status.paused': 'Paused',
    'scans.status.completed': 'Completed',
    'scans.status.failed': 'Failed',
    'scans.status.cancelled': 'Cancelled',
    'scans.source.local': 'Local Directory',
    'scans.source.git': 'Git Repository',
    'scans.source.zip': 'ZIP Archive',

    // Dashboard
    'dashboard.title': 'Dashboard',
    'dashboard.overview': 'Overview',
    'dashboard.totalScans': 'Total Scans',
    'dashboard.activeScans': 'Active Scans',
    'dashboard.totalVulns': 'Total Vulns',
    'dashboard.criticalVulns': 'Critical Vulns',
    'dashboard.recentScans': 'Recent Scans',
    'dashboard.quickActions': 'Quick Actions',
    'dashboard.vulnBreakdown': 'Vulnerability Breakdown',

    // Vulnerabilities
    'vuln.title': 'Vulnerabilities',
    'vuln.severity.critical': 'Critical',
    'vuln.severity.high': 'High',
    'vuln.severity.medium': 'Medium',
    'vuln.severity.low': 'Low',
    'vuln.severity.info': 'Info',

    // Reports
    'reports.title': 'Reports',
    'reports.pdf': 'PDF Report',
    'reports.json': 'JSON Export',
    'reports.csv': 'CSV Summary',
    'reports.generate': 'Generate',
    'reports.download': 'Download',

    // Settings
    'settings.title': 'Settings',
    'settings.language': 'Language',
    'settings.theme': 'Theme',
    'settings.notifications': 'Notifications',
    'settings.scan': 'Scan Settings',
    'settings.database': 'Database',
    'settings.system': 'System Info',
    'settings.version': 'Version',
    'settings.backend': 'Backend',
    'settings.websocket': 'WebSocket',
    'settings.connected': 'Connected',
    'settings.active': 'Active',
    'settings.emailAlerts': 'Email Alerts',
    'settings.criticalOnly': 'Critical Only',
  },
};

export type Language = 'zh' | 'en';
export type TranslationKey = keyof typeof translations.zh;
