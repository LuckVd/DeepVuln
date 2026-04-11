/**
 * Rule translations for vulnerability findings
 * Maps vulnerability types and common descriptions to Chinese translations
 */

export interface RuleTranslation {
  type: string;
  name: string;
  description?: string;
  remediation?: string;
}

// Common translations for vulnerability types and descriptions
const RULE_TRANSLATIONS: Record<string, RuleTranslation> = {
  // Command Injection
  'command_injection': {
    type: '命令注入',
    name: '命令注入',
    description: '该命令行依赖于用户提供的值，可能导致命令注入攻击。',
    remediation: '使用严格的输入验证，仅允许允许列表中的值。避免直接执行用户提供的命令。考虑使用参数化的 API 或专门的库来执行命令。'
  },
  'java/command-line-injection': {
    type: '命令注入',
    name: 'Java 命令行注入',
    description: '该命令行依赖于用户提供的值，可能导致命令注入攻击。',
    remediation: '使用严格的输入验证，仅允许允许列表中的值。避免直接执行用户提供的命令。考虑使用 ProcessBuilder 而不是 Runtime.exec()，并使用参数数组而不是字符串。'
  },
  'java/relative-path-command': {
    type: '路径遍历',
    name: '相对路径命令执行',
    description: '使用相对路径执行命令可能导致意外的程序执行。',
    remediation: '使用绝对路径或从安全位置解析可执行文件路径。'
  },

  // Error Message Exposure
  'java/error-message-exposure': {
    type: '信息泄露',
    name: '错误消息暴露',
    description: '错误消息可能泄露敏感信息（如堆栈跟踪、路径、数据库详情）。',
    remediation: '在生产环境中避免将详细错误消息直接返回给用户。使用通用的错误消息，并将详细信息记录到服务器日志中。'
  },

  // Suspicious Code Quality
  'suspicious_code_quality_issue': {
    type: '代码质量',
    name: '可疑代码质量问题',
    description: '代码中存在质量问题，可能导致可维护性下降或潜在错误。',
    remediation: '重构代码以提高可读性和可维护性。遵循代码规范和最佳实践。'
  },
  'suspicious_command_injection': {
    type: '命令注入',
    name: '可疑命令注入',
    description: '检测到可疑的命令注入漏洞，代码中直接拼接用户输入到命令中执行。',
    remediation: '使用严格的输入验证和参数化命令。避免使用 shell 解释器，考虑使用安全的 API 替代。'
  },

  // SQL Injection
  'sql_injection': {
    type: 'SQL 注入',
    name: 'SQL 注入',
    description: '直接拼接用户输入到 SQL 查询中，可能导致 SQL 注入攻击。',
    remediation: '使用参数化查询或 ORM 框架，避免直接拼接 SQL 字符串。'
  },

  // XSS
  'xss': {
    type: '跨站脚本',
    name: 'XSS 跨站脚本',
    description: '用户输入未经转义直接输出到页面，可能导致跨站脚本攻击。',
    remediation: '对所有用户输入进行 HTML 转义，使用 CSP 头部，使用安全的模板引擎。'
  },
  'reflected_xss': {
    type: '跨站脚本',
    name: '反射型 XSS',
    description: '通过 URL 参数反射的用户输入未经转义直接输出到页面。',
    remediation: '对所有用户输入进行 HTML 转义，使用 HttpOnly cookie。'
  },

  // Path Traversal
  'path_traversal': {
    type: '路径遍历',
    name: '路径遍历',
    description: '使用用户输入构造文件路径，可能导致访问任意文件。',
    remediation: '验证文件路径，限制在特定目录内。使用 basename() 或类似函数获取文件名。'
  },

  // Hardcoded Credentials
  'hardcoded_credentials': {
    type: '硬编码凭据',
    name: '硬编码凭据',
    description: '代码中包含硬编码的密码、密钥或其他敏感凭据。',
    remediation: '将凭据移至环境变量或配置文件，并确保这些文件不被提交到代码库。'
  },

  // Cryptographic Issues
  'weak_crypto': {
    type: '加密问题',
    name: '弱加密算法',
    description: '使用了已知不安全的加密算法或过短的密钥长度。',
    remediation: '使用现代、安全的加密算法（如 AES-256、RSA-2048+）。'
  },

  // Default Credentials
  'default_credentials': {
    type: '默认凭据',
    name: '默认凭据',
    description: '使用默认的用户名和密码。',
    remediation: '在部署时更改所有默认凭据。'
  },

  // Insecure Configuration
  'insecure_config': {
    type: '不安全配置',
    name: '不安全配置',
    description: '应用程序或框架配置不安全，可能暴露敏感信息或功能。',
    remediation: '检查并加固所有配置项，禁用不必要的功能。'
  },

  // Information Disclosure
  'information_disclosure': {
    type: '信息泄露',
    name: '信息泄露',
    description: '应用程序泄露敏感信息，如版本号、调试信息或内部路径。',
    remediation: '禁用详细的错误消息，移除调试代码，配置服务器不泄露版本信息。'
  },

  // SSRF
  'ssrf': {
    type: 'SSRF',
    name: '服务端请求伪造',
    description: '应用程序根据用户提供的 URL 发起请求，可能被利用访问内部资源。',
    remediation: '验证和限制目标 URL，使用 URL 白名单，禁用重定向，只访问 HTTP/HTTPS 端点。'
  },

  // CSRF
  'csrf': {
    type: 'CSRF',
    name: '跨站请求伪造',
    description: '应用程序缺少 CSRF 保护，可能被利用执行未授权操作。',
    remediation: '实现 CSRF token，验证 SameSite cookie 属性，使用双重提交 cookie。'
  },

  // Missing Authentication
  'missing_auth': {
    type: '认证缺失',
    name: '认证缺失',
    description: '敏感操作缺少身份验证检查。',
    remediation: '为所有敏感操作添加身份验证和授权检查。'
  },

  // Buffer Overflow
  'buffer_overflow': {
    type: '缓冲区溢出',
    name: '缓冲区溢出',
    description: '不安全的内存操作可能导致缓冲区溢出。',
    remediation: '使用安全的字符串处理函数（如 strncpy 而不是 strcpy），进行边界检查。'
  },

  // Race Condition
  'race_condition': {
    type: '竞态条件',
    name: '竞态条件',
    description: '并发访问共享资源时存在竞态条件。',
    remediation: '使用适当的锁机制或原子操作。'
  },

  // XML External Entity
  'xxe': {
    type: 'XXE',
    name: 'XML 外部实体注入',
    description: 'XML 解析器容易受到 XXE 攻击。',
    remediation: '禁用外部实体处理，使用安全的 XML 解析器。'
  },

  // Deserialization
  'unsafe_deserialization': {
    type: '不安全反序列化',
    name: '不安全反序列化',
    description: '反序列化不受信任的数据可能导致远程代码执行。',
    remediation: '避免反序列化不受信任的数据，使用完整性检查，使用安全的序列化格式。'
  },

  // LDAP Injection
  'ldap_injection': {
    type: 'LDAP 注入',
    name: 'LDAP 注入',
    description: '用户输入直接用于 LDAP 查询，可能导致 LDAP 注入。',
    remediation: '使用参数化 LDAP 查询或对用户输入进行严格验证和转义。'
  },
};

/**
 * Get translation for a vulnerability type
 */
export function getRuleTranslation(vulnType: string): RuleTranslation | null {
  return RULE_TRANSLATIONS[vulnType] || null;
}

/**
 * Get translated name for a vulnerability type
 */
export function getVulnTypeName(vulnType: string): string {
  const translation = RULE_TRANSLATIONS[vulnType];
  return translation?.name || vulnType;
}

/**
 * Translate description if mapping exists, otherwise return original
 */
export function translateDescription(vulnType: string, originalDescription: string): string {
  const translation = RULE_TRANSLATIONS[vulnType];
  if (translation?.description) {
    return translation.description;
  }
  return originalDescription;
}

/**
 * Translate remediation if mapping exists, otherwise return original
 */
export function translateRemediation(vulnType: string, originalRemediation: string | null): string | null {
  const translation = RULE_TRANSLATIONS[vulnType];
  if (translation?.remediation) {
    return translation.remediation;
  }
  return originalRemediation;
}

/**
 * Get all vulnerability types that have translations
 */
export function getTranslatedVulnTypes(): string[] {
  return Object.keys(RULE_TRANSLATIONS);
}
