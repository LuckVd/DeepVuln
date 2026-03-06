"""
Security Audit Prompts - Prompt templates for AI-powered security analysis.

These prompts are designed to guide LLMs in performing thorough security audits
and producing structured, actionable findings.
"""

from dataclasses import dataclass, field
from typing import Any

# =============================================================================
# VULNERABILITY PATTERN LIBRARY
# =============================================================================
# Detailed patterns for each vulnerability type including:
# - vulnerable_patterns: Code patterns that indicate vulnerability
# - sinks: Dangerous functions that can be exploited
# - sanitizers: Functions/patterns that mitigate the vulnerability
# - languages: Language-specific patterns

VULNERABILITY_PATTERNS = {
    "sql_injection": {
        "name": "SQL Injection",
        "cwe": "CWE-89",
        "description": "User input is used in SQL queries without proper sanitization",
        "vulnerable_patterns": [
            # Python
            'f"SELECT * FROM {table}"',
            'f"SELECT * FROM users WHERE id = {user_id}"',
            'cursor.execute("SELECT * FROM " + table_name)',
            'cursor.execute(query % user_input)',
            'cursor.execute(query.format(user_input))',
            '.raw("SELECT * FROM " + user_input)',
            '.extra(where=[user_input])',
            # JavaScript/TypeScript
            'connection.query(`SELECT * FROM ${table}`)',
            'sequelize.query(`SELECT * FROM users WHERE id = ${id}`)',
            'knex.raw(`SELECT * FROM ${table}`)',
            # Java
            '"SELECT * FROM " + tableName',
            'createQuery("FROM User WHERE id = " + id)',
            'createNativeQuery("SELECT * FROM " + table)',
            # Go
            'fmt.Sprintf("SELECT * FROM %s", table)',
            'db.Query("SELECT * FROM " + table)',
        ],
        "sinks": [
            "execute(", "executemany(", "executescript(",
            "raw(", "extra(", "Raw(",
            "query(", "Query(", "QueryRow(",
            "createQuery(", "createNativeQuery(",
            "prepareStatement(", "createStatement(",
        ],
        "sanitizers": [
            "parameterized", "%s", "?", "$1", ":param",
            "bindparam", "bindParam", "setString", "setInt",
            "PreparedStatement", "sql.NamedArg", "sql.Named(",
        ],
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "description": "User input is reflected in HTML without proper escaping",
        "vulnerable_patterns": [
            # JavaScript/TypeScript
            "innerHTML =",
            "outerHTML =",
            "document.write(",
            "dangerouslySetInnerHTML=",
            "v-html=",
            '{{{ user_input }}}',  # Handlebars raw
            "| safe",  # Jinja2/Django
            "| raw",  # Blade/Laravel
            "res.write(",
            "response.write(",
            # Python
            "mark_safe(",
            "Markup(",
            # React
            "defaultProps.dangerouslySetInnerHTML",
        ],
        "sinks": [
            "innerHTML", "outerHTML", "insertAdjacentHTML",
            "document.write", "document.writeln",
            "dangerouslySetInnerHTML", "v-html",
            "res.write", "response.write",
            ".html(",  # jQuery
        ],
        "sanitizers": [
            "escape(", "htmlspecialchars(", "htmlentities(",
            "DOMPurify.sanitize(", "sanitize(",
            "encodeURI", "encodeURIComponent",
            "text()", "textContent", "innerText",
            "escapeHtml", "html_escape", "e(",
        ],
    },
    "command_injection": {
        "name": "Command Injection",
        "cwe": "CWE-78",
        "description": "User input is used in system commands without sanitization",
        "vulnerable_patterns": [
            # Python
            "os.system(",
            "subprocess.call(",
            'subprocess.Popen("',
            "os.popen(",
            "commands.getoutput(",
            "eval(",
            "exec(",
            # JavaScript
            "child_process.exec(",
            "exec(",
            "spawn(",
            "execSync(",
            # Java
            "Runtime.exec(",
            "ProcessBuilder(",
            # Go
            "exec.Command(",
            "exec.CommandContext(",
        ],
        "sinks": [
            "os.system", "os.popen", "subprocess.call", "subprocess.Popen",
            "subprocess.run", "commands.getoutput",
            "child_process.exec", "child_process.spawn", "exec", "execSync",
            "Runtime.exec", "ProcessBuilder",
            "exec.Command", "exec.CommandContext",
            "eval(", "exec(",
        ],
        "sanitizers": [
            "shlex.quote(", "shell_quote(", "escapeshellarg(",
            "subprocess.run(shell=False)",
            "subprocess.Popen(shell=False)",
            "shellescape(", "quote(",
        ],
    },
    "path_traversal": {
        "name": "Path Traversal",
        "cwe": "CWE-22",
        "description": "User input is used in file paths without validation",
        "vulnerable_patterns": [
            'open("' + "user_input",
            "open(f",
            'readFile("' + "user_input",
            "fs.readFile(",
            "send_file(",
            "sendfile(",
            "static(",
            "os.path.join(base, user_input)",
            "path.join(base, user_input)",
            "filepath.Join(base, user_input)",
        ],
        "sinks": [
            "open(", "read(", "write(", "readFile", "writeFile",
            "send_file", "sendfile", "static",
            "os.path.join", "path.join", "filepath.Join",
            "File(", "FileInputStream", "FileOutputStream",
            "ioutil.ReadFile", "os.ReadFile", "os.Open",
        ],
        "sanitizers": [
            "os.path.basename(", "path.basename(",
            "os.path.realpath(", "os.path.abspath(",
            "filepath.Base(", "filepath.Clean(",
            "realpath(", "canonicalize(",
            "Path.normalize(", "Paths.get(",
        ],
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
        "description": "User input controls URLs or hosts for server-side requests",
        "vulnerable_patterns": [
            "requests.get(",
            "urllib.request.urlopen(",
            "http.get(",
            "fetch(",
            "axios.get(",
            "HttpClient(",
            "http.Get(",
            "curl_exec(",
            "file_get_contents(",
        ],
        "sinks": [
            "requests.get", "requests.post", "requests.put",
            "urllib.request.urlopen", "urllib.urlopen",
            "http.get", "http.post", "http.request",
            "fetch", "axios", "got", "superagent",
            "HttpClient", "URL", "URLConnection",
            "http.Get", "http.Post", "http.NewRequest",
            "curl_exec", "file_get_contents",
        ],
        "sanitizers": [
            "validators.url(", "validate_url(",
            "urlparse(", "URL(",
            "whitelist", "allowlist",
            "socket.gethostbyname(",
        ],
    },
    "deserialization": {
        "name": "Unsafe Deserialization",
        "cwe": "CWE-502",
        "description": "Untrusted data is deserialized without validation",
        "vulnerable_patterns": [
            "pickle.loads(",
            "pickle.load(",
            "yaml.load(",
            "marshal.loads(",
            "ObjectInputStream",
            "readObject(",
            "JSON.parse(",
            "eval(",
            "new Function(",
        ],
        "sinks": [
            "pickle.loads", "pickle.load", "cPickle.loads",
            "yaml.load", "yaml.unsafe_load",
            "marshal.loads", "marshal.load",
            "ObjectInputStream", "readObject",
            "JSON.parse", "eval", "Function(",
            "unserialize(", "maybe_unserialize(",
        ],
        "sanitizers": [
            "yaml.safe_load(", "json.loads(",
            "JSON.parse(", "JSON.parseStrict(",
            "ObjectMapper", "Gson", "Jackson",
            "signature verification", "hmac",
        ],
    },
    "code_injection": {
        "name": "Code Injection",
        "cwe": "CWE-94",
        "description": "User input is evaluated or executed as code",
        "vulnerable_patterns": [
            "eval(",
            "exec(",
            "compile(",
            "new Function(",
            "setTimeout(user_input)",
            "setInterval(user_input)",
            "vm.runInContext(",
            "vm.runInNewContext(",
        ],
        "sinks": [
            "eval", "exec", "compile",
            "Function(", "setTimeout", "setInterval",
            "vm.runInContext", "vm.runInNewContext", "vm.runInThisContext",
            "ScriptEngine", "eval(",
        ],
        "sanitizers": [
            # Very few safe alternatives for eval
            "JSON.parse", "ast.literal_eval",
            "new Function with static code only",
        ],
    },
}

# =============================================================================
# VULNERABILITY TYPES (Basic Info)
# =============================================================================

VULNERABILITY_TYPES = {
    "sql_injection": {
        "name": "SQL Injection",
        "cwe": "CWE-89",
        "description": "User input is used in SQL queries without proper sanitization",
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "description": "User input is reflected in HTML without proper escaping",
    },
    "command_injection": {
        "name": "Command Injection",
        "cwe": "CWE-78",
        "description": "User input is used in system commands without sanitization",
    },
    "path_traversal": {
        "name": "Path Traversal",
        "cwe": "CWE-22",
        "description": "User input is used in file paths without validation",
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
        "description": "User input controls URLs or hosts for server-side requests",
    },
    "xxe": {
        "name": "XML External Entity (XXE)",
        "cwe": "CWE-611",
        "description": "XML parsing with external entity processing enabled",
    },
    "deserialization": {
        "name": "Unsafe Deserialization",
        "cwe": "CWE-502",
        "description": "Untrusted data is deserialized without validation",
    },
    "hardcoded_secrets": {
        "name": "Hardcoded Secrets",
        "cwe": "CWE-798",
        "description": "Passwords, API keys, or tokens hardcoded in source code",
    },
    "crypto_weakness": {
        "name": "Cryptographic Weakness",
        "cwe": "CWE-327",
        "description": "Weak or improper use of cryptographic functions",
    },
    "auth_bypass": {
        "name": "Authentication Bypass",
        "cwe": "CWE-287",
        "description": "Flaws in authentication logic that allow access without credentials",
    },
    "idor": {
        "name": "Insecure Direct Object Reference (IDOR)",
        "cwe": "CWE-639",
        "description": "User input controls access to objects without authorization checks",
    },
    "open_redirect": {
        "name": "Open Redirect",
        "cwe": "CWE-601",
        "description": "User input controls redirect URLs without validation",
    },
    "ldap_injection": {
        "name": "LDAP Injection",
        "cwe": "CWE-90",
        "description": "User input is used in LDAP queries without sanitization",
    },
    "log_injection": {
        "name": "Log Injection",
        "cwe": "CWE-93",
        "description": "User input is written to logs without sanitization",
    },
    "code_injection": {
        "name": "Code Injection",
        "cwe": "CWE-94",
        "description": "User input is evaluated or executed as code",
    },
}


# =============================================================================
# ATTACKER PERSPECTIVE PROMPT
# =============================================================================

ATTACKER_PERSPECTIVE = """
## Attacker Mindset Analysis

Before concluding "not exploitable" or "INFO", think like an attacker:

### 1. What if I control the input?
- Can I inject SQL/XSS/commands through this parameter?
- Can I bypass validation with special characters or encoding?
- Can I manipulate the data format (JSON, XML, serialization)?

### 2. What if I chain this with another issue?
- Can this be combined with IDOR to access others' data?
- Can this lead to privilege escalation?
- Can this expose sensitive configuration or secrets?
- Can this be used to pivot to internal systems?

### 3. What if the defense fails?
- What if the sanitizer has bypass techniques?
- What if the WAF is misconfigured or bypassed?
- What if authentication has weaknesses?
- What if the framework has known vulnerabilities?

### 4. Edge Cases to Consider
- What about Unicode/encoding tricks?
- What about null bytes or special characters?
- What about race conditions?
- What about type confusion?

**IMPORTANT**: When in doubt, report as "suspicious_code" rather than skipping.
Let the verification layer (L5) or human reviewer confirm exploitability.
"""


# =============================================================================
# VULNERABILITY PATTERNS REFERENCE FOR PROMPT
# =============================================================================

def get_vulnerability_patterns_prompt(focus_types: list[str] | None = None) -> str:
    """Generate a prompt section with vulnerability patterns to look for.

    Args:
        focus_types: List of vulnerability types to include. If None, includes all.

    Returns:
        Formatted string with vulnerability patterns.
    """
    types_to_include = focus_types if focus_types else list(VULNERABILITY_PATTERNS.keys())

    sections = ["## Vulnerability Patterns to Look For\n"]

    for vuln_type in types_to_include:
        if vuln_type not in VULNERABILITY_PATTERNS:
            continue

        pattern = VULNERABILITY_PATTERNS[vuln_type]
        sections.append(f"### {pattern['name']} ({pattern['cwe']})")
        sections.append(f"{pattern['description']}\n")

        # Add vulnerable patterns
        if pattern.get("vulnerable_patterns"):
            sections.append("**Vulnerable Patterns:**")
            for vp in pattern["vulnerable_patterns"][:5]:  # Limit to 5 examples
                sections.append(f"- `{vp}`")
            sections.append("")

        # Add sinks
        if pattern.get("sinks"):
            sections.append("**Dangerous Sinks:**")
            sinks_str = ", ".join(f"`{s}`" for s in pattern["sinks"][:8])
            sections.append(f"{sinks_str}\n")

        sections.append("")

    return "\n".join(sections)

# Severity guidelines for consistent assessment
SEVERITY_GUIDELINES = {
    "critical": "Exploitation can cause severe damage without user interaction. Examples: RCE, SQL injection with data exfiltration, authentication bypass.",
    "high": "Exploitation can cause significant damage. Examples: Stored XSS, path traversal with file write, SSRF to internal services.",
    "medium": "Exploitation requires specific conditions or has limited impact. Examples: Reflected XSS, open redirect, IDOR.",
    "low": "Exploitation is difficult or has minimal impact. Examples: Log injection, minor info disclosure.",
    "info": "Best practice recommendation or informational finding. Not a security vulnerability.",
}


@dataclass
class SecurityAuditPrompt:
    """Configuration for security audit prompts."""

    language: str = "unknown"
    framework: str | None = None
    vulnerability_focus: list[str] | None = None
    context_findings: list[dict[str, Any]] = field(default_factory=list)
    attack_surface: list[str] | None = None
    max_code_length: int = 8000

    def get_system_prompt(self) -> str:
        """Get the system prompt for the security audit."""
        # Build vulnerability patterns section based on focus
        patterns_section = get_vulnerability_patterns_prompt(self.vulnerability_focus)

        return f"""You are an expert security code auditor with deep knowledge of application security vulnerabilities, secure coding practices, and threat modeling.

Your task is to analyze code snippets for security vulnerabilities and provide detailed, actionable findings.

## Your Expertise

- Web application security (OWASP Top 10)
- API security vulnerabilities
- Authentication and authorization flaws
- Injection vulnerabilities (SQL, command, XSS, etc.)
- Cryptographic weaknesses
- Business logic vulnerabilities
- Language-specific security issues

{patterns_section}
## Analysis Approach

1. **Identify data sources**: Look for user input, external data, and untrusted sources
2. **Trace data flow**: Follow how data moves through the code
3. **Find sinks**: Identify dangerous functions that could be exploited
4. **Check sanitization**: Verify if proper validation/sanitization exists
5. **Assess impact**: Evaluate the potential harm if exploited

{ATTACKER_PERSPECTIVE}
## Output Format

You MUST respond with valid JSON in this exact format:
```json
{{
  "findings": [
    {{
      "type": "vulnerability_type_snake_case",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.0-1.0,
      "title": "Brief descriptive title",
      "description": "Detailed explanation of the vulnerability",
      "line": 42,
      "end_line": 45,
      "code_snippet": "vulnerable code",
      "dataflow": "source -> processing -> sink",
      "attack_surface": "How attacker reaches this code (or 'internal' if not externally reachable)",
      "user_controlled": true/false,
      "exploitation_conditions": "What conditions must be met to exploit",
      "recommendation": "How to fix this vulnerability",
      "cwe": "CWE-XXX",
      "owasp": "A01:2021"
    }}
  ],
  "suspicious_code": [
    {{
      "location": "file.py:45",
      "code_snippet": "dangerous code pattern",
      "why_suspicious": "This pattern is commonly associated with X vulnerability",
      "potential_vulnerability": "vulnerability_type",
      "confidence": 0.3,
      "recommended_action": "manual_review|verify_data_flow|check_sanitization"
    }}
  ],
  "summary": "Brief overall assessment",
  "security_score": 1-10
}}
```

## Important Rules

1. **Be thorough**: Look for ALL the vulnerable patterns listed above
2. **Include suspicious_code**: If you see a dangerous pattern but are unsure about exploitability, add it to suspicious_code
3. **Don't skip uncertain findings**: Better to report as suspicious than to miss a real vulnerability
4. Include specific line numbers when possible
5. Provide actionable remediation advice
6. Always respond with valid JSON only - no additional text
7. **CRITICAL**: Think like an attacker - what could go wrong?
8. **CRITICAL**: When in doubt, add to suspicious_code rather than skipping"""  # noqa: E501

    def get_user_prompt_for_file(
        self,
        file_path: str,
        code: str,
    ) -> str:
        """Build the user prompt for analyzing a file."""
        prompt_parts = [
            f"Analyze the following {self.language} code for security vulnerabilities.",
            "",
            f"**File:** `{file_path}`",
        ]

        if self.framework:
            prompt_parts.append(f"**Framework:** {self.framework}")

        if self.vulnerability_focus:
            vuln_names = [
                VULNERABILITY_TYPES.get(v, {}).get("name", v)
                for v in self.vulnerability_focus
            ]
            prompt_parts.append(f"**Focus Areas:** {', '.join(vuln_names)}")

        if self.attack_surface:
            prompt_parts.append(f"**Attack Surface:** {', '.join(self.attack_surface)}")

        prompt_parts.append("")
        prompt_parts.append("**Code:**")
        prompt_parts.append("```")
        # Truncate if too long
        if len(code) > self.max_code_length:
            code = code[:self.max_code_length] + "\n... (truncated)"
        prompt_parts.append(code)
        prompt_parts.append("```")

        if self.context_findings:
            prompt_parts.append("")
            prompt_parts.append("**Related Findings from Previous Analysis:**")
            for finding in self.context_findings[:5]:  # Limit context
                prompt_parts.append(
                    f"- [{finding.get('severity', 'unknown')}] {finding.get('title', 'Unknown')}"
                )

        return "\n".join(prompt_parts)

    def get_user_prompt_for_function(
        self,
        file_path: str,
        function_name: str,
        code: str,
        caller_context: str | None = None,
    ) -> str:
        """Build the user prompt for analyzing a specific function."""
        prompt_parts = [
            f"Analyze this {self.language} function for security vulnerabilities.",
            "",
            f"**File:** `{file_path}`",
            f"**Function:** `{function_name}`",
        ]

        if caller_context:
            prompt_parts.append("")
            prompt_parts.append("**Called from:**")
            prompt_parts.append("```")
            prompt_parts.append(caller_context[:500])  # Limit context
            prompt_parts.append("```")

        prompt_parts.append("")
        prompt_parts.append("**Function Code:**")
        prompt_parts.append("```")
        prompt_parts.append(code)
        prompt_parts.append("```")

        return "\n".join(prompt_parts)


def build_audit_prompt(
    language: str,
    code: str,
    file_path: str,
    framework: str | None = None,
    vulnerability_focus: list[str] | None = None,
    context: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """
    Build system and user prompts for security audit.

    Args:
        language: Programming language.
        code: Code to analyze.
        file_path: Path to the file.
        framework: Optional framework name.
        vulnerability_focus: List of vulnerability types to focus on.
        context: Additional context (findings, attack surface, etc.).

    Returns:
        Tuple of (system_prompt, user_prompt).
    """
    config = SecurityAuditPrompt(
        language=language,
        framework=framework,
        vulnerability_focus=vulnerability_focus,
        context_findings=context.get("findings", []) if context else [],
        attack_surface=context.get("attack_surface") if context else None,
    )

    return config.get_system_prompt(), config.get_user_prompt_for_file(file_path, code)


def build_file_analysis_prompt(
    file_path: str,
    code: str,
    language: str,
    **options,
) -> tuple[str, str]:
    """
    Convenience function to build prompts for file analysis.

    Args:
        file_path: Path to the file.
        code: Code content.
        language: Programming language.
        **options: Additional options (framework, focus, etc.).

    Returns:
        Tuple of (system_prompt, user_prompt).
    """
    return build_audit_prompt(
        language=language,
        code=code,
        file_path=file_path,
        framework=options.get("framework"),
        vulnerability_focus=options.get("vulnerability_focus"),
        context=options.get("context"),
    )


def build_function_analysis_prompt(
    file_path: str,
    function_name: str,
    code: str,
    language: str,
    caller_context: str | None = None,
    **options,
) -> tuple[str, str]:
    """
    Build prompts for function-level analysis.

    Args:
        file_path: Path to the file.
        function_name: Name of the function.
        code: Function code.
        language: Programming language.
        caller_context: Optional context showing where function is called.
        **options: Additional options.

    Returns:
        Tuple of (system_prompt, user_prompt).
    """
    config = SecurityAuditPrompt(
        language=language,
        framework=options.get("framework"),
        vulnerability_focus=options.get("vulnerability_focus"),
    )

    return (
        config.get_system_prompt(),
        config.get_user_prompt_for_function(
            file_path=file_path,
            function_name=function_name,
            code=code,
            caller_context=caller_context,
        ),
    )
