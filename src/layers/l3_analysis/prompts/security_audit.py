"""
Security Audit Prompts - Prompt templates for AI-powered security analysis.

These prompts are designed to guide LLMs in performing thorough security audits
and producing structured, actionable findings.
"""

from dataclasses import dataclass, field
from typing import Any


# Vulnerability types the agent should look for
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
        return """You are an expert security code auditor with deep knowledge of application security vulnerabilities, secure coding practices, and threat modeling.

Your task is to analyze code snippets for security vulnerabilities and provide detailed, actionable findings.

## Your Expertise

- Web application security (OWASP Top 10)
- API security vulnerabilities
- Authentication and authorization flaws
- Injection vulnerabilities (SQL, command, XSS, etc.)
- Cryptographic weaknesses
- Business logic vulnerabilities
- Language-specific security issues

## Analysis Approach

1. **Identify data sources**: Look for user input, external data, and untrusted sources
2. **Trace data flow**: Follow how data moves through the code
3. **Find sinks**: Identify dangerous functions that could be exploited
4. **Check sanitization**: Verify if proper validation/sanitization exists
5. **Assess impact**: Evaluate the potential harm if exploited

## Output Format

You MUST respond with valid JSON in this exact format:
```json
{
  "findings": [
    {
      "type": "vulnerability_type_snake_case",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.0-1.0,
      "title": "Brief descriptive title",
      "description": "Detailed explanation of the vulnerability",
      "line": 42,
      "end_line": 45,
      "code_snippet": "vulnerable code",
      "dataflow": "source -> processing -> sink",
      "recommendation": "How to fix this vulnerability",
      "cwe": "CWE-XXX",
      "owasp": "A01:2021"
    }
  ],
  "summary": "Brief overall assessment",
  "security_score": 1-10
}
```

## Important Rules

1. Only report ACTUAL vulnerabilities with clear evidence
2. Include specific line numbers when possible
3. Provide actionable remediation advice
4. Be conservative with confidence scores
5. If no vulnerabilities found, return empty findings array
6. Always respond with valid JSON only - no additional text"""  # noqa: E501

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
