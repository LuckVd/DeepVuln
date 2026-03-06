"""
Prompts Module

Contains prompt templates for security analysis.
"""

from src.layers.l3_analysis.prompts.adversarial import (
    ARBITER_SYSTEM_PROMPT,
    ATTACKER_SYSTEM_PROMPT,
    DEFENDER_SYSTEM_PROMPT,
    get_arbiter_user_prompt,
    get_attacker_user_prompt,
    get_defender_user_prompt,
)
from src.layers.l3_analysis.prompts.exploitability import (
    EXPLOITABILITY_STATUSES,
    ExploitabilityPrompt,
    build_exploitability_prompt,
    parse_exploitability_response,
)
from src.layers.l3_analysis.prompts.security_audit import (
    SEVERITY_GUIDELINES,
    VULNERABILITY_TYPES,
    SecurityAuditPrompt,
    build_audit_prompt,
    build_file_analysis_prompt,
    build_function_analysis_prompt,
)

__all__ = [
    "SecurityAuditPrompt",
    "build_audit_prompt",
    "build_file_analysis_prompt",
    "build_function_analysis_prompt",
    "VULNERABILITY_TYPES",
    "SEVERITY_GUIDELINES",
    # Exploitability prompts
    "ExploitabilityPrompt",
    "build_exploitability_prompt",
    "parse_exploitability_response",
    "EXPLOITABILITY_STATUSES",
    # Adversarial verification prompts
    "ATTACKER_SYSTEM_PROMPT",
    "DEFENDER_SYSTEM_PROMPT",
    "ARBITER_SYSTEM_PROMPT",
    "get_attacker_user_prompt",
    "get_defender_user_prompt",
    "get_arbiter_user_prompt",
]
