"""
Prompts Module

Contains prompt templates for security analysis.
"""

from src.layers.l3_analysis.prompts.security_audit import (
    SecurityAuditPrompt,
    build_audit_prompt,
    build_file_analysis_prompt,
    build_function_analysis_prompt,
    VULNERABILITY_TYPES,
    SEVERITY_GUIDELINES,
)
from src.layers.l3_analysis.prompts.exploitability import (
    ExploitabilityPrompt,
    build_exploitability_prompt,
    parse_exploitability_response,
    EXPLOITABILITY_STATUSES,
)
from src.layers.l3_analysis.prompts.adversarial import (
    ATTACKER_SYSTEM_PROMPT,
    DEFENDER_SYSTEM_PROMPT,
    ARBITER_SYSTEM_PROMPT,
    get_attacker_user_prompt,
    get_defender_user_prompt,
    get_arbiter_user_prompt,
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
