"""Logic-Vulnerability Discovery Prompts (E5: AI 补漏逻辑漏洞).

Unlike the exploitability prompts (which *adjudicate* an existing finding),
these prompts are *generative*: given only entry-point-reachable source
regions, ask the LLM to surface logic vulnerabilities that static tools miss
(missing authorization, auth bypass, IDOR, business-logic flaws, complex
injection). False positives are the primary risk, so the prompt enforces a
strict, limited-scope contract and a three-element hard-evidence requirement.
"""

from __future__ import annotations

import json
import re
from typing import Any

# All vulnerability categories this detector covers in v1.
LOGIC_VULN_CATEGORIES = {
    "missing_authorization": "Missing authorization / access-control check on an entry point",
    "auth_bypass": "Authentication bypass (e.g. trust client-supplied identity/role)",
    "idor": "Insecure Direct Object Reference (user input controls object access)",
    "business_logic": "Business-logic flaw (state machine, quantity/amount/step abuse)",
    "complex_injection": "Injection too context-dependent for static rules to confirm",
}

# The three required hard-evidence fields. A finding missing ANY of these
# (absent, None, or whitespace-only) is discarded as ungrounded (anti-FP).
REQUIRED_EVIDENCE_FIELDS = ("missing_check", "entry_point", "attack_path")

_DEFAULT_MAX_CODE_LENGTH = 8000


def _system_prompt() -> str:
    categories_doc = "\n".join(
        f"- {key}: {desc}" for key, desc in LOGIC_VULN_CATEGORIES.items()
    )
    return f"""You are a senior application security auditor focused on LOGIC vulnerabilities \
that static analysis tools routinely miss.

# Mission
You are shown ONLY source code that is reachable from external entry points \
(HTTP/RPC/MQ/file/cron handlers). Your job is to find logic flaws — NOT to \
re-report obvious pattern-based bugs (those are already caught by semgrep/AST).

# Scope (STRICT — violations cause false positives)
- Only analyze the entry-point handlers and code they directly call.
- Only report a flaw you can trace from a concrete entry point to a concrete \
missing control. If a handler is internal-only or already protected, say nothing.
- Do NOT invent code that is not shown. Do NOT assume frameworks/middleware \
that are not visible in the provided code.

# Categories (v1)
{categories_doc}

# Reporting bar — three-element hard evidence (MANDATORY)
For every finding you MUST provide all three, or omit the finding entirely:
1. missing_check: the SPECIFIC control that is absent (e.g. "no ownership check \
on user_id before returning the record").
2. entry_point: the concrete handler/route the attacker reaches \
(e.g. "GET /api/users/{{id}} -> get_user").
3. attack_path: a concrete step-by-step exploit path from the entry point to \
impact (what the attacker sends, what happens, why the missing check matters).

# Anti-false-positive rules
- If authorization is enforced by visible middleware/decorator/code, do NOT \
report a missing-authorization finding for that handler.
- If you are not confident a control is truly missing, OMIT the finding. \
Silence is correct; a speculative report is not.
- Prefer fewer, high-confidence findings.

# Output format (STRICT JSON, no prose)
Return ONLY a JSON object:
{{
  "findings": [
    {{
      "title": "<short summary>",
      "category": "<one of: {', '.join(LOGIC_VULN_CATEGORIES)}>",
      "severity": "<critical|high|medium|low>",
      "confidence": <0.0-1.0>,
      "file": "<source file>",
      "line": <int>,
      "function": "<handler/function name>",
      "missing_check": "<REQUIRED specific missing control>",
      "entry_point": "<REQUIRED concrete entry point>",
      "attack_path": "<REQUIRED concrete exploit path>",
      "description": "<what and why>",
      "cwe": "<optional CWE id, e.g. CWE-862>"
    }}
  ]
}}

If no grounded logic vulnerability exists, return {{"findings": []}}."""


def _truncate(code: str, max_length: int) -> str:
    if len(code) <= max_length:
        return code
    keep = max_length - 40
    return code[:keep] + "\n... [truncated]"


def build_logic_vuln_prompt(
    entry_regions: list[dict[str, Any]],
    *,
    max_code_length: int = _DEFAULT_MAX_CODE_LENGTH,
) -> tuple[str, str]:
    """Build (system, user) prompts for logic-vulnerability discovery.

    Args:
        entry_regions: list of dicts, each ``{file, line, entry_point_type,
            handlers: [{handler, ...}], code}``. Only entry-point-reachable
            regions should be supplied (the detector enforces limited scope).
        max_code_length: per-region source-code budget before truncation.

    Returns:
        Tuple of (system_prompt, user_prompt).
    """
    if not entry_regions:
        return _system_prompt(), "No entry-point-reachable code regions were provided."

    parts = [
        "Analyze the following entry-point-reachable source regions for logic "
        "vulnerabilities. Apply the scope and evidence rules from the system "
        "prompt strictly. Return ONLY the JSON object.\n",
    ]
    for idx, region in enumerate(entry_regions, start=1):
        # Accept either a ``handlers`` list or a single ``handler`` string.
        handlers = region.get("handlers") or (
            [{"handler": region["handler"]}] if region.get("handler") else []
        )
        handler_names = (
            ", ".join(h.get("handler", "?") for h in handlers) if handlers else "unknown"
        )
        parts.append(
            f"### Region {idx}: {region.get('file', '?')} "
            f"(entry type: {region.get('entry_point_type', '?')}, "
            f"handlers: {handler_names})\n"
            f"```{region.get('language', '')}\n"
            f"{_truncate(str(region.get('code', '')), max_code_length)}\n```\n"
        )
    return _system_prompt(), "\n".join(parts)


def _extract_json_text(response_text: str) -> str | None:
    """Return the JSON-bearing substring of a response, or None."""
    text = response_text.strip()
    # Direct JSON.
    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        pass
    # ```json ... ``` / ``` ... ``` fenced block.
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if fence:
        try:
            json.loads(fence.group(1))
            return fence.group(1)
        except json.JSONDecodeError:
            pass
    # Largest balanced-looking array or object.
    for pattern in (r"\{[\s\S]*\}", r"\[[\s\S]*\]"):
        match = re.search(pattern, text)
        if match:
            try:
                json.loads(match.group(0))
                return match.group(0)
            except json.JSONDecodeError:
                continue
    return None


def _has_evidence(finding: dict[str, Any]) -> bool:
    """True iff all three required hard-evidence fields are present and non-empty."""
    for field in REQUIRED_EVIDENCE_FIELDS:
        value = finding.get(field)
        if value is None:
            return False
        if isinstance(value, str) and not value.strip():
            return False
    return True


def _normalize(finding: dict[str, Any]) -> dict[str, Any]:
    """Clamp confidence into [0, 1] and coerce line to int; keep other fields."""
    out = dict(finding)
    try:
        conf = float(out.get("confidence", 0.5))
        out["confidence"] = max(0.0, min(1.0, conf))
    except (TypeError, ValueError):
        out["confidence"] = 0.5
    try:
        out["line"] = int(out.get("line", 0) or 0)
    except (TypeError, ValueError):
        out["line"] = 0
    return out


def parse_logic_vuln_response(response_text: str) -> list[dict[str, Any]]:
    """Parse an LLM logic-vuln response into a list of grounded finding dicts.

    Enforces the anti-false-positive contract: any finding missing one of the
    three required evidence fields (missing_check / entry_point / attack_path)
    is dropped. Malformed or unparseable input yields an empty list.

    Args:
        response_text: Raw LLM response text.

    Returns:
        List of normalized finding dicts (each guaranteed to carry the three
        required evidence fields and a clamped confidence).
    """
    if not response_text or not response_text.strip():
        return []

    json_text = _extract_json_text(response_text)
    if json_text is None:
        return []

    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return []

    # Accept {"findings": [...]}, a bare list, or a single finding object.
    if isinstance(data, dict):
        if "findings" in data:
            raw_findings = data["findings"]
            if isinstance(raw_findings, dict):
                raw_findings = [raw_findings]
        else:
            # A bare single-finding object (no "findings" wrapper).
            raw_findings = [data]
    elif isinstance(data, list):
        raw_findings = data
    else:
        return []

    if not isinstance(raw_findings, list):
        return []

    results: list[dict[str, Any]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        if not _has_evidence(item):
            continue  # anti-FP: drop ungrounded findings
        results.append(_normalize(item))
    return results
