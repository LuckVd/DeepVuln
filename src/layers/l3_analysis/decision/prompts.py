"""
LLM Prompt templates for CodeQL language decision.

Provides structured prompts for the LLM decision process, following
the principles of security priority, efficiency balance, and risk focus.
"""

from typing import Any

from .models import (
    AttackSurfaceSummary,
    BuildDifficulty,
    BuildDifficultyLevel,
    DecisionConstraints,
    LanguageDecisionInput,
    LanguageStructure,
    ModuleSummary,
    SemgrepSummary,
)


def format_language_table(languages: list[LanguageStructure]) -> str:
    """Format language structure as a table for the prompt."""
    if not languages:
        return "No languages detected."

    lines = ["| Language | Files | LOC | % | Role |", "|----------|-------|-----|---|------|"]
    for lang in sorted(languages, key=lambda x: x.line_count, reverse=True):
        lines.append(
            f"| {lang.name} | {lang.file_count} | {lang.line_count:,} | "
            f"{lang.percentage:.1f}% | {lang.role} |"
        )
    return "\n".join(lines)


def format_build_difficulty(difficulties: dict[str, BuildDifficulty]) -> str:
    """Format build difficulty information for the prompt."""
    if not difficulties:
        return "No build difficulty information available."

    lines = ["| Language | Difficulty | Est. Time | Build Config | Blockers |"]
    lines.append("|----------|------------|-----------|--------------|----------|")

    for lang, diff in sorted(difficulties.items(), key=lambda x: x[1].estimated_time_seconds):
        blockers_str = "; ".join(diff.blockers[:2]) if diff.blockers else "None"
        if len(diff.blockers) > 2:
            blockers_str += f" (+{len(diff.blockers) - 2} more)"
        config_str = "Yes" if diff.has_build_config else "No"
        lines.append(
            f"| {lang} | {diff.level.value} | {diff.estimated_time_seconds}s | "
            f"{config_str} | {blockers_str} |"
        )
    return "\n".join(lines)


def format_modules(modules: list[ModuleSummary]) -> str:
    """Format module summaries for the prompt."""
    if not modules:
        return "Single module project (no subprojects detected)."

    lines = ["| Module | Path | Primary Language | Languages | LOC |"]
    lines.append("|--------|------|------------------|-----------|-----|")

    for mod in modules[:10]:  # Limit to 10 modules
        langs = ", ".join(mod.languages[:3])
        if len(mod.languages) > 3:
            langs += f" (+{len(mod.languages) - 3})"
        lines.append(
            f"| {mod.name} | {mod.path} | {mod.primary_language} | "
            f"{langs} | {mod.loc_estimate:,} |"
        )
    return "\n".join(lines)


def format_attack_surface(attack_surface: AttackSurfaceSummary) -> str:
    """Format attack surface summary for the prompt."""
    lines = ["### Attack Surface Summary"]
    lines.append(f"- **Total Endpoints**: {attack_surface.total_endpoints}")

    if attack_surface.entry_points_by_language:
        lines.append("\n**Entry Points by Language**:")
        for lang, count in sorted(
            attack_surface.entry_points_by_language.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            lines.append(f"  - {lang}: {count}")

    if attack_surface.sensitive_data_flows:
        lines.append("\n**Sensitive Data Flows**:")
        for flow in attack_surface.sensitive_data_flows[:5]:
            lines.append(f"  - {flow}")

    return "\n".join(lines)


def format_semgrep_result(semgrep: SemgrepSummary | None) -> str:
    """Format Semgrep results for the prompt."""
    if not semgrep:
        return "### Semgrep Results\nNot available or not run."

    lines = ["### Semgrep Results"]
    lines.append(f"**Total Findings**: {semgrep.total_findings}")

    if semgrep.findings_by_language:
        lines.append("\n**Findings by Language**:")
        for lang, counts in sorted(
            semgrep.findings_by_language.items(),
            key=lambda x: sum(x[1].values()),
            reverse=True,
        ):
            severity_str = ", ".join(f"{k}: {v}" for k, v in counts.items() if v > 0)
            if severity_str:
                lines.append(f"  - {lang}: {severity_str}")

    return "\n".join(lines)


def build_decision_prompt(input_data: LanguageDecisionInput) -> str:
    """
    Build the complete decision prompt for the LLM.

    Args:
        input_data: Complete input data for the decision.

    Returns:
        Formatted prompt string.
    """
    # Build input sections
    language_table = format_language_table(input_data.languages)
    build_table = format_build_difficulty(input_data.build_difficulties)
    modules_table = format_modules(input_data.modules)
    attack_surface = format_attack_surface(input_data.attack_surface)
    semgrep = format_semgrep_result(input_data.semgrep_result)

    # Build constraints section
    constraints = input_data.constraints
    constraints_str = f"""
### Constraints
- **Maximum Languages to Scan**: {constraints.max_languages}
- **Maximum Time Budget**: {constraints.max_time_budget_seconds // 60} minutes
- **Minimum Confidence Threshold**: {constraints.min_confidence}
"""

    # Build the complete prompt
    prompt = f"""You are a security scanning expert deciding which programming languages to prioritize for CodeQL deep scanning.

## Decision Principles

1. **Security Priority**: Prioritize languages with larger attack surfaces and more entry points.
2. **Efficiency Balance**: Maximize security coverage within the time budget.
3. **Risk Focus**: Prioritize languages where Semgrep found high-severity issues.
4. **Build Feasibility**: Avoid languages with high build difficulty or blocking factors.
5. **Module Awareness**: For monorepos, consider each module's primary language independently.

## Input Data

### Languages Detected
{language_table}

### Build Difficulty Assessment
{build_table}

### Module Structure
{modules_table}

{attack_surface}

{semgrep}

{constraints_str}

## Output Format

Provide your decision as a JSON object with this exact structure:

```json
{{
  "recommended_languages": ["java", "python"],
  "recommendations": [
    {{
      "language": "java",
      "priority_score": 0.9,
      "reasoning": "Primary language with 45% of code, 120 entry points, and Semgrep found 3 high-severity issues.",
      "estimated_time_seconds": 600
    }},
    {{
      "language": "python",
      "priority_score": 0.75,
      "reasoning": "Secondary language with 20% of code, easy build, 50 entry points.",
      "estimated_time_seconds": 180
    }}
  ],
  "skipped_languages": ["cpp"],
  "skip_reasons": {{
    "cpp": "Build difficulty is hard, no compile_commands.json, limited attack surface (5% of code, 2 entry points)."
  }},
  "estimated_total_time": "13 minutes",
  "estimated_total_seconds": 780,
  "confidence": 0.85,
  "reasoning_summary": "Java is prioritized as the primary attack surface. Python included for quick coverage. C++ skipped due to build complexity and low security value."
}}
```

## Important Notes

1. **priority_score** should be between 0.0 and 1.0, with higher meaning more important.
2. **estimated_time_seconds** should match the build difficulty assessment.
3. **confidence** reflects your certainty in this recommendation.
4. Ensure total estimated time stays within the time budget.
5. If you need to trim languages to fit the budget, remove the lowest priority ones.
6. Always provide clear, actionable reasoning for each decision.

Now provide your decision as a JSON object:"""

    return prompt


def build_system_prompt() -> str:
    """Build the system prompt for the LLM decision call."""
    return """You are a CodeQL scanning strategy expert. Your task is to analyze project characteristics and recommend which programming languages should be prioritized for CodeQL deep scanning.

You must respond with valid JSON that matches the expected output format exactly. Do not include any text before or after the JSON object.

Your recommendations should balance:
- Security value (attack surface, entry points, known vulnerabilities)
- Resource efficiency (build time, success probability)
- Risk coverage (high-risk languages based on Semgrep results)

Be conservative: recommend fewer languages if the time budget is tight, and always explain your reasoning clearly."""


def validate_decision_response(response: dict[str, Any]) -> list[str]:
    """
    Validate the structure of the LLM decision response.

    Args:
        response: Parsed JSON response from LLM.

    Returns:
        List of validation errors, empty if valid.
    """
    errors = []

    # Required fields
    required_fields = [
        "recommended_languages",
        "skipped_languages",
        "confidence",
    ]

    for field in required_fields:
        if field not in response:
            errors.append(f"Missing required field: {field}")

    # Validate recommended_languages
    if "recommended_languages" in response:
        if not isinstance(response["recommended_languages"], list):
            errors.append("recommended_languages must be a list")
        elif not all(isinstance(lang, str) for lang in response["recommended_languages"]):
            errors.append("recommended_languages must contain only strings")

    # Validate confidence
    if "confidence" in response:
        conf = response["confidence"]
        if not isinstance(conf, (int, float)) or not (0 <= conf <= 1):
            errors.append("confidence must be a number between 0 and 1")

    # Validate recommendations if present
    if "recommendations" in response:
        if not isinstance(response["recommendations"], list):
            errors.append("recommendations must be a list")
        else:
            for i, rec in enumerate(response["recommendations"]):
                if not isinstance(rec, dict):
                    errors.append(f"recommendations[{i}] must be an object")
                    continue
                if "language" not in rec:
                    errors.append(f"recommendations[{i}] missing 'language' field")
                if "priority_score" in rec:
                    score = rec["priority_score"]
                    if not isinstance(score, (int, float)) or not (0 <= score <= 1):
                        errors.append(f"recommendations[{i}].priority_score must be between 0 and 1")

    return errors


def parse_time_estimate(time_str: str) -> int:
    """
    Parse a time string like "13 minutes" or "2 hours" into seconds.

    Args:
        time_str: Human-readable time string.

    Returns:
        Time in seconds.
    """
    time_str = time_str.lower().strip()

    multipliers = {
        "second": 1,
        "seconds": 1,
        "sec": 1,
        "s": 1,
        "minute": 60,
        "minutes": 60,
        "min": 60,
        "m": 60,
        "hour": 3600,
        "hours": 3600,
        "hr": 3600,
        "h": 3600,
    }

    import re

    # Try to match patterns like "13 minutes" or "2 hours 30 minutes"
    total_seconds = 0
    pattern = r"(\d+)\s*(second|seconds|sec|s|minute|minutes|min|m|hour|hours|hr|h)"
    matches = re.findall(pattern, time_str)

    for value, unit in matches:
        total_seconds += int(value) * multipliers.get(unit, 60)

    return total_seconds if total_seconds > 0 else 0
