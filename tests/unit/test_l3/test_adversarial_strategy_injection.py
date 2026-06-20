"""
Tests for strategy-knowledge injection into the base adversarial prompts.

Phase 18 / P6-子项5: 把 strategy_library 的真实攻防知识按 finding 的 vuln
类型接进 get_attacker_user_prompt / get_defender_user_prompt，让 LLM 生成
论证时参考（而非增强版那种"生成后贴字符串"）。
"""

from src.layers.l3_analysis.prompts.adversarial import (
    get_attacker_user_prompt,
    get_defender_user_prompt,
)


def _sqli_finding() -> dict:
    return {
        "type": "sql_injection",
        "severity": "high",
        "location": "app.py:10",
        "title": "SQL Injection",
        "description": "user input concatenated into SQL query",
    }


def test_attacker_prompt_injects_relevant_bypass_for_sqli():
    """SQLi attacker prompt 含按类型注入的绕过技巧 + 攻击链。"""
    prompt = get_attacker_user_prompt(_sqli_finding(), code_context="cursor.execute(q)")
    low = prompt.lower()
    # comment_injection 绕过技巧 tagged for sql_injection
    assert "comment" in low
    # 注入了策略知识 section
    assert "## relevant attack techniques" in low
    # 接地气表述：不预设漏洞已使用，而是"评估是否适用"
    assert any(w in low for w in ("assess", "consider", "applicab", "whether"))


def test_attacker_prompt_is_vuln_type_aware():
    """XSS finding 应得到 XSS 相关知识，而非 SQLi 专属攻击链。"""
    xss = {**_sqli_finding(), "type": "xss", "title": "XSS"}
    prompt = get_attacker_user_prompt(xss, code_context="el.innerHTML = userInput")
    low = prompt.lower()
    # xss 攻击链（xss_session_hijack）出现
    assert "xss" in low
    # 注入了 section
    assert "## relevant attack techniques" in low


def test_defender_prompt_injects_defense_checklist_for_sqli():
    """SQLi defender prompt 含参数化查询防御 + 接地气'核实'表述。"""
    prompt = get_defender_user_prompt(_sqli_finding(), code_context="cursor.execute(q)")
    low = prompt.lower()
    # 参数化查询防御机制
    assert "parameterized" in low
    # 注入了防御 section
    assert "## defense checklist" in low
    # 接地气表述：核实防御是否存在/有效
    assert any(w in low for w in ("verify", "check", "whether"))


def test_unknown_vuln_type_no_strategy_bloat():
    """未知 vuln 类型不应注入策略 section（避免无关内容膨胀 prompt）。"""
    finding = {**_sqli_finding(), "type": "totally_unknown_vuln_type"}
    prompt = get_attacker_user_prompt(finding, code_context="x")
    assert "## relevant attack techniques" not in prompt.lower()
