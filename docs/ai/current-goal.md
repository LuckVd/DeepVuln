# Current Goal

## Status

**阶段**: Phase 8 - AST Engine 与代码图构建 + 前置防误报架构
**状态**: ✅ COMPLETED
**开始日期**: 2026-04-05
**完成日期**: 2026-04-05

---

## 已完成目标

### P8-08: 前置防误报架构（P0）✅ 已完成

---

## 问题背景

### 当前误报现状

基于 2026-04-03 对 `java-test-app-obf` 项目的扫描分析：

| 问题类型 | 数量 | 占比 | 示例 |
|----------|------|------|------|
| 同一漏洞多层检测 | ~40 | **46%** | SQL 注入在调用链被检测 7 次 |
| CodeQL 泛化检测（XSS） | ~16 | **18%** | "[user-provided value](1)" 无法区分 JSON vs HTML |
| 未实现功能被检测 | ~10 | **11%** | `newInstance("GroovyShell")` 但从未调用 `evaluate()` |
| 配置/低危问题 | ~15 | **17%** | Dockerfile 缺少 USER 指令混入高危报告 |
| 其他误报 | ~6 | **7%** | - |
| **合计误报** | **87** | **100%** | - |

### 扫描引擎问题分布

| 引擎 | 发现数 | 主要问题 | 误报率 |
|------|--------|----------|--------|
| **Agent** | 206 | 过度推断、重复检测 | ~50% |
| **CodeQL** | 94 | 泛化模式匹配 | ~80% |
| **Semgrep** | 19 | 较准确 | ~20% |

### 资源浪费分析

**Token 消耗**: 3,429,214 (Prompt: 1.99M, Completion: 1.44M)

```
原始 findings: 319 (19 + 94 + 206)
去重后: 224 (去除 95 个，约 30%)
最终报告: 224 个 findings

问题：
- 大量 Token 用于分析和验证明显误报
- 对抗验证处理了 126 个 medium+ severity findings
- 如果前置过滤，可节省 ~40% 的对抗验证资源
```

### 根本原因

1. **Agent 无约束推断**: 基于 "file 参数名" → 推断为 "路径遍历"，而不验证是否实际处理文件
2. **CodeQL 泛化模式**: 用通用模板匹配，无法区分上下文（JSON vs HTML）
3. **去重时机过晚**: P6-17 在所有引擎汇总后去重，此时已消耗大量资源
4. **无执行路径验证**: 静态分析无法确定代码是否被实际执行

---

## 核心理念

> **防误报应该靠前进行**，在源头防止而非事后过滤

### 设计原则

1. ⚠️ **参考 code-audit skill** 的防幻觉规则 (`/opt/AI/code-audit/SKILL.md`, `agent.md`)
2. ⚠️ **去重前置** - 在 Agent 产生 findings 时立即去重
3. ⚠️ **误报前置** - 在扫描各阶段设置门槛
4. ⚠️ **节省资源** - 减少不必要的 LLM 调用和对抗验证

---

## 预期效果

| 指标 | 当前 | 预期 | 改善 |
|------|------|------|------|
| Agent 误报率 | ~50% | ~25% | **-50%** |
| CodeQL 误报率 | ~80% | ~40% | **-50%** |
| 重复检测率 | ~46% | ~20% | **-56%** |
| 对抗验证减少 | - | ~40% | **节省 40% 资源** |
| Token 消耗减少 | - | ~30% | **节省 30% Token** |
| 扫描时间减少 | - | ~20% | **节省 20% 时间** |

---

## 架构设计

### 防误报层级

```
┌─────────────────────────────────────────────────────────────────┐
│              阶段0: 文件级预过滤 (FilePreFilter)                   │
│  ├─ 跳过配置文件、测试文件、生成代码                              │
│  ├─ 跳过只有常量/定义的文件                                       │
│  └─ 检查攻击面可达性 (Call Graph)                                  │
├─────────────────────────────────────────────────────────────────┤
│              阶段1: Agent Prompt 增强 (EnhancedPrompt)             │
│  ├─ 防幻觉规则 (来自 code-audit skill)                           │
│  ├─ 执行证据要求                                                  │
│  └─ Few-Shot 示例                                                │
├─────────────────────────────────────────────────────────────────┤
│              阶段2: Finding 流式验证 (StreamingValidator)           │
│  ├─ 检查执行证据                                                  │
│  ├─ 置信度合理性校准                                              │
│  └─ 即时降级/丢弃明显误报                                         │
├─────────────────────────────────────────────────────────────────┤
│              阶段3: 去重前置 (InMemoryDeduplicator)                   │
│  ├─ 文件级去重（同一文件同一行号只保留最高分）                     │
│  └─ 调用链去重（同一漏洞在不同层级只保留一个）                     │
├─────────────────────────────────────────────────────────────────┤
│              阶段4: CodeQL 预过滤 (CodeQLPreFilter)                 │
│  ├─ 根据项目类型调整规则                                          │
│  ├─ 降低泛化规则默认置信度                                        │
│  └─ 响应类型检测（JSON vs HTML）                                 │
├─────────────────────────────────────────────────────────────────┤
│              阶段5: 对抗验证准入门槛 (VerificationGatekeeper)       │
│  ├─ 低置信度+低严重级 → 跳过对抗验证                              │
│  ├─ 明显误报模式 → 自动拒绝                                       │
│  └─ 强证据+高置信度 → 自动确认                                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                    最终报告（少量高质量 findings）
```

---

## 实施步骤详解

### P8-08a: 文件级预过滤器

**状态**: todo
**优先级**: P0
**文件**: `src/layers/l3_analysis/pre_filter/file_pre_filter.py`

#### 设计

```python
class FilePreFilter:
    """
    文件级预过滤器 - 在扫描前判断文件是否值得分析

    这是第一道防线，在 Agent 开始扫描前过滤掉不值得分析的文件
    """

    def should_analyze(
        self,
        file_path: Path,
        code: str,
        attack_surface: list[str]
    ) -> tuple[bool, str]:
        """
        判断文件是否需要分析

        Returns:
            (should_analyze, reason)
        """
        # 1. 跳过配置文件
        if self._is_config_file(file_path):
            return False, "Configuration file - skipped"

        # 2. 跳过生成代码
        if self._is_generated_code(code):
            return False, "Auto-generated code - skipped"

        # 3. 检查是否有可执行代码
        if not self._has_executable_code(code):
            return False, "No executable code paths - skipped"

        # 4. 检查攻击面可达性（使用现有 Call Graph）
        if not self._has_attack_surface_reachability(file_path, attack_surface):
            return False, "No attack surface reachability - skipped"

        return True, "Pass pre-filter"

    def _is_config_file(self, file_path: Path) -> bool:
        """检测是否是配置文件"""
        config_patterns = [
            "config", ".conf", ".yaml", ".yml", ".json",
            ".properties", ".toml", "dockerfile"
        ]
        return any(p in file_path.lower() for p in config_patterns)

    def _is_generated_code(self, code: str) -> bool:
        """检测是否是生成代码"""
        generated_markers = [
            "DO NOT EDIT", "Auto-generated", "Generated by",
            "Code created by", "// @generated"
        ]
        return any(marker in code for marker in generated_markers)

    def _has_executable_code(self, code: str) -> bool:
        """检测是否有可执行代码（函数调用、危险操作）"""
        # 检查是否有函数定义或函数调用
        import re
        executable_patterns = [
            r"def\s+\w+\s*\(",      # Python 函数定义
            r"public\s+.*\s*\w+\s*\(",  # Java 方法
            r"function\s+\w+\s*\(",   # JS 函数
            r"\.\w+\s*\(",            # 方法调用
            r"execute|exec|eval|open|read|write",  # 危险操作
        ]
        return any(re.search(p, code) for p in executable_patterns)

    def _has_attack_surface_reachability(
        self,
        file_path: Path,
        attack_surface: list[str]
    ) -> bool:
        """
        检查文件是否在攻击面可达范围内

        使用现有 Call Graph 组件验证
        """
        from src.layers.l3_analysis.call_graph import CallGraphBuilder

        # TODO: 集成 Call Graph 检查
        # 简化版本：检查文件是否包含 HTTP 端点
        if not attack_surface:
            return True  # 无攻击面信息，保守处理

        # 检查文件路径是否与攻击面相关
        file_str = str(file_path).lower()
        return any(
            endpoint.lower() in file_str
            or "controller" in file_str
            or "handler" in file_str
            for endpoint in attack_surface
        )
```

#### 集成点

```python
# 修改 src/layers/l3_analysis/engines/opencode_agent.py

async def _analyze_single_file(self, ...):
    # 新增：文件预过滤
    from src.layers.l3_analysis.pre_filter import FilePreFilter
    pre_filter = FilePreFilter()

    should_analyze, reason = pre_filter.should_analyze(
        file_path, code, context.get("attack_surface", [])
    )

    if not should_analyze:
        self.logger.debug(f"Skipping {file_path}: {reason}")
        return []

    # 原有扫描逻辑...
```

#### 验收标准

- [ ] 单元测试覆盖所有过滤条件
- [ ] 扫描测试项目，确认配置文件被跳过
- [ ] 扫描时间减少 ~10%（跳过的文件）

---

### P8-08b: Agent Prompt 增强 - 防幻觉规则

**状态**: todo
**优先级**: P0
**依赖**: P8-08a
**文件**: `src/layers/l3_analysis/prompts/enhanced_audit_prompt.py`

#### 设计

**参考来源**: `/opt/AI/code-audit/SKILL.md` 和 `agent.md`

```python
# 从 code-audit skill 提取的防幻觉规则

ANTI_HALLUCINATION_RULES = """
## ⚠️ Anti-Hallucination Rules (CRITICAL - MUST FOLLOW)

### Rule 1: Verify Code Execution
ONLY report a vulnerability if ALL of the following are true:
✓ User-controlled input exists (request param, user input, env var)
✓ The input reaches a dangerous operation WITHOUT sanitization
✓ The dangerous operation is ACTUALLY executed

DO NOT report if:
✗ Only string concatenation/return (no actual file operation)
✗ Method only constructs objects but never calls dangerous methods
✗ Parameters are unused or only logged

### Rule 2: Verify File Existence
✓ MUST reference actual code from the provided snippet
✗ DO NOT assume additional files exist based on "typical project structure"

### Rule 3: Confidence Calibration
| Confidence | Required Evidence |
|------------|-------------------|
| 0.9-1.0 | Working PoC + clear attack path |
| 0.7-0.9 | Clear data flow + actual dangerous call |
| 0.5-0.7 | Dangerous pattern but uncertain execution |
| 0.3-0.5 | Suspicious pattern only → suspicious_code |
| 0.0-0.3 | Too uncertain → skip or suspicious_code

**Core Principle: Better to miss a vulnerability than report a false positive.**
"""

# Few-Shot 示例（正反例对比）

FEW_SHOT_EXAMPLES = """
## Examples: Correct vs Incorrect Reporting

### ❌ WRONG: Reporting Non-Executable Pattern
```java
public String handleUpload(String file) {
    return "File uploaded: " + file;  // Only returns string
}
```
Don't report: "Path Traversal"
Do: Skip or add to suspicious_code with "requires actual file operation"

### ✅ CORRECT: Reporting Executable Pattern
```java
public String readFile(String path) {
    return Files.readString(Paths.get(path));  // Actual file read!
}
```
Report: "Path Traversal - user input reaches Files.readString()"

### ❌ WRONG: Reporting Construction Only
```python
shell = ProcessBuilder(cmd)  # Only constructed, never started
```
Don't report: "Command Injection"

### ✅ CORRECT: Reporting Actual Execution
```python
shell = ProcessBuilder(cmd)
shell.start()  # Actually executed!
```
Report: "Command Injection via ProcessBuilder.start()"

### ❌ WRONG: Reporting Unused Parameter
```java
public void process(String input) {
    String sanitized = sanitize(input);  // Sanitized but not used
    executeQuery("SELECT * FROM users");  // No data flow
}
```
Don't report: "SQL Injection"

### ✅ CORRECT: Reporting Actual Data Flow
```java
public void process(String input) {
    String sanitized = sanitize(input);  # Has sanitization
    if (isBypass(sanitized)) {
        executeQuery("SELECT * FROM users WHERE name = '" + input + "'");  // Raw input!
    }
}
```
Report: "SQL Injection - sanitization bypass, raw input reaches query"
"""

# 执行证据要求

EXECUTION_EVIDENCE_REQUIREMENTS = """
## Execution Evidence Requirements

For each vulnerability type, specific evidence is required:

### SQL Injection
- Evidence: User input reaches database query WITHOUT parameterization
- Must show: `execute("... " + user_input)` or similar
- NOT evidence: String concatenation without database call

### Command Injection
- Evidence: User input reaches system command execution
- Must show: `.exec()`, `.start()`, `Runtime.exec()`, etc.
- NOT evidence: Only constructing ProcessBuilder

### Path Traversal
- Evidence: User input reaches file operation
- Must show: `Files.read()`, `FileInputStream()`, `open()`, etc.
- NOT evidence: Only string concatenation with file name

### XSS
- Evidence: User input reaches HTML rendering
- Must show: `innerHTML`, `dangerouslySetInnerHTML`, template rendering
- NOT evidence: JSON response, error message, logging
"""
```

#### 集成点

```python
# 修改 src/layers/l3_analysis/prompts/security_audit.py

def build_audit_prompt(
    language: str,
    code: str,
    file_path: str,
    framework: str | None = None,
    vulnerability_focus: list[str] | None = None,
    context: dict[str, Any] | None = None,
    use_enhanced_prompt: bool = True,  # 新增参数
) -> tuple[str, str]:
    """Build system and user prompts for security audit."""

    if use_enhanced_prompt:
        # 使用增强的 Prompt
        from src.layers.l3_analysis.prompts.enhanced_audit_prompt import (
            ANTI_HALLUCINATION_RULES,
            EXECUTION_EVIDENCE_REQUIREMENTS,
            FEW_SHOT_EXAMPLES,
        )

        system_prompt = f"""{BASE_SYSTEM_PROMPT}

{ANTI_HALLUCINATION_RULES}

{EXECUTION_EVIDENCE_REQUIREMENTS}

{FEW_SHOT_EXAMPLES}

## Core Principle
Better to miss a vulnerability than report a false positive.
"""
    else:
        # 原有 Prompt
        system_prompt = BASE_SYSTEM_PROMPT

    return system_prompt, user_prompt
```

#### 验收标准

- [ ] 防幻觉规则成功集成到 Agent Prompt
- [ ] Few-Shot 示例清晰展示正反例
- [ ] Agent 误报率降低 ~50%

---

### P8-08c: Finding 流式验证

**状态**: todo
**优先级**: P0
**依赖**: P8-08b
**文件**: `src/layers/l3_analysis/pre_filter/streaming_validator.py`

#### 设计

```python
class StreamingValidator:
    """
    流式验证器 - 在 Finding 产生时立即验证

    这是第二道防线，在 Agent 返回 findings 时立即验证
    每个 finding 在进入结果列表前都要通过这个验证
    """

    def validate_finding(self, finding: Finding) -> tuple[bool, Finding]:
        """
        验证单个 finding

        Returns:
            (accept, adjusted_finding)
            - accept: True=加入结果列表, False=丢弃
            - adjusted_finding: 可能被调整的 finding（降级、分类等）
        """
        # 1. 检查执行证据
        if not self._has_execution_evidence(finding):
            if finding.confidence > 0.5:
                # 降级为可疑代码
                finding.confidence = max(0.3, finding.confidence - 0.3)
                finding.metadata["validation_note"] = "No execution evidence - downgraded"
                finding.metadata["category"] = "suspicious"
                return True, finding
            else:
                # 直接丢弃
                return False, finding

        # 2. 检查置信度合理性
        if finding.confidence > 0.8:
            if not self._has_strong_evidence(finding):
                finding.confidence = 0.7  # 降级
                finding.metadata["validation_note"] = "Insufficient evidence for high confidence"

        # 3. 检查是否是配置问题
        if self._is_config_issue(finding):
            finding.metadata["category"] = "CONFIG"
            finding.severity = SeverityLevel.INFO

        # 4. 检查是否是未实现的代码
        if self._is_unimplemented_code(finding):
            return False, finding

        return True, finding

    def _has_execution_evidence(self, finding: Finding) -> bool:
        """检查是否有执行证据"""
        code = (finding.location.snippet or "").lower()

        # 危险调用模式（有实际执行）
        execution_patterns = [
            ".execute(", ".evaluate(", ".exec(", ".run(",
            "processbuilder(", "runtime.exec(",
            "file(", "open(", "readfile(", "writefile(",
            "eval(", "exec(", "compile(", "unpickle(",
        ]

        # 仅构造模式（没有实际执行）
        construction_only_patterns = [
            "newinstance(", "getclass(", "forname(",
            "getregistry(", "new initialdircontext(",
        ]

        has_execution = any(p in code for p in execution_patterns)
        is_construction_only = any(p in code for p in construction_only_patterns)

        if is_construction_only and not has_execution:
            return False

        # 检查是否只是返回字符串
        if "return" in code and ("\"" in code or "'" in code):
            # 进一步检查是否有危险操作
            if not has_execution:
                return False

        return True

    def _is_config_issue(self, finding: Finding) -> bool:
        """检查是否是配置问题"""
        # Dockerfile 问题
        if "dockerfile" in finding.location.file.lower():
            return True

        # 配置文件问题
        config_extensions = [".conf", ".yaml", ".yml", ".json", ".properties"]
        return any(finding.location.file.endswith(ext) for ext in config_extensions)

    def _is_unimplemented_code(self, finding: Finding) -> bool:
        """检查是否是未实现的代码"""
        code = (finding.location.snippet or "").lower()

        # 检查是否只是方法定义但没有调用
        # 这需要更复杂的静态分析，暂时简化
        return False
```

#### 集成点

```python
# 修改 src/layers/l3_analysis/engines/opencode_agent.py

def _parse_llm_response(
    self,
    response: str,
    file_path: str,
    source_path: Path,
) -> list[Finding]:
    """Parse LLM response into Finding objects."""
    findings = []

    try:
        data = robust_json_loads(response)

        # 新增：流式验证
        from src.layers.l3_analysis.pre_filter import StreamingValidator
        validator = StreamingValidator()

        for item in data.get("findings", []):
            finding = self._convert_to_finding(item, file_path, source_path)

            if finding is None:
                continue

            # 流式验证：每个 finding 都要验证
            accept, adjusted = validator.validate_finding(finding)

            if accept:
                findings.append(adjusted)
            else:
                self.logger.debug(
                    f"Filtered finding: {finding.title} - "
                    f"reason: {adjusted.metadata.get('validation_note', 'unknown')}"
                )

    except Exception as e:
        self.logger.error(f"Failed to parse LLM response: {e}")

    return findings
```

#### 验收标准

- [ ] 流式验证成功集成到 Agent 解析流程
- [ ] 明显误报在进入结果列表前被过滤
- [ ] 置信度校准合理

---

### P8-08d: CodeQL 预过滤器

**状态**: todo
**优先级**: P1
**依赖**: P8-08a
**文件**: `src/layers/l3_analysis/pre_filter/codeql_pre_filter.py`

#### 设计

```python
class CodeQLPreFilter:
    """
    CodeQL 预过滤器 - 在扫描前调整规则和扫描后过滤结果
    """

    def get_adjusted_rules(self, project_type: str) -> dict:
        """
        根据项目类型返回调整后的规则配置

        降低泛化规则的默认置信度，减少误报进入后续流程
        """
        return {
            # XSS 规则调整
            "javascript/xss*": {
                "confidence_penalty": 0.2,  # 默认降低置信度
                "requires_response_check": True,
            },
            "*/xss*": {
                "check_response_type": True,  # 检查响应类型
            },

            # SQL 注入规则
            "*/sql*": {
                "requires_taint_tracking": True,  # 需要污点追踪
            },
        }

    def should_accept_finding(self, finding: Finding) -> tuple[bool, str]:
        """
        判断是否接受 CodeQL finding

        这是在 CodeQL 扫描完成后的后处理
        """
        # XSS 规则需要检查响应类型
        if "xss" in finding.rule_id.lower():
            if not self._confirms_html_response(finding):
                return False, "XSS finding but no HTML response - reject"

        return True, "Accept"

    def _confirms_html_response(self, finding: Finding) -> bool:
        """
        检查是否确认是 HTML 响应

        简化版本：检查代码片段中是否有 HTML 渲染
        """
        code = (finding.location.snippet or "").lower()

        html_rendering_patterns = [
            "innerhtml", "outerhtml", "insertadjacenthtml",
            "document.write", "render(", "response.write",
            "<html", "{{", "${", "%>", "v-html="
        ]

        # 检查是否是 JSON 响应
        json_patterns = [
            "response.json(", "json(", "return {",
            "content-type: application/json",
            "@responsebody", "ResponseEntity"
        ]

        has_html = any(p in code for p in html_rendering_patterns)
        has_json = any(p in code for p in json_patterns)

        return has_html and not has_json
```

#### 集成点

```python
# 修改 src/layers/l3_analysis/engines/codeql.py

def scan(self, source_path, **options):
    # 新增：应用规则调整
    from src.layers.l3_analysis.pre_filter import CodeQLPreFilter
    pre_filter = CodeQLPreFilter()

    project_type = self._detect_project_type(source_path)
    adjusted_rules = pre_filter.get_adjusted_rules(project_type)

    # 应用调整后的规则
    self._apply_rule_adjustments(adjusted_rules)

    # 原有扫描逻辑...
    raw_findings = self._run_queries(...)

    # 新增：结果预过滤
    filtered = []
    for finding in raw_findings:
        accept, reason = pre_filter.should_accept_finding(finding)
        if accept:
            filtered.append(finding)
        else:
            self.logger.debug(f"Filtered CodeQL finding: {reason}")

    return filtered
```

#### 验收标准

- [ ] CodeQL XSS 误报率降低 ~50%
- [ ] 响应类型检测准确

---

### P8-08e: 去重前置

**状态**: todo
**优先级**: P0
**依赖**: P8-08c
**文件**: `src/layers/l3_analysis/pre_filter/in_memory_deduplicator.py`

#### 设计

```python
class InMemoryDeduplicator:
    """
    内存级去重器 - 在 Agent 产生 findings 时立即去重

    与 P6-17 的关系：
    - P6-17 (ClusterBasedDeduplicator) 是全局去重
      → 所有引擎 findings 汇总后去重
      → 使用 LLM 判断是否重复

    - P8-08e (InMemoryDeduplicator) 是前置去重
      → 单个文件扫描时立即去重
      → 基于规则（文件+行号）快速去重
      → 无需 LLM 调用

    两者协同：P8-08e 减少 P6-17 的输入，节省资源
    """

    def __init__(self):
        # 当前文件的去重缓存
        self.current_file_dedup = {}  # {(file, line): finding}
        # 调用链去重缓存
        self.call_chain_dedup = {}  # {vuln_hash: finding}

    def deduplicate_findings(
        self,
        findings: list[Finding],
        file_path: str
    ) -> list[Finding]:
        """
        对单个文件的 findings 进行去重

        1. 文件级去重：同一文件同一行号只保留最高分的
        2. 调用链去重：同一漏洞在不同层级只保留一个
        """
        deduped = []

        for finding in findings:
            # 1. 文件级去重
            line_key = (file_path, finding.location.line)
            if line_key in self.current_file_dedup:
                existing = self.current_file_dedup[line_key]
                if finding.final_score > existing.final_score:
                    # 新发现的分数更高，替换
                    deduped.remove(existing)
                    deduped.append(finding)
                    self.current_file_dedup[line_key] = finding
                # 否则跳过，保留现有的
            else:
                deduped.append(finding)
                self.current_file_dedup[line_key] = finding

            # 2. 调用链去重（基于漏洞类型）
            vuln_hash = self._get_vulnerability_hash(finding)
            if vuln_hash in self.call_chain_dedup:
                # 同一漏洞类型，只保留第一个（通常是调用链的最上层）
                # 或者保留分数最高的
                existing = self.call_chain_dedup[vuln_hash]
                if finding.final_score > existing.final_score:
                    # 从结果中移除旧的，添加新的
                    if existing in deduped:
                        deduped.remove(existing)
                    deduped.append(finding)
                    self.call_chain_dedup[vuln_hash] = finding
            else:
                self.call_chain_dedup[vuln_hash] = finding

        self.logger.info(
            f"In-memory deduplication: {len(findings)} -> {len(deduped)} findings"
        )

        return deduped

    def _get_vulnerability_hash(self, finding: Finding) -> str:
        """
        生成漏洞类型哈希，用于调用链去重

        同一漏洞在不同层级的特征：
        - 相同的 rule_id (漏洞类型)
        - 相同的 sink (危险函数)
        - 但不同的 file_path (调用链不同层级)
        """
        import hashlib

        # 提取 sink（危险函数）
        sink = self._extract_sink(finding)

        # 组合：rule_id + sink
        combined = f"{finding.rule_id}:{sink}"

        return hashlib.md5(combined.encode()).hexdigest()[:8]

    def _extract_sink(self, finding: Finding) -> str:
        """从 finding 中提取 sink（危险函数）"""
        code = (finding.location.snippet or "")

        # 简化版本：从代码中提取函数名
        import re
        match = re.search(r'(\w+)\s*\(', code)
        if match:
            return match.group(1)

        return "unknown"

    def clear(self):
        """清理缓存（每个文件扫描后调用）"""
        self.current_file_dedup.clear()
        # call_chain_dedup 可以保留，用于跨文件去重
```

#### 集成点

```python
# 修改 src/layers/l3_analysis/engines/opencode_agent.py

async def _analyze_single_file(self, ...):
    # 原有扫描逻辑...
    findings = self._parse_llm_response(...)

    # 新增：前置去重
    from src.layers.l3_analysis.pre_filter import InMemoryDeduplicator
    deduplicator = InMemoryDeduplicator()

    deduped_findings = deduplicator.deduplicate_findings(
        findings,
        str(file_path)
    )

    return deduped_findings
```

#### 与 P6-17 的协同

```
扫描流程：
├─ Agent 扫描文件 A
│  ├─ 产生 10 findings
│  └─ P8-08e 去重 → 6 findings (节省 40%)
│
├─ Agent 扫描文件 B
│  ├─ 产生 8 findings
│  └─ P8-08e 去重 → 5 findings (节省 37.5%)
│
└─ 汇总所有 findings (206 → 156，节省 ~24%)
   └─ P6-17 全局去重 → 140 findings
      └─ LLM 判断只处理 140 个，而非 206 个
```

#### 验收标准

- [ ] 文件级去重：同一文件同一行号只保留最高分
- [ ] 调用链去重：同一漏洞在不同层级只保留一个
- [ ] 与 P6-17 协同工作，无冲突

---

### P8-08f: 对抗验证准入门槛

**状态**: todo
**优先级**: P1
**依赖**: P8-08e
**文件**: `src/layers/l3_analysis/verification/verification_gatekeeper.py`

#### 设计

```python
class VerificationGatekeeper:
    """
    对抗验证门槛 - 决定是否需要对抗验证

    不是所有 finding 都需要昂贵的对抗验证
    明显的误报或明显的漏洞可以直接决定
    """

    def should_verify(self, finding: Finding) -> tuple[bool, str]:
        """
        判断是否需要对抗验证

        Returns:
            (should_verify, reason)
        """
        # 1. 明确的误报 → 跳过对抗验证
        if self._is_clear_false_positive(finding):
            return False, "Clear false positive - auto-reject"

        # 2. 强证据 → 跳过对抗验证
        if finding.confidence >= 0.9:
            if self._has_working_poc(finding):
                return False, "Strong evidence + working PoC - auto-confirm"

        # 3. 低置信度 + 低严重级 → 跳过对抗验证
        if finding.confidence < 0.5:
            if finding.severity in ["low", "info"]:
                return False, "Low confidence + low severity - needs_review only"

        # 4. 其他情况需要对抗验证
        return True, "Requires adversarial verification"

    def _is_clear_false_positive(self, finding: Finding) -> bool:
        """检查是否是明显的误报"""
        code = (finding.location.snippet or "").lower()

        # 明显的误报模式
        false_positive_patterns = [
            # 只有字符串拼接，没有实际操作
            ("return " in code and not any(op in code for op in [".execute(", ".run("])),

            # 只有注释或日志
            ("logger." in code and "return" not in code),

            # 只有变量赋值
            (len(code.split("=")) == 1 and "return" not in code),
        ]

        return any(pattern[0] and pattern[1] for pattern in false_positive_patterns)

    def _has_working_poc(self, finding: Finding) -> bool:
        """检查是否有可工作的 PoC"""
        # 检查 metadata 中是否有 PoC
        return finding.metadata.get("poc") is not None

    def auto_decide(self, finding: Finding, reason: str) -> str:
        """
        自动决定 finding 的状态

        Returns:
            status: "confirmed", "false_positive", "needs_review"
        """
        if "auto-reject" in reason:
            return "false_positive"
        elif "auto-confirm" in reason:
            return "confirmed"
        elif "needs_review" in reason:
            return "needs_review"
        else:
            return "needs_review"
```

#### 集成点

```python
# 修改 src/layers/l3_analysis/verification/enhanced_adversarial.py

async def verify_findings(self, findings: List[Finding]):
    """使用准入门槛过滤后再进行对抗验证"""

    # 新增：验证门槛
    from src.layers.l3_analysis.verification import VerificationGatekeeper
    gatekeeper = VerificationGatekeeper()

    # 分类：需要验证 vs 可跳过
    to_verify = []
    auto_decided = []

    for finding in findings:
        should_verify, reason = gatekeeper.should_verify(finding)

        if should_verify:
            to_verify.append(finding)
        else:
            # 自动决定
            status = gatekeeper.auto_decide(finding, reason)
            finding.status = status
            finding.metadata["auto_decision"] = reason
            auto_decided.append(finding)

    self.logger.info(
        f"Verification gatekeeper: {len(auto_decided)} auto-decided, "
        f"{len(to_verify)} require adversarial verification"
    )

    # 只对需要验证的进行对抗验证
    if to_verify:
        verified = await self._run_adversarial_verification(to_verify)
        return verified + auto_decided
    else:
        return auto_decided
```

#### 验收标准

- [ ] 对抗验证减少 ~40%
- [ ] 明显误报自动拒绝
- [ ] 强证据自动确认

---

### P8-08g: 集成测试与效果评估

**状态**: todo
**优先级**: P1
**依赖**: P8-08f

#### 测试计划

1. **端到端测试**
   - 扫描 `java-test-app-obf` 测试项目
   - 对比实施前后的误报率

2. **资源消耗对比**
   - Token 消耗
   - 扫描时间
   - 对抗验证次数

3. **调优参数**
   - 置信度阈值
   - 过滤规则

#### 验收标准

- [ ] Agent 误报率降低 ~50%
- [ ] CodeQL 误报率降低 ~50%
- [ ] 重复检测率降低 ~56%
- [ ] Token 消耗减少 ~30%
- [ ] 扫描时间减少 ~20%

---

### P8-08h: 修复 P6-17 LLM 去重解析

**状态**: todo
**优先级**: P0
**依赖**: P8-08e
**文件**: `src/layers/l3_analysis/deduplicator.py`

#### 问题分析

从扫描日志发现：
```
ERROR Failed to parse LLM response: Expecting value: line 1 column 1 (char 0)
ERROR Failed to parse JSON: Extra data: line 1 column 2 (char 1)
INFO  Cluster deduplication complete: 171 -> 157 findings
```

**根因**: GLM-5 返回的 JSON 格式不稳定，可能包含：
- `reasoning_content` 字段（思考过程）
- 非标准 JSON 格式
- 多余的换行或注释

#### 修复方案

```python
# 修改 src/layers/l3_analysis/deduplicator.py

class ClusterBasedDeduplicator:
    """两阶段混合去重器（修复版）"""

    def _parse_llm_response(self, response: str) -> dict:
        """
        解析 LLM 响应，增强容错性

        处理 GLM-5 的非标准 JSON 格式
        """
        # 1. 尝试标准 JSON 解析
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # 2. 处理 GLM-5 的 reasoning_content 格式
        # 格式：{"reasoning_content": "...", "content": "{...}"}
        if "reasoning_content" in response:
            # 提取 content 字段
            import re
            match = re.search(r'"content"\s*:\s*({.*?})\s*(?:,|"|$)', response, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except:
                    pass

        # 3. 处理多余的文本（注释、说明）
        # 提取第一个完整的 JSON 对象
        import re
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except:
                pass

        # 4. 最后尝试：清理后解析
        cleaned = self._clean_json_string(response)
        try:
            return json.loads(cleaned)
        except:
            # 解析失败，返回空结果
            self.logger.error(f"Failed to parse LLM response after all attempts")
            return {"findings": []}

    def _clean_json_string(self, s: str) -> str:
        """清理 JSON 字符串"""
        # 移除注释
        lines = []
        for line in s.split('\n'):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#'):
                continue
            lines.append(line)

        cleaned = '\n'.join(lines)

        # 移除尾随逗号
        cleaned = re.sub(r',\s*}', '}', cleaned)
        cleaned = re.sub(r',\s*]', ']', cleaned)

        return cleaned
```

#### 验收标准

- [ ] GLM-5 响应解析成功率 > 95%
- [ ] 去重效果达到预期（171 → 140 findings）

---

## 目录结构

```
src/layers/l3_analysis/pre_filter/
├── __init__.py                        # 模块导出
├── file_pre_filter.py                 # P8-08a: 文件级预过滤
├── streaming_validator.py             # P8-08c: Finding 流式验证
├── codeql_pre_filter.py               # P8-08d: CodeQL 预过滤
├── in_memory_deduplicator.py           # P8-08e: 去重前置
└── config.py                          # 配置参数

src/layers/l3_analysis/prompts/
├── enhanced_audit_prompt.py           # P8-08b: 增强审计 Prompt
│   ├── ANTI_HALLUCINATION_RULES       # 防幻觉规则
│   ├── EXECUTION_EVIDENCE_REQUIREMENTS # 执行证据要求
│   └── FEW_SHOT_EXAMPLES             # Few-Shot 示例
└── security_audit.py                  # 修改：集成防幻觉规则

src/layers/l3_analysis/verification/
├── verification_gatekeeper.py         # P8-08f: 对抗验证门槛
└── enhanced_adversarial.py            # 修改：集成门槛

tests/unit/test_l3/test_pre_filter/
├── __init__.py
├── test_file_pre_filter.py            # P8-08a 测试
├── test_streaming_validator.py        # P8-08c 测试
├── test_codeql_pre_filter.py          # P8-08d 测试
├── test_in_memory_deduplicator.py      # P8-08e 测试
└── test_verification_gatekeeper.py    # P8-08f 测试
```

---

## 验收标准汇总

### 功能验收

- [ ] P8-08a: 文件预过滤器生效，配置文件被跳过
- [ ] P8-08b: Agent Prompt 增强，防幻觉规则生效
- [ ] P8-08c: 流式验证生效，明显误报被过滤
- [ ] P8-08d: CodeQL 预过滤生效，XSS 误报降低
- [ ] P8-08e: 去重前置生效，重复检测减少
- [ ] P8-08f: 对抗验证门槛生效，验证次数减少
- [ ] P8-08h: LLM 去重解析修复，去重效果恢复

### 效果验收

- [ ] Agent 误报率降低 ~50%（从 ~50% 到 ~25%）
- [ ] CodeQL 误报率降低 ~50%（从 ~80% 到 ~40%）
- [ ] 重复检测率降低 ~56%（从 ~46% 到 ~20%）
- [ ] 对抗验证减少 ~40%
- [ ] Token 消耗减少 ~30%
- [ ] 扫描时间减少 ~20%

### 测试验收

- [ ] 所有模块单元测试通过（覆盖率 > 80%）
- [ ] 端到端测试验证
- [ ] 对比测试：实施前后扫描同一项目

---

## 参考资源

### code-audit Skill

**路径**: `/opt/AI/code-audit/`

**关键文件**:
- **SKILL.md**:
  - Anti-Hallucination Rules (防幻觉规则)
  - 两层检查清单
  - 攻击链思维

- **agent.md**:
  - 执行控制器
  - Anti-Hallucination Rules 详细说明
  - 防激进扫描原则

**核心规则**:
```
⚠️ 严禁幻觉行为 - 违反此规则的发现将被视为无效

1. 先验证文件存在，再报告漏洞
2. 引用真实代码
3. 核心原则: 宁可漏报，不可误报
```

### 现有组件

- **Call Graph**: `src/layers/l3_analysis/call_graph/` (可达性验证)
- **P6-17 去重器**: `src/layers/l3_analysis/deduplicator.py` (全局去重)
- **对抗验证**: `src/layers/l3_analysis/verification/enhanced_adversarial.py`

### 分析报告

- **根因分析**: 2026-04-04 扫描分析
- **问题统计**: 87 个误报，46% 重复检测

---

## 已完成目标摘要

### P8-07: 规则库扩展

✅ **完成日期**: 2026-04-05
✅ **提交**: 851ba8d

**变更**:
- 新增 13 条框架规则（Flask 4, Django 2, FastAPI 1, Express 2, Java 2, Go 2）
- 实现 FrameworkDetector
- 覆盖 SSTI、硬编码密钥、XSS、SQL 注入、CORS、原型污染、反射误用等
