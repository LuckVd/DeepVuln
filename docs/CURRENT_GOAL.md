# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P2-03 OpenCode Agent 基础框架 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-19 |
| **完成日期** | 2026-02-19 |

---

## 背景说明

OpenCode Agent 是 DeepVuln 的核心 AI 审计引擎，利用大语言模型（LLM）进行深度代码审计。相比 Semgrep/CodeQL 的规则匹配，Agent 提供：

1. **语义理解能力**：理解代码上下文、业务逻辑
2. **灵活推理**：发现规则引擎无法覆盖的复杂漏洞
3. **自适应审计**：根据项目特征调整审计策略
4. **证据链构建**：追踪数据流并构建攻击路径

**设计理念**：
- Agent 为主，SAST 工具为辅
- 多轮递进审计（侦察→深度→关联）
- 攻击面驱动分析

---

## 完成标准

### Phase 1: 基础架构
- [x] 创建 `OpenCodeAgent` 类框架
- [x] 定义 Agent 接口（继承 `BaseEngine`）
- [x] 实现 LLM 客户端抽象层

### Phase 2: LLM 集成
- [x] 支持 OpenAI API
- [x] 支持本地模型（Ollama/OpenAI 兼容）
- [x] 实现请求重试和错误处理
- [x] Token 使用统计

### Phase 3: 审计能力
- [x] 代码片段分析 prompt 模板
- [x] 漏洞类型识别（15 种漏洞类型）
- [x] 结果转换为 `Finding` 模型
- [x] 置信度评估

### Phase 4: 集成与测试
- [x] 集成到 `EngineRegistry`
- [x] CLI 命令支持（`deepvuln agent`）
- [x] 单元测试覆盖（64 个测试）
- [x] 与 SmartScanner 协作

---

## 技术要点

### LLM 客户端设计

```python
class LLMClient(ABC):
    @abstractmethod
    async def complete(self, prompt: str, **options) -> str: ...

    @abstractmethod
    async def complete_with_context(
        self,
        system_prompt: str,
        user_prompt: str,
        context: list[dict],
    ) -> str: ...
```

### 支持的 LLM 提供商

| 提供商 | API | 配置 |
|--------|-----|------|
| OpenAI | GPT-4 / GPT-4-turbo | `OPENAI_API_KEY` |
| Azure OpenAI | GPT-4 | `AZURE_OPENAI_*` |
| Ollama | 本地模型 | `OLLAMA_BASE_URL` |
| OpenAI 兼容 | 任意 | `LLM_BASE_URL` + `LLM_API_KEY` |

### Prompt 模板结构

```
System: You are a security code auditor...

Context:
- Language: {language}
- File: {file_path}
- Related findings: {findings}

Code:
{code_snippet}

Task: Analyze for security vulnerabilities...
```

### Agent 输出格式

```json
{
  "findings": [
    {
      "type": "sql_injection",
      "severity": "high",
      "confidence": 0.9,
      "title": "...",
      "description": "...",
      "line": 42,
      "recommendation": "..."
    }
  ]
}
```

---

## 关联文件

### 已创建
- `src/layers/l3_analysis/engines/opencode_agent.py` - Agent 实现
- `src/layers/l3_analysis/llm/` - LLM 客户端模块
  - `client.py` - 抽象基类
  - `openai_client.py` - OpenAI 实现
  - `ollama_client.py` - Ollama 实现
- `src/layers/l3_analysis/prompts/` - Prompt 模板
  - `security_audit.py` - 安全审计模板
- `tests/unit/test_l3/test_opencode_agent.py` - Agent 单元测试（34 个测试）
- `tests/unit/test_l3/test_llm_client.py` - LLM 客户端测试（30 个测试）

### 已修改
- `src/layers/l3_analysis/__init__.py` - 导出 OpenCodeAgent
- `src/layers/l3_analysis/engines/__init__.py` - 注册 Agent
- `src/cli/main.py` - 添加 `agent` 命令

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-19 | 设置新目标：P2-03 OpenCode Agent 基础框架 |
| 2026-02-19 | 完成 LLM 客户端抽象层（LLMClient, OpenAIClient, OllamaClient） |
| 2026-02-19 | 完成安全审计 Prompt 模板（15 种漏洞类型） |
| 2026-02-19 | 完成 OpenCodeAgent 核心实现（继承 BaseEngine） |
| 2026-02-19 | 添加 CLI 命令 `deepvuln agent` |
| 2026-02-19 | 编写 64 个单元测试（全部通过） |
| 2026-02-19 | ✅ P2-03 OpenCode Agent 基础框架完成 |

---

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| LLM API 成本高 | 高 | 设置 token 上限、使用本地模型备选 |
| 输出格式不稳定 | 中 | 结构化 prompt + 结果解析 |
| 幻觉/误报 | 中 | 多轮验证、置信度评估 |
| 响应延迟 | 中 | 异步处理、超时控制 |

---

## 下一步

**目标已完成！** 建议下一个目标：P2-04 审计策略引擎（优先级计算）

### CLI 使用示例

```bash
# 使用 OpenAI
export OPENAI_API_KEY=sk-...
deepvuln agent --path ./src

# 使用 Ollama 本地模型
deepvuln agent --path ./src --provider ollama --model llama2

# 指定漏洞类型
deepvuln agent --path ./src --focus sql_injection --focus xss

# 过滤严重程度
deepvuln agent --path ./src --severity high --severity critical
```
