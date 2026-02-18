# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P2-01 Semgrep 引擎集成 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-18 |
| **完成日期** | 2026-02-18 |

---

## 背景说明

Semgrep 是一个快速、可定制的静态分析工具，通过模式匹配检测代码中的安全问题。作为 L3 层的第一个组件，Semgrep 负责：

1. **快速扫描**：秒级完成代码扫描
2. **模式匹配**：检测已知漏洞模式（SQL注入、XSS、命令注入等）
3. **结果归一化**：将扫描结果转换为统一的 `Finding` 模型
4. **规则管理**：支持自定义规则 + 官方规则集

**为什么选择 Semgrep 作为 L3 第一个组件**：
- 实现简单，快速产出价值
- 无需构建索引（相比 CodeQL）
- 支持多语言（Java/Python/Go/JavaScript 等）
- 可与后续 Agent 形成互补

---

## 完成标准

### Phase 1: 核心引擎实现
- [ ] 创建 `src/layers/l3_analysis/` 目录结构
- [ ] 实现 `SemgrepEngine` 类
- [ ] 实现 `Finding` 通用数据模型
- [ ] 支持基本扫描功能

### Phase 2: 规则管理
- [ ] 创建 `rules/semgrep/` 规则目录
- [ ] 支持加载自定义规则
- [ ] 支持选择官方规则集（security、audit 等）
- [ ] 根据技术栈自动选择规则

### Phase 3: 结果处理
- [ ] 解析 Semgrep JSON 输出
- [ ] 转换为 `Finding` 模型
- [ ] 支持严重性过滤
- [ ] 支持结果去重

### Phase 4: 集成与测试
- [ ] 与 L1 层技术栈检测集成
- [ ] 单元测试覆盖
- [ ] 集成测试（使用测试项目）
- [ ] CLI 命令支持

---

## 技术方案

### 目录结构

```
src/layers/l3_analysis/
├── __init__.py
├── models.py                    # 通用数据模型
├── engines/
│   ├── __init__.py
│   ├── base.py                  # 引擎基类
│   └── semgrep.py               # Semgrep 引擎
└── rules/
    └── semgrep/                 # Semgrep 规则（符号链接到 rules/semgrep）

rules/semgrep/
├── java/
│   ├── sql-injection.yaml
│   ├── xss.yaml
│   └── ...
├── python/
│   ├── sql-injection.yaml
│   ├── command-injection.yaml
│   └── ...
└── config.yaml                  # 规则配置
```

### 核心接口设计

```python
# src/layers/l3_analysis/models.py

class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    SUSPICIOUS = "suspicious"
    INFO = "info"

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class CodeLocation(BaseModel):
    file: str
    line: int
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    snippet: str | None = None

class Finding(BaseModel):
    """通用漏洞发现模型"""
    id: str
    type: FindingType
    title: str
    description: str
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0)
    location: CodeLocation
    source: Literal["semgrep", "codeql", "agent"]
    rule_id: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    references: list[str] = Field(default_factory=list)
    fix_suggestion: str | None = None
    metadata: dict = Field(default_factory=dict)
```

```python
# src/layers/l3_analysis/engines/base.py

class BaseEngine(ABC):
    """分析引擎基类"""

    @abstractmethod
    async def scan(
        self,
        source_path: Path,
        **options,
    ) -> list[Finding]:
        """执行扫描"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """检查引擎是否可用"""
        pass
```

```python
# src/layers/l3_analysis/engines/semgrep.py

class SemgrepEngine(BaseEngine):
    """Semgrep 扫描引擎"""

    def __init__(
        self,
        semgrep_path: str = "semgrep",
        timeout: int = 300,
    ): ...

    async def scan(
        self,
        source_path: Path,
        rules: list[str] | None = None,      # 自定义规则路径
        rule_sets: list[str] | None = None,  # 官方规则集: ["security", "audit"]
        languages: list[str] | None = None,  # 限制语言
        severity_filter: list[SeverityLevel] | None = None,
    ) -> list[Finding]:
        """执行 Semgrep 扫描"""
        ...

    def is_available(self) -> bool:
        """检查 Semgrep CLI 是否安装"""
        ...

    def get_supported_languages(self) -> list[str]:
        """获取支持的语言列表"""
        ...
```

### Semgrep CLI 调用

```bash
# 基本调用
semgrep --config <rules> --json --quiet <source_path>

# 使用官方规则集
semgrep --config auto --json <source_path>

# 使用自定义规则
semgrep --config rules/semgrep/java/ --json <source_path>

# 指定语言
semgrep --lang java --json <source_path>
```

### 结果解析

Semgrep JSON 输出结构：
```json
{
  "results": [
    {
      "check_id": "java.lang.security.audit.xss.servlet-response.write",
      "path": "src/main/java/Controller.java",
      "start": { "line": 45, "col": 9 },
      "end": { "line": 45, "col": 50 },
      "extra": {
        "message": "Potential XSS vulnerability",
        "severity": "WARNING",
        "lines": "response.getWriter().write(userInput);",
        "metavars": {
          "$USER_INPUT": { ... }
        }
      }
    }
  ],
  "errors": []
}
```

---

## 关联文件

### 待创建
- `src/layers/l3_analysis/__init__.py` - 模块入口
- `src/layers/l3_analysis/models.py` - 数据模型
- `src/layers/l3_analysis/engines/__init__.py` - 引擎模块
- `src/layers/l3_analysis/engines/base.py` - 引擎基类
- `src/layers/l3_analysis/engines/semgrep.py` - Semgrep 实现
- `rules/semgrep/` - Semgrep 规则目录
- `tests/unit/test_l3/__init__.py` - 测试目录
- `tests/unit/test_l3/test_semgrep_engine.py` - Semgrep 测试

### 可能修改
- `src/core/config/settings.py` - 添加 L3 配置
- `ROADMAP.md` - 更新 P2-01 状态

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-18 | 设置新目标：P2-01 Semgrep 引擎集成 |
| 2026-02-18 | 完成 uv 环境配置，添加 semgrep 依赖，创建环境规范文档 |
| 2026-02-18 | 目标完成：环境配置就绪，可开始 SemgrepEngine 代码实现 |

---

## 备注

### 依赖要求
- Semgrep CLI >= 1.0.0
- Python >= 3.11

### 安装 Semgrep
```bash
# macOS/Linux
brew install semgrep

# 或使用 pip
pip install semgrep

# 验证安装
semgrep --version
```

### 规则来源
1. **官方规则集**：`p/security`, `p/owasp-top-ten`, `p/java`, `p/python`
2. **自定义规则**：`rules/semgrep/` 目录
3. **社区规则**：https://semgrep.dev/explore

### 关键约束
1. **超时控制**：大项目可能需要较长扫描时间
2. **内存限制**：Semgrep 默认内存限制可能需要调整
3. **规则质量**：自定义规则需要充分测试避免误报
