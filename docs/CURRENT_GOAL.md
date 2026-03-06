# 当前目标

> 单一焦点：本次会话关注的核心任务
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P5-01c：污点追踪与多维消毒剂检测 |
| **状态** | completed |
| **优先级** | P0 |
| **创建日期** | 2026-03-06 |
| **完成日期** | 2026-03-06 |
| **所属阶段** | Phase 5 - 精度深化 |
| **模块层级** | L3 Analysis Layer |
| **依赖** | P5-01b（已完成） |
| **父任务** | P5-01：可利用性评估增强 |

---

## 问题背景

当前消毒剂检测仅依赖语义匹配（已知库函数名），存在以下问题：

| 问题 | 现状 | 影响 |
|------|------|------|
| 检测维度单一 | 仅基于函数名 | 无法识别自定义消毒函数 |
| AST 变换分析 | 缺失 | 无法检测 str.replace/re.sub 等操作 |
| 类型检测 | 缺失 | 无法识别 SafeHtml/escape 装饰器 |
| 污点追踪 | 缺失 | 无法判断消毒剂是否阻断污点路径 |

---

## 核心目标

**实现多维消毒剂检测 + 反向污点追踪，准确判断漏洞可利用性。**

---

## 技术方案

### 1. 多维检测框架

```
src/layers/l3_analysis/call_graph/
├── models.py              # 扩展：TaintTraceResult, SanitizerMatchEx
├── transform_analyzer.py  # 新增：AST 变换分析
├── type_analyzer.py       # 新增：类型检测
└── taint_tracker.py       # 新增：污点追踪器
```

### 2. 核心数据模型

```python
class SanitizerDetectionMethod(str, Enum):
    TRANSFORM_ANALYSIS = "transform_analysis"  # AST-based
    TYPE_BASED = "type_based"  # Type/Decorator
    SEMANTIC = "semantic"  # Known library
    CODEQL = "codeql"  # CodeQL native

@dataclass
class TransformScore:
    has_replace_ops: bool
    has_encode_calls: bool
    dangerous_char_coverage: float
    is_sanitizer: bool
    confidence: float

@dataclass
class TaintTraceResult:
    source_id: str | None
    sink_id: str
    is_reachable: bool
    is_sanitized: bool
    sanitizers: list[SanitizerMatchEx]
    confidence: float

    @property
    def is_exploitable(self) -> bool:
        return self.is_reachable and not self.is_sanitized
```

### 3. 检测流程

```
1. TransformAnalyzer: 分析函数 AST
   - 检测 str.replace, re.sub 操作
   - 检测 html.escape, encodeURIComponent 调用
   - 计算危险字符覆盖率

2. TypeAnalyzer: 分析类型签名
   - 检测 SafeHtml, SafeSql 返回类型
   - 检测 @sanitizer, @escape 装饰器
   - 检测类型守卫模式

3. TaintTracker: 反向污点追踪
   - 从 sink 点出发 BFS
   - 检测路径上的消毒剂
   - 计算综合置信度

4. 综合判定:
   - 多维检测融合 (transform_weight=0.5, type_weight=0.3, semantic_weight=0.2)
   - 距离衰减 (distance_decay_factor=0.9)
   - 最终 is_exploitable 判定
```

---

## 新建文件

| 文件 | 用途 |
|------|------|
| `src/layers/l3_analysis/call_graph/transform_analyzer.py` | AST 变换分析 |
| `src/layers/l3_analysis/call_graph/type_analyzer.py` | 类型检测 |
| `src/layers/l3_analysis/call_graph/taint_tracker.py` | 污点追踪器 |
| `tests/unit/test_l3/test_transform_analyzer.py` | 变换分析测试 |
| `tests/unit/test_l3/test_taint_tracker.py` | 污点追踪测试 |

---

## 修改文件

| 文件 | 改动 |
|------|------|
| `src/layers/l3_analysis/call_graph/models.py` | 扩展：添加污点追踪模型 |

---

## 验收标准

| 标准 | 指标 |
|------|------|
| 变换分析 | 检测 replace/encode 操作，覆盖率计算 |
| 类型检测 | 识别安全返回类型、装饰器 |
| 污点追踪 | 反向 BFS，路径上消毒剂检测 |
| 多维融合 | 权重组合，置信度计算 |
| 测试覆盖 | 20+ 新测试 |
| 兼容性 | 现有测试全部通过 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-06 | 创建 P5-01c 目标 |
| 2026-03-06 | feat(l3): add P5-01c taint tracking models and analyzer skeleton |
| 2026-03-06 | feat(l3): implement P5-01c taint tracking with multi-dimensional sanitizer detection (完成) |
