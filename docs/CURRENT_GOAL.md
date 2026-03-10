# 当前目标

> P6-02 CodeQL 失败结构化诊断
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P6-02 CodeQL 失败结构化诊断 |
| **状态** | pending |
| **优先级** | P0 |
| **创建日期** | 2026-03-11 |
| **所属阶段** | Phase 6 - 扫描结果可信度 |

---

## 问题背景

P6-01 已完成，现在 full scan 结果有了顶层 `status` 和 `failed_engines` 字段。但 CodeQL 失败时的诊断信息仍然不够详细：

当前输出：
```
FAILED - All language scans failed. Languages attempted: typescript, javascript
```

期望输出：
```
codeql [CORE]: db_create_failed
  Message: Database creation failed for typescript
  Stage: database creation
  Suggestion: Check if the project has valid TypeScript source files
```

---

## P6-02 子任务

### P6-02a：失败原因拆分

**修改文件**：`src/layers/l3_analysis/engines/codeql.py`

**新增错误类型枚举**：
```python
class CodeQLErrorType(Enum):
    NOT_INSTALLED = "not_installed"           # CodeQL CLI 未安装
    UNSUPPORTED_LANGUAGE = "unsupported_language"  # 语言不支持
    DB_CREATE_FAILED = "db_create_failed"     # 数据库创建失败
    BUILD_FAILED = "build_failed"             # 构建失败
    ANALYZE_FAILED = "analyze_failed"         # 分析失败
    TIMEOUT = "timeout"                        # 超时
    PACK_ERROR = "pack_error"                 # Query pack 错误
    UNKNOWN = "unknown"                        # 未知错误
```

**验收标准**：
- [ ] CodeQL 引擎输出结构化错误类型
- [ ] 错误类型可映射到 P6-01 的 `error_type` 字段

---

### P6-02b：多语言项目展示每种语言独立状态

**修改文件**：`src/layers/l3_analysis/engines/codeql.py`

**新增字段**：
```python
codeql_result["language_status"] = {
    "typescript": {"status": "failed", "stage": "db_create", "error": "..."},
    "javascript": {"status": "skipped", "reason": "dependency_failed"},
}
```

**验收标准**：
- [ ] 多语言项目显示每种语言独立状态
- [ ] 语言状态包含失败阶段信息

---

## P6-01 完成记录

| 项目 | 状态 |
|------|------|
| ScanStatus 枚举 | ✅ 已添加到 `models.py` |
| FailedEngineInfo 模型 | ✅ 已添加到 `models.py` |
| `_collect_failed_engines` 辅助函数 | ✅ 已添加到 `main.py` |
| `_determine_scan_status` 辅助函数 | ✅ 已添加到 `main.py` |
| 结果对象包含 `status` 字段 | ✅ |
| 结果对象包含 `failed_engines` 字段 | ✅ |
| 文本导出包含状态信息 | ✅ |
| 文本导出包含失败引擎详情 | ✅ |
| 单元测试 | ✅ 12 个新测试通过 |

---

## Phase 6 完整任务列表

### 阶段 1：结果状态模型
| 任务 | 描述 | 状态 |
|------|------|------|
| P6-01 | 扫描结果状态模型重构 | **done** ✅ |
| P6-02 | CodeQL 失败结构化诊断 | todo |

### 阶段 2：噪声治理
| 任务 | 描述 | 状态 |
|------|------|------|
| P6-03 | 证据强度字段引入 | todo |
| P6-04 | conditional/informational 细分 | todo |
| P6-05 | 术语重命名：Verified → Processed | todo |

### 阶段 3：覆盖率透明化
| 任务 | 描述 | 状态 |
|------|------|------|
| P6-06 | Agent 覆盖率统计 | todo |
| P6-07 | 目录分类与降权策略 | todo |
| P6-08 | 多语言覆盖矩阵 | todo |

### 阶段 4：测试与验收
| 任务 | 描述 | 状态 |
|------|------|------|
| P6-09~12 | 各模块测试 | todo |

---

## 验收指标

### P6-01 任务验收 ✅

| 指标 | 当前值 | 目标值 | 状态 |
|------|--------|--------|------|
| 顶层状态字段 | 有 | 有 | ✅ |
| 状态判定矩阵 | 完整定义 | 完整定义 | ✅ |
| failed_engines 结构化输出 | 有 | 有 | ✅ |
| CodeQL 失败时状态误读 | 低 | 低 | ✅ |

### Phase 6 总体验收

| 指标 | 当前值 | 目标值 |
|------|--------|--------|
| conditional 数量 | ~100 条 | <40 条 |
| evidence_strength 覆盖率 | 0% | 100% |
| Agent 覆盖率统计字段 | 无 | 6 个 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-11 | 完成 P6-01：扫描结果状态模型重构 |
| 2026-03-11 | 设置 P6-02 为当前目标 |
