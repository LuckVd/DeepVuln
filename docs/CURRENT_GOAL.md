# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P3-05：Semgrep 文件级过滤（include/exclude/lang） |
| **状态** | completed |
| **优先级** | P1 |
| **创建日期** | 2026-03-04 |
| **完成日期** | 2026-03-04 |
| **所属阶段** | Phase 3 - 精度重构 |

---

## 目标概述

在 Semgrep 执行前，根据 TechStack、AttackSurface、has_tests、has_docs、is_monorepo 动态生成 `--include`、`--exclude`、`--exclude-dir`、`--lang` 参数，实现真正的扫描面控制。

**核心目标**：Markdown 永不被扫描、非主语言不进入扫描、无关目录永久排除。

---

## 约束条件

| 约束 | 说明 |
|------|------|
| 只允许新建 | `src/core/file_filtering.py` |
| 只允许修改 | `src/layers/l3_analysis/engines/semgrep.py` |
| 禁止修改 | Rule Gating、Finding Budget、CLI 接口、Agent、CodeQL、TechStack 数据模型 |

---

## 完成标准

### 1️⃣ FileFilteringResult 数据结构（必须）

```python
class FileFilteringResult:
    include_patterns: list[str]   # --include 参数
    exclude_patterns: list[str]   # --exclude 参数
    exclude_dirs: list[str]       # --exclude-dir 参数
    lang_flags: list[str]         # --lang 参数
```

- [x] 实现 `FileFilteringResult` 数据类
- [x] `include_patterns` 字段
- [x] `exclude_patterns` 字段
- [x] `exclude_dirs` 字段
- [x] `lang_flags` 字段

### 2️⃣ 永久排除目录（必须）

```python
DEFAULT_EXCLUDE_DIRS = [
    ".git", ".svn", ".hg",
    "node_modules", "dist", "build", "target",
    "__pycache__", ".venv", "venv", ".mypy_cache",
]
```

- [x] 实现永久排除目录列表
- [x] 传递给 `--exclude` 参数

### 3️⃣ Markdown 与文档排除（必须）

**必须排除**：
- `*.md`
- `docs/`
- `*.rst`

- [x] Markdown 文件永远不被扫描
- [x] docs 目录排除
- [x] RST 文件排除

### 4️⃣ 主语言过滤（必须）

**规则**：
- 根据 `primary_language` 设置 `--lang` 参数
- 如果有 `secondary_languages`，添加多个 `--lang`
- 禁止无关语言进入扫描

- [x] 根据 TechStack.languages 生成 lang_flags
- [x] 支持多语言项目
- [x] Monorepo 不使用单一语言限制

### 5️⃣ CLI 项目过滤（必须）

**如果 `project_type == "cli"`**：
- 不 include web 文件
- 不 include `templates/`
- 不 include `static/`

- [x] 检测 CLI 项目类型
- [x] 排除 web 相关目录

### 6️⃣ 无 HTTP 攻击面过滤（必须）

**如果 `attack_surface.http_endpoints == 0`**：
- 排除 `routes/`
- 排除 `controllers/`
- 排除 `api/`

- [x] 检测 HTTP 攻击面
- [x] 排除 web 相关目录（目录级，非规则级）

### 7️⃣ Tests 过滤策略（必须）

**默认**：不扫描 `tests/`

**例外**：`has_tests=True` 且 `project_type=library` 时扫描

- [x] 默认排除 tests 目录
- [x] library 项目例外处理

### 8️⃣ Monorepo 支持（必须）

**如果 `is_monorepo=True`**：
- 不使用 `--lang` 单一限制
- 仍使用 include 目录过滤

- [x] 检测 Monorepo
- [x] 不限制语言

### 9️⃣ Semgrep 集成（必须）

```python
filter_engine = FileFilteringEngine(tech_stack, attack_surface)
filter_result = filter_engine.build()

for d in filter_result.exclude_dirs:
    cmd.extend(["--exclude-dir", d])
for p in filter_result.exclude_patterns:
    cmd.extend(["--exclude", p])
for l in filter_result.lang_flags:
    cmd.extend(["--lang", l])
```

- [x] 在 SemgrepEngine 中集成 FileFilteringEngine
- [x] 传递所有过滤参数

### 🔟 Metadata 记录（必须）

在 `ScanResult.metadata` 中加入：

```json
{
  "file_filtering": {
    "excluded_dirs": ["node_modules", "build"],
    "excluded_patterns": ["*.md", "*.rst"],
    "lang_used": ["python", "javascript"]
  }
}
```

- [x] 存储排除目录
- [x] 存储排除模式
- [x] 存储使用的语言

---

## 三层过滤架构

| 层级 | 功能 | 参数 |
|------|------|------|
| 目录级 | 排除无关目录 | `--exclude` |
| 文件类型级 | 排除文档/配置 | `--exclude` |
| 语言级 | 限制扫描语言 | `--lang` |

---

## 必须保证

- [x] 不改变 CLI 参数
- [x] 不改变 Rule Gating
- [x] 不影响 Finding Budget
- [x] 不改变返回结果结构
- [x] 不影响 CodeQL
- [x] 不改写 TechStack 逻辑
- [x] 不动态删除规则 pack（属于 Rule Gating）

---

## 变更文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/core/file_filtering.py` | 新建 | 文件过滤引擎 |
| `src/layers/l3_analysis/engines/semgrep.py` | 修改 | 集成过滤引擎 |

---

## 实现优先级

| 优先级 | 功能 |
|--------|------|
| P0 | 目录排除 |
| P0 | Markdown 排除 |
| P0 | 语言过滤 |
| P1 | CLI 目录过滤 |
| P1 | HTTP 攻击面目录过滤 |
| P1 | Monorepo 处理 |
| P2 | Metadata 记录 |

---

## 实现顺序

1. ✅ 目录排除
2. ✅ Markdown 排除
3. ✅ 语言过滤
4. ✅ CLI 目录过滤
5. ✅ HTTP 攻击面目录过滤
6. ✅ Monorepo 处理

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-04 | 设置目标：Semgrep 文件级过滤 |
| 2026-03-04 | 实现 FileFilteringResult 和 FileFilteringEngine |
| 2026-03-04 | 集成到 SemgrepEngine |
| 2026-03-04 | 所有测试通过（1358 passed） |
| 2026-03-04 | 任务完成 |

---

## 验收清单

- [x] Markdown 永远不被扫描
- [x] node_modules 永远不被扫描
- [x] build/dist 永远不被扫描
- [x] 非主语言文件不会进入扫描
- [x] CLI 项目不扫描 web 目录
- [x] tests 默认不扫描
- [x] Monorepo 不报错
- [x] metadata 正确记录过滤信息

---

## 预期效果

实现后系统会：
- **Markdown 扫描 = 0** - 文档文件永久排除
- **无关目录排除** - node_modules/build 等永不扫描
- **语言精准匹配** - 只扫描项目实际使用的语言
- **攻击面驱动** - 无 HTTP 时不扫描 web 目录
- **与 Rule Gating 配合** - 实现完整的三级裁剪

---

## Phase 3 完成状态

当 P3-05 完成后：

| 功能 | 状态 |
|------|------|
| 规则裁剪 (Rule Gating) | ✅ |
| 文件裁剪 (File Filtering) | ✅ |
| 结果熔断 (Finding Budget) | ✅ |

**Phase 3 核心任务已全部完成！**

---

## 备注

- 此任务与 P3-04 Rule Gating、P3-07 Finding Budget 配合使用
- Rule Gating：规则级裁剪
- File Filtering：文件级裁剪
- Finding Budget：结果级熔断
- 三者结合实现 90%+ 噪声消除
