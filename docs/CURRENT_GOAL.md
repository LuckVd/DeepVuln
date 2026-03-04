# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P0-1：TechStackDetector 精度重构（全量扫描 + 主语言识别 + 项目画像输出） |
| **状态** | completed |
| **优先级** | P0 |
| **创建日期** | 2026-03-04 |
| **完成日期** | 2026-03-04 |
| **所属阶段** | Phase 2 - L2 项目理解层 |

---

## 约束条件

| 约束 | 说明 | 状态 |
|------|------|------|
| 只修改 L2 层 | 技术栈识别模块及相关数据模型 | ✅ |
| 禁止修改 L3 | 不修改分析引擎、规则引擎、Agent | ✅ |
| 保持 CLI 接口 | 不改变现有命令行参数 | ✅ |
| 向后兼容 | 保持原有接口调用方式 | ✅ |
| 不引入依赖 | 不添加第三方库 | ✅ |

---

## 当前问题（已解决）

| 问题 | 影响 | 解决方案 |
|------|------|----------|
| 仅返回 `set[Language]` | 无主次语言区分 | 新增 `LanguageInfo` 数据结构 |
| 无 `primary_language` | 无法驱动 Rule Gating | 添加 `primary_language` 字段 |
| 仅采样 100 文件 | 严重失真 | 删除采样，全量扫描 |
| 无 LOC 统计 | 无法判断语言占比 | 实现 LOC 统计 |
| 无项目类型识别 | 无法针对性扫描 | 实现 `project_type` 识别 |
| 无 test/docs 识别 | 误扫测试/文档代码 | 添加 `has_tests`/`has_docs` |

---

## 完成标准

### 1️⃣ 全量扫描（必须）

- [x] 删除 `sample_size = 100` 采样逻辑
- [x] 改为全量遍历项目文件（排除无关目录）

### 2️⃣ LanguageInfo 数据结构（必须）

- [x] 实现 `LanguageInfo` 数据类（Pydantic BaseModel）
- [x] 统计 file_count
- [x] 统计 line_count（非空行）
- [x] 统计 test_file_count
- [x] 统计 doc_file_count
- [x] 设置 role 字段
- [x] 添加 loc_percentage 字段

### 3️⃣ TechStack 数据模型（必须）

- [x] 添加 `languages: list[LanguageInfo]` 字段
- [x] 添加 `primary_language` 字段
- [x] 添加 `secondary_languages` 字段
- [x] 添加 `total_loc` 字段
- [x] 添加 `total_files` 字段
- [x] 添加 `project_type` 字段
- [x] 添加 `has_tests` 字段
- [x] 添加 `has_docs` 字段
- [x] 添加 `is_monorepo` 字段
- [x] 添加 `get_language_list()` 向后兼容方法

### 4️⃣ LOC 统计（必须）

- [x] 统计每种语言的 `file_count`
- [x] 统计每种语言的 `line_count`（非空行、非注释行）

### 5️⃣ 主语言判定规则（必须）

- [x] `primary_language` = 最大 LOC 的语言
- [x] `secondary_languages` = LOC 占比 > 10% 的语言
- [x] 占比 < 5% 的语言忽略

### 6️⃣ 测试文件识别（必须）

- [x] 识别测试目录 (`test/`, `tests/`, `spec/`, `__tests__/`)
- [x] 识别测试文件命名 (`test_*.py`, `*_test.py`, `*.spec.js`, etc.)
- [x] 设置 `has_tests = True/False`

### 7️⃣ 文档识别（必须）

- [x] 识别文档目录 (`docs/`, `doc/`)
- [x] 识别 Markdown 文件 (`.md`)
- [x] 设置 `has_docs = True/False`

### 8️⃣ Monorepo 识别（必须）

- [x] 检测多个包管理文件 (`package.json`, `setup.py`, `go.mod`, etc.)
- [x] 设置 `is_monorepo = True`

### 9️⃣ 项目类型识别（必须）

- [x] 实现 `ProjectType` 枚举 (`web`, `api`, `cli`, `library`, `unknown`)
- [x] Python web: Flask/Django/FastAPI
- [x] Node web: Express
- [x] CLI: argparse/click
- [x] Library: 无明显入口

---

## 变更文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/layers/l1_intelligence/tech_stack_detector/models.py` | 新增 | LanguageInfo + TechStack 数据模型 |
| `src/layers/l1_intelligence/tech_stack_detector/detector.py` | 重写 | 全量扫描 + LOC 统计 + 项目画像 |
| `src/layers/l1_intelligence/tech_stack_detector/__init__.py` | 修改 | 导出新模型 |
| `src/layers/l1_intelligence/workflow/auto_security_scan.py` | 修改 | 使用 `get_language_list()` |
| `src/cli/scan_display.py` | 修改 | 使用 `get_language_list()` |
| `src/layers/l1_intelligence/security_analyzer/analyzer.py` | 修改 | 使用 `get_language_list()` |
| `tests/unit/test_tech_stack_detector/test_detector.py` | 更新 | 适配新数据结构 |
| `tests/unit/test_cli/test_scan_display.py` | 更新 | 适配新数据结构 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-04 19:00 | 设置目标：TechStackDetector 精度重构 |
| 2026-03-04 19:10 | 创建 models.py，定义 LanguageInfo 和更新 TechStack |
| 2026-03-04 19:20 | 重写 detector.py，实现全量扫描和 LOC 统计 |
| 2026-03-04 19:30 | 实现主语言判定、测试/文档/monorepo 识别 |
| 2026-03-04 19:40 | 实现项目类型识别 |
| 2026-03-04 19:45 | 修复向后兼容性问题，更新使用点 |
| 2026-03-04 19:50 | 更新测试用例，所有测试通过 |
| 2026-03-04 20:00 | **任务完成** |

---

## 验收清单

- [x] 不再使用 100 文件采样
- [x] `primary_language` 始终正确
- [x] Markdown 不可能成为 primary（不在 EXTENSION_TO_LANGUAGE 中）
- [x] JS 不会成为 Swift 项目的 primary（基于 LOC 判定）
- [x] monorepo 可识别
- [x] 输出结构可用于 Rule Gating
- [x] 保持向后兼容（`get_language_list()` 方法）
- [x] 不删除原有 `Language` 枚举

---

## 可选增强（已实现）

- [x] 扫描性能日志（`get_scan_statistics()`）
- [x] LOC 百分比输出（`loc_percentage` 字段）
- [x] JSON 序列化支持（`to_dict()` 方法）

---

## 测试结果

```
tests/unit/test_tech_stack_detector/test_detector.py: 27 passed
tests/unit/test_cli/test_scan_display.py: 14 passed
Total: 41 passed, 0 failed
```

---

## 备注

- 此任务是 L2 层基础设施改进，不涉及 L3 分析逻辑
- 目标是为 Rule Gating 提供精确的技术栈画像
- 完成后可显著减少跨语言误报
- 向后兼容通过 `get_language_list()` 方法实现
