# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P2-02 CodeQL 引擎集成 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-19 |
| **完成日期** | 2026-02-19 |

---

## 背景说明

CodeQL 是 GitHub 开发的代码分析引擎，通过构建代码数据库进行深度数据流分析。相比 Semgrep 的模式匹配，CodeQL 提供：

1. **深度数据流分析**：追踪数据从源点到汇点的完整路径
2. **污点分析**：检测用户输入如何影响敏感操作
3. **跨函数/跨文件追踪**：发现复杂调用链中的漏洞
4. **自定义查询**：使用 QL 语言编写精确的漏洞查询

**为什么需要 CodeQL**：
- Semgrep 擅长快速模式匹配，但缺乏数据流追踪
- CodeQL 能发现 Semgrep 漏掉的复杂漏洞
- 两者互补，提高检测覆盖率

---

## 完成标准

### Phase 1: 环境准备
- [x] CodeQL CLI 安装验证
- [x] 创建 `CodeQLEngine` 类框架
- [x] 数据库构建功能（create database）

### Phase 2: 核心功能
- [x] 支持多种语言数据库构建（Java/Python/Go/JavaScript/C#/Ruby/C++）
- [x] 执行 QL 查询并解析结果
- [x] 转换为统一的 `Finding` 模型
- [x] 集成到 `EngineRegistry`

### Phase 3: 查询管理
- [x] 创建 `rules/codeql/` 目录
- [x] 支持自定义 QL 查询
- [x] 内置常用安全查询（SQL注入、XSS、命令注入等）

### Phase 4: 集成与测试
- [x] 与 SmartScanner 集成
- [x] 单元测试覆盖（35个测试用例）
- [x] CLI 命令支持（`deepvuln codeql`）

---

## 技术要点

### CodeQL CLI 依赖

```bash
# 下载 CodeQL CLI
# https://github.com/github/codeql-cli-binaries/releases

# 构建数据库
codeql database create <db-path> --language=<lang> --source-root=<src>

# 执行查询
codeql database analyze <db-path> <query-pack> --format=sarif-latest --output=<output.sarif>
```

### 支持的语言

| 语言 | CodeQL 支持 | 优先级 |
|------|-------------|--------|
| Java | ✅ | P0 |
| Python | ✅ | P0 |
| Go | ✅ | P1 |
| JavaScript | ✅ | P1 |
| C/C++ | ✅ | P2 |

### 输出格式

CodeQL 输出 SARIF 格式，需要解析为 Finding 模型。

---

## 关联文件

### 待创建
- `src/layers/l3_analysis/engines/codeql.py` - CodeQL 引擎实现
- `rules/codeql/` - CodeQL 查询目录
- `tests/unit/test_l3/test_codeql_engine.py` - 单元测试

### 待修改
- `src/layers/l3_analysis/__init__.py` - 导出 CodeQLEngine
- `src/layers/l3_analysis/engines/__init__.py` - 注册 CodeQL
- `src/cli/main.py` - 添加 `codeql` CLI 命令

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-19 | 设置新目标：P2-02 CodeQL 引擎集成 |
| 2026-02-19 | 完成 CodeQLEngine 核心实现（数据库创建、分析、SARIF解析） |
| 2026-02-19 | 安装 CodeQL CLI v2.24.1 到 /opt/codeql/ |
| 2026-02-19 | 创建 rules/codeql/ 目录及示例查询 |
| 2026-02-19 | 添加 CLI 命令 `deepvuln codeql` |
| 2026-02-19 | 编写 35 个单元测试 |
| 2026-02-19 | 修复数据库创建路径重复问题（cwd=None） |
| 2026-02-19 | 修复查询包兼容性问题（使用特定安全查询目录） |
| 2026-02-19 | ✅ CodeQL 扫描测试成功（0 findings，符合预期） |

---

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| CodeQL CLI 安装复杂 | 高 | 提供安装脚本，支持自动下载 |
| 数据库构建失败 | 中 | 降级到 Semgrep + Agent 方案 |
| 内存消耗大 | 中 | 限制项目大小，提供增量构建 |
| 查询学习曲线 | 低 | 提供内置查询库，降低使用门槛 |

---

## 下一步

1. ~~验证 CodeQL CLI 是否已安装~~ ✅
2. ~~创建 CodeQLEngine 基础框架~~ ✅
3. ~~实现数据库构建功能~~ ✅

**目标已完成！** 建议下一个目标：P2-03 OpenCode Agent 基础框架
