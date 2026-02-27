# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 实现全 LLM 参与的通用入口点检测系统 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-27 |
| **完成日期** | 2026-02-27 |

---

## 背景

### 现状问题

当前入口点检测存在以下限制：

1. **框架绑定**：只支持固定的 Web 框架（Flask、FastAPI、Gin、Echo、Spring 等）
2. **LLM 限制过多**：
   - 需要 `--llm-detect` 参数才启用
   - 只检测"看起来像 HTTP"的文件（关键词过滤）
   - 只对静态检测失败的文件使用 LLM
3. **语言覆盖不全**：非主流框架、自定义框架无法识别

### 目标

取消所有 LLM 限制，让 LLM 全面参与入口点检测：

1. **项目结构分析**：把项目结构发给 LLM，让它判断哪些文件需要检测
2. **智能文件选择**：根据 LLM 返回，选择性地读取文件内容
3. **通用入口点识别**：LLM 分析代码内容，识别任意语言/框架的入口点
4. **无框架限制**：不再依赖预定义的框架检测器

---

## 完成标准

### P1: 设计 LLM 入口点检测架构
- [x] 设计两阶段 LLM 交互流程
- [x] 定义 Prompt 模板
- [x] 设计返回格式解析

### P2: 实现阶段 1 - 项目结构分析
- [x] 生成项目结构树
- [x] LLM 分析需要检测的文件
- [x] 解析 LLM 返回的文件列表

### P3: 实现阶段 2 - 入口点识别
- [x] 读取 LLM 选中的文件内容
- [x] LLM 分析代码识别入口点
- [x] 解析并标准化入口点格式

### P4: 集成到现有系统
- [x] 修改 `AttackSurfaceDetector` 支持 LLM 主导模式
- [x] 添加 CLI 参数 `--llm-full-detect`
- [x] 保持向后兼容（静态检测仍可用）

### P5: 测试验证
- [x] 测试 PandaWiki（Go 自定义框架）- 检测到入口点
- [x] 测试 DeepVuln（Python 自定义 HTTP）- 检测到 17 个入口点
- [x] 添加单元测试 - 44 个测试全部通过

---

## 实现方案

### 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                    LLM Full Detection Flow                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 1: Project Structure Analysis                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Source Code                                              │   │
│  │      │                                                    │   │
│  │      ▼                                                    │   │
│  │  Generate Project Tree (files, dirs, extensions)         │   │
│  │      │                                                    │   │
│  │      ▼                                                    │   │
│  │  LLM: "分析项目结构，判断哪些文件可能包含入口点"           │   │
│  │      │                                                    │   │
│  │      ▼                                                    │   │
│  │  Return: [file1.go, file2.py, handler/, api/...]         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Phase 2: Entry Point Detection                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  For each selected file:                                  │   │
│  │      │                                                    │   │
│  │      ▼                                                    │   │
│  │  Read file content                                        │   │
│  │      │                                                    │   │
│  │      ▼                                                    │   │
│  │  LLM: "分析代码，识别所有入口点（HTTP/RPC/gRPC/MQ/Cron）"  │   │
│  │      │                                                    │   │
│  │      ▼                                                    │   │
│  │  Return: [{type, path, handler, line, framework}, ...]   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Prompt 模板设计

**Phase 1 - 项目结构分析**:
```
分析以下项目结构，识别可能包含外部入口点的文件或目录。

入口点类型包括：
- HTTP/Web API endpoints
- RPC services (gRPC, Dubbo, Thrift)
- Message Queue consumers
- Scheduled jobs/Cron
- WebSocket handlers
- CLI commands (如果暴露给外部)

项目结构：
{project_tree}

请返回 JSON 格式：
{
  "target_files": ["path/to/file1", "path/to/file2"],
  "target_dirs": ["handler/", "api/"],
  "reasoning": "简要说明选择原因"
}
```

**Phase 2 - 入口点识别**:
```
分析以下代码，识别所有外部入口点。

文件: {file_path}
语言: {language}

代码：
```
{code_content}
```

请返回 JSON 格式：
{
  "entry_points": [
    {
      "type": "http|rpc|grpc|mq|cron|ws|cli",
      "method": "GET|POST|...",
      "path": "/api/path",
      "handler": "function_name",
      "line": 42,
      "framework": "detected_framework_or_custom",
      "description": "简要描述"
    }
  ],
  "framework_detected": "gin|flask|custom|unknown",
  "confidence": 0.0-1.0
}
```

### 关键文件修改

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/layers/l1_intelligence/attack_surface/llm_detector.py` | 重构 | 实现两阶段 LLM 检测 |
| `src/layers/l1_intelligence/attack_surface/detector.py` | 修改 | 添加 LLM 主导模式 |
| `src/cli/main.py` | 修改 | 添加 `--llm-full-detect` 参数 |
| `tests/unit/test_l1/test_llm_detector.py` | 新增 | LLM 检测器测试 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-27 15:40 | 设置新目标：全 LLM 参与的通用入口点检测 |
| 2026-02-27 16:00 | 完成 P1: 两阶段 LLM 检测架构设计 |
| 2026-02-27 16:15 | 完成 P2-P4: 实现并集成到 CLI |
| 2026-02-27 16:20 | 测试 PandaWiki: LLM 全检测成功识别入口点 |
| 2026-02-27 17:00 | 测试 DeepVuln: 检测到 17 个入口点（8 HTTP + 4 Cron + 5 CLI） |
| 2026-02-27 17:05 | 完成单元测试：44 个测试全部通过 |

---

## 验证标准

1. PandaWiki（Go 自定义框架）能检测到入口点
2. copyparty（Python 自定义 HTTP）入口点检测不退化
3. 支持任意语言/框架，不依赖预定义检测器
4. LLM 检测可独立使用，不强制依赖静态检测
