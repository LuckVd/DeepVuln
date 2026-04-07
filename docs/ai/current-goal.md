# Current Goal

## 目标信息

**ID**: P10-00-web-service-persistence
**标题**: Web 服务与持久化存储
**阶段**: Phase 10
**优先级**: P0
**创建日期**: 2026-04-07

---

## 目标描述

建立完整的 Web 服务后端，支持项目管理、扫描任务管理和结果持久化。

### 范围

- ✅ PostgreSQL 数据库设计与迁移
- ✅ Pydantic 数据模型 (请求/响应)
- ✅ FastAPI 应用框架
- ✅ 项目管理 REST API
- ✅ 扫描任务 REST API
- ✅ 数据库 Repository 层
- ✅ CLI 集成服务
- ✅ API 测试覆盖

### 架构决策

| 决策点 | 选择 | 理由 |
|--------|------|------|
| 数据库 | PostgreSQL (仅) | 统一环境，使用 Docker |
| 认证 | API Key | 简单有效，适合内部使用 |
| ORM | SQLAlchemy 2.0 | 异步支持，生态成熟 |
| 迁移工具 | Alembic | 标准 Python 迁移工具 |

---

## 实施计划

### S1: 数据库设计与迁移 (P10-01)

**文件**:
- `migrations/versions/001_init_schema.py`
- `migrations/env.py`
- `src/web/models/database.py`

**数据表**:
```sql
-- projects: 项目信息
CREATE TABLE projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    source_type VARCHAR(50) NOT NULL,
    source_path TEXT NOT NULL,
    branch VARCHAR(255),
    commit_hash VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_scan_id INTEGER REFERENCES scans(id),
    metadata JSONB
);

-- scans: 扫描任务 (增强版，参考 DeepAudit AgentTask)
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,

    -- 任务基本信息
    status VARCHAR(50) NOT NULL,           -- pending/running/paused/completed/failed/cancelled
    scan_type VARCHAR(50) NOT NULL,        -- full/base/incremental
    config JSONB NOT NULL,

    -- 进度跟踪 (细粒度)
    current_phase VARCHAR(50),             -- L1_preparation, L1_attack_surface, L2_semgrep, L2_codeql, L3_agent, L3_adjudication, report_generation
    current_step VARCHAR(255),             -- 当前执行步骤描述 (如 "正在分析文件 foo.py")
    current_engine VARCHAR(100),           -- 当前执行的引擎 (semgrep/codeql/agent/ast_engine)

    -- 进度百分比 (自动计算，基于阶段权重)
    progress_percent INTEGER DEFAULT 0,

    -- 文件统计
    total_files INTEGER DEFAULT 0,
    indexed_files INTEGER DEFAULT 0,
    analyzed_files INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0,
    files_with_findings INTEGER DEFAULT 0,

    -- 引擎统计
    engines_completed INTEGER DEFAULT 0,   -- 已完成的引擎数量
    engines_total INTEGER DEFAULT 5,       -- 总引擎数量 (semgrep/codeql/agent/ast_engine/adjudication)

    -- LLM/Token 统计
    tokens_used INTEGER DEFAULT 0,
    tokens_budget INTEGER DEFAULT 100000,
    llm_requests_count INTEGER DEFAULT 0,

    -- 发现统计 (参考 DeepAudit)
    findings_count INTEGER DEFAULT 0,
    verified_count INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,

    -- 质量评分
    quality_score REAL DEFAULT 0.0,
    coverage_score REAL DEFAULT 0.0,

    -- 时间记录
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    estimated_completion TIMESTAMP,

    -- 错误信息
    error_message TEXT,
    failed_engines JSONB,                  -- 失败的引擎信息

    -- 检查点数据 (用于暂停/续扫)
    checkpoint_data JSONB,

    -- 结果引用
    report_path TEXT,

    INDEX idx_scans_status (status),
    INDEX idx_scans_project (project_id)
);

-- scan_phases: 阶段状态 (增强版，支持引擎级追踪)
CREATE TABLE scan_phases (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    -- 阶段信息
    phase_name VARCHAR(100) NOT NULL,     -- L1_preparation, L1_attack_surface, L2_semgrep, L2_codeql, L3_agent, L3_adjudication, report_generation
    engine_name VARCHAR(100),              -- semgrep/codeql/agent/ast_engine/adjudication
    status VARCHAR(50) NOT NULL,           -- pending/running/completed/failed/skipped

    -- 进度描述
    current_step VARCHAR(255),             -- 当前步骤描述
    progress_percent INTEGER DEFAULT 0,    -- 阶段内进度

    -- 统计信息 (引擎级)
    files_processed INTEGER DEFAULT 0,
    findings_found INTEGER DEFAULT 0,      -- 本阶段发现的漏洞数
    tokens_used INTEGER DEFAULT 0,         -- 本阶段消耗的 token

    -- 时间记录
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,

    -- 输出数据
    output_path TEXT,                      -- 阶段输出文件路径
    output_data JSONB,                     -- 阶段输出数据 (可复用)

    -- 错误信息
    error_message TEXT,

    created_at TIMESTAMP DEFAULT NOW(),

    INDEX idx_scan_phases_scan (scan_id),
    INDEX idx_scan_phases_status (status)
);

-- scan_events: 扫描事件流 (实时进度更新，参考 DeepAudit AgentEvent)
CREATE TABLE scan_events (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    phase_id INTEGER REFERENCES scan_phases(id) ON DELETE CASCADE,

    -- 事件信息
    event_type VARCHAR(50) NOT NULL,       -- 详见事件类型列表
    event_level VARCHAR(20) DEFAULT 'info', -- debug/info/warning/error

    -- 事件内容
    message TEXT,
    details JSONB,                         -- 事件详情

    -- 引擎信息
    engine_name VARCHAR(100),

    -- Agent 特定信息 (对抗辩论/对话)
    agent_turn INTEGER DEFAULT 0,          -- Agent 轮次
    agent_role VARCHAR(50),                -- user/assistant/system/critic/verifier
    agent_message TEXT,                    -- Agent 消息内容
    agent_reasoning TEXT,                  -- Agent 推理过程 (如果有)

    -- 文件处理信息
    file_path TEXT,                        -- 当前处理的文件
    file_index INTEGER DEFAULT 0,          -- 文件序号 (1-based)
    file_total INTEGER DEFAULT 0,          -- 总文件数

    -- Token 消耗 (本事件)
    tokens_used INTEGER DEFAULT 0,
    tokens_input INTEGER DEFAULT 0,
    tokens_output INTEGER DEFAULT 0,

    -- 关联的发现
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,

    -- 序号 (用于排序)
    sequence INTEGER DEFAULT 0,

    created_at TIMESTAMP DEFAULT NOW(),

    INDEX idx_scan_events_scan (scan_id),
    INDEX idx_scan_events_type (event_type),
    INDEX idx_scan_events_created (created_at)
);

-- 事件类型定义 (event_type)
-- phase_start: 阶段开始
-- phase_complete: 阶段完成
-- engine_start: 引擎开始
-- file_start: 开始处理文件
-- file_complete: 文件处理完成
-- agent_thinking: Agent 思考中
-- agent_action: Agent 执行动作
-- agent_observation: Agent 观察结果
-- adversarial_start: 对抗验证开始
-- adversarial_round: 对抗轮次
-- adversarial_complete: 对抗验证完成
-- finding_new: 新发现漏洞
-- finding_verified: 漏洞已验证
-- finding_false_positive: 确认为误报
-- progress: 进度更新
-- error: 错误
-- warning: 警告
-- info: 信息

-- findings: 漏洞结果
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    phase_id INTEGER REFERENCES scan_phases(id) ON DELETE CASCADE,

    -- 漏洞信息
    vuln_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence REAL,                       -- 0.0 - 1.0

    -- 位置信息
    file_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    function_name VARCHAR(255),

    -- 详情
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,                         -- 证据代码片段
    remediation TEXT,                      -- 修复建议

    -- 状态
    status VARCHAR(50) DEFAULT 'pending',  -- pending/confirmed/false_positive/conditional

    -- 引擎来源
    engine VARCHAR(50) NOT NULL,           -- semgrep/codeql/agent/ast_engine/adjudication

    -- 额外元数据
    metadata JSONB,

    -- CPG 路径 (Phase 9 集成)
    cpg_path JSONB,

    created_at TIMESTAMP DEFAULT NOW(),

    INDEX idx_findings_scan (scan_id),
    INDEX idx_findings_severity (severity),
    INDEX idx_findings_vuln_type (vuln_type),
    INDEX idx_findings_file_path (file_path)
);

-- scan_files: 文件状态 (增量扫描)
CREATE TABLE scan_files (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    file_hash VARCHAR(64),
    scanned_at TIMESTAMP DEFAULT NOW(),
    findings_count INTEGER DEFAULT 0,

    INDEX idx_scan_files_scan (scan_id),
    INDEX idx_scan_files_path (file_path)
);

-- api_keys: API 密钥
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP
);
```

### S2: Pydantic 数据模型 (P10-02)

**文件**:
- `src/web/models/__init__.py`
- `src/web/models/project.py`
- `src/web/models/scan.py`
- `src/web/models/finding.py`
- `src/web/models/checkpoint.py`

**枚举类型**:
```python
class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanType(str, Enum):
    FULL = "full"
    BASE = "base"
    INCREMENTAL = "incremental"

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    CONDITIONAL = "conditional"
```

### S3: FastAPI 项目初始化 (P10-03)

**文件**:
- `src/web/main.py`
- `src/web/core/__init__.py`
- `src/web/core/database.py`
- `src/web/core/config.py`
- `src/web/core/security.py`

**目录结构**:
```
src/web/
├── api/
│   ├── __init__.py
│   ├── deps.py
│   └── v1/
│       ├── api.py
│       ├── projects.py
│       ├── scans.py
│       └── findings.py
├── api/
│   └── websocket/                    # WebSocket 支持
│       ├── __init__.py
│       └── scans.py
├── core/
│   ├── __init__.py
│   ├── database.py
│   ├── config.py
│   └── security.py
├── models/
│   ├── __init__.py
│   ├── project.py
│   ├── scan.py
│   ├── finding.py
│   └── event.py                      # 事件模型
├── repositories/
│   ├── __init__.py
│   ├── base.py
│   ├── project.py
│   ├── scan.py
│   ├── finding.py
│   └── event.py                      # 事件仓库
├── services/
│   ├── __init__.py
│   ├── scan_executor.py
│   ├── cli_adapter.py
│   └── progress_tracker.py           # 进度跟踪服务
└── main.py
```

**新增依赖**:
```toml
[project.optional-dependencies]
web = [
    "fastapi>=0.109.0",
    "uvicorn[standard]>=0.27.0",
    "sqlalchemy[asyncio]>=2.0.25",
    "alembic>=1.13.0",
    "asyncpg>=0.29.0",
    "passlib[bcrypt]>=1.7.4",
    "websockets>=12.0",           # WebSocket 支持
    "python-multipart>=0.0.6",    # 表单数据支持
]
```

### S4: Repository 层 (P10-06)

**文件**:
- `src/web/repositories/base.py` (AsyncRepository 基类)
- `src/web/repositories/project.py`
- `src/web/repositories/scan.py`
- `src/web/repositories/finding.py`

### S5: 项目管理 API (P10-04)

**端点**:
```
POST   /api/v1/projects          # 创建项目
GET    /api/v1/projects          # 列出项目 (分页/过滤)
GET    /api/v1/projects/{id}     # 获取详情
PUT    /api/v1/projects/{id}     # 更新项目
DELETE /api/v1/projects/{id}     # 删除项目
GET    /api/v1/projects/{id}/scans # 扫描历史
```

### S6: 扫描任务 API (P10-05)

**端点**:
```
POST   /api/v1/scans                        # 创建扫描
GET    /api/v1/scans                        # 列出扫描
GET    /api/v1/scans/{id}                   # 获取详情
GET    /api/v1/scans/{id}/progress          # 获取进度 (增强版)
GET    /api/v1/scans/{id}/phases            # 获取阶段详情
GET    /api/v1/scans/{id}/events            # 获取事件流
GET    /api/v1/scans/{id}/agent-conversation # 获取 Agent 对话 (新增)
GET    /api/v1/scans/{id}/current-file      # 获取当前处理文件详情 (新增)
WS     /api/v1/ws/scans/{id}/progress       # WebSocket 实时进度
GET    /api/v1/scans/{id}/findings          # 获取漏洞
GET    /api/v1/scans/{id}/report            # 获取报告
```

**进度响应格式** (参考 DeepAudit):
```json
{
  "scan_id": 123,
  "status": "running",
  "progress_percent": 45,
  "current_phase": "L3_agent",
  "current_step": "正在分析 src/main.py (文件 15/200)",
  "current_engine": "agent",

  // 文件统计
  "total_files": 200,
  "indexed_files": 200,
  "analyzed_files": 15,
  "files_with_findings": 3,

  // 引擎统计
  "engines": {
    "completed": ["L1_preparation", "L1_attack_surface", "L2_semgrep"],
    "running": "L3_agent",
    "pending": ["L2_codeql", "L3_adjudication", "report_generation"]
  },

  // Token 统计
  "tokens": {
    "used": 12500,
    "budget": 100000,
    "percent": 12.5
  },

  // 发现统计
  "findings": {
    "total": 8,
    "verified": 5,
    "false_positive": 1,
    "by_severity": {
      "critical": 1,
      "high": 2,
      "medium": 3,
      "low": 2,
      "info": 0
    }
  },

  // 阶段详情
  "phases": [
    {
      "name": "L1_preparation",
      "status": "completed",
      "duration_seconds": 5,
      "findings": 0
    },
    {
      "name": "L1_attack_surface",
      "status": "completed",
      "duration_seconds": 15,
      "findings": 0
    },
    {
      "name": "L2_semgrep",
      "status": "completed",
      "duration_seconds": 120,
      "findings": 5
    },
    {
      "name": "L3_agent",
      "status": "running",
      "progress_percent": 7,
      "tokens_used": 12500,
      "findings": 3
    }
  ],

  // 时间信息
  "started_at": "2026-04-07T10:30:00Z",
  "estimated_completion": "2026-04-07T12:15:00Z"
}
```

**Agent 对话响应** (GET /api/v1/scans/{id}/agent-conversation):
```json
{
  "scan_id": 123,
  "phase": "L3_agent",
  "current_file": {
    "path": "src/main.py",
    "index": 15,
    "total": 200,
    "findings_in_file": 1
  },
  "conversation": [
    {
      "turn": 1,
      "role": "user",
      "message": "分析以下代码是否存在 SQL 注入漏洞...",
      "tokens": 150
    },
    {
      "turn": 2,
      "role": "assistant",
      "message": "分析中...发现 user_input 变量直接拼接到 SQL 查询中...",
      "reasoning": "首先检查数据流：user_input -> query.execute()...",
      "tokens": {
        "input": 150,
        "output": 280
      }
    },
    {
      "turn": 3,
      "role": "critic",
      "message": "我需要验证这个漏洞是否真实存在...",
      "tokens": {
        "input": 430,
        "output": 200
      }
    },
    {
      "turn": 4,
      "role": "verifier",
      "message": "正在构造验证用例...",
      "action": "call_tool",
      "tool_name": "code_query",
      "tool_input": {
        "query": "SELECT * FROM users WHERE name = '...'"
      }
    }
  ],
  "adversarial_status": {
    "active": true,
    "round": 2,
    "max_rounds": 5,
    "current_findings": 1,
    "verifying_finding_id": "uuid-xxx"
  }
}
```

**当前文件详情** (GET /api/v1/scans/{id}/current-file):
```json
{
  "scan_id": 123,
  "current_file": {
    "path": "src/main.py",
    "index": 15,
    "total": 200,
    "size_bytes": 2048,
    "language": "python"
  },
  "file_preview": {
    "lines": [
      "1: from flask import Flask, request",
      "2: app = Flask(__name__)",
      "3:",
      "4: @app.route('/user/<name>')",
      "5: def get_user(name):",
      "6:     query = f\"SELECT * FROM users WHERE name = '{name}'\"",
      "7:     # ↑ 潜在 SQL 注入点",
      "8:     return execute_query(query)"
    ],
    "highlighted_lines": [6],  // 正在分析的行
    "findings_in_file": [
      {
        "line": 6,
        "severity": "high",
        "title": "SQL 注入",
        "status": "verifying"
      }
    ]
  },
  "agent_actions_on_file": [
    {
      "timestamp": "10:45:23",
      "action": "ast_analysis",
      "result": "found 3 function calls"
    },
    {
      "timestamp": "10:45:25",
      "action": "dataflow_trace",
      "result": "tracked source: name -> sink: execute"
    },
    {
      "timestamp": "10:45:28",
      "action": "adversarial_start",
      "result": "verifying finding #1"
    }
  ]
}
```

**实时事件流** (WebSocket):
```json
// 文件开始处理
{
  "type": "file_start",
  "message": "开始分析 src/main.py",
  "data": {
    "file": "src/main.py",
    "index": 15,
    "total": 200
  }
}

// Agent 思考
{
  "type": "agent_thinking",
  "message": "Agent 正在分析...",
  "data": {
    "file": "src/main.py",
    "turn": 2,
    "role": "assistant",
    "message": "分析中...发现 user_input 变量直接拼接到 SQL 查询中..."
  },
  "tokens_used": 280
}

// 对抗辩论开始
{
  "type": "adversarial_start",
  "message": "开始对抗验证",
  "data": {
    "finding_id": "uuid-xxx",
    "finding_title": "SQL 注入",
    "max_rounds": 5
  }
}

// 对抗轮次
{
  "type": "adversarial_round",
  "message": "Critic 质疑：这个漏洞可能被框架防护",
  "data": {
    "round": 2,
    "role": "critic",
    "message": "Flask 的路由参数可能已经做了转义...",
    "previous_message": "Assistant: 这里是 SQL 注入点"
  },
  "tokens_used": 350
}

// 工具调用
{
  "type": "agent_action",
  "message": "Verifier 调用代码查询工具",
  "data": {
    "role": "verifier",
    "tool_name": "code_query",
    "tool_input": {
      "query": "查找 name 参数的来源"
    }
  }
}

// 新发现
{
  "type": "finding_new",
  "message": "发现 SQL 注入漏洞",
  "data": {
    "engine": "agent",
    "file": "src/main.py",
    "line": 6,
    "severity": "high",
    "title": "用户输入未过滤直接拼接到 SQL 查询"
  },
  "tokens_used": 150
}

// 文件完成
{
  "type": "file_complete",
  "message": "完成分析 src/main.py",
  "data": {
    "file": "src/main.py",
    "index": 15,
    "total": 200,
    "findings_found": 1,
    "tokens_used": 1200
  }
}
```

### S7: CLI 集成服务 (P10-07)

**文件**:
- `src/web/services/scan_executor.py` (ScanExecutor)
- `src/web/services/cli_adapter.py` (CLIAdapter)
- `src/web/services/progress_tracker.py` (ProgressTracker)
- `src/web/services/event_streamer.py` (EventStreamer)

**CLI 输出格式** (需要适配现有 CLI):

方案 A: **JSONL 流式输出** (推荐)
```jsonl
{"type": "phase_start", "phase": "L3_agent", "timestamp": "2026-04-07T10:30:00Z"}
{"type": "file_start", "file": "src/main.py", "index": 15, "total": 200}
{"type": "agent_thinking", "role": "assistant", "message": "分析中...", "tokens": 280}
{"type": "finding_new", "file": "src/main.py", "line": 6, "severity": "high", "title": "SQL 注入"}
{"type": "adversarial_start", "finding_id": "xxx", "rounds": 5}
{"type": "adversarial_round", "round": 1, "role": "critic", "message": "质疑...", "tokens": 350}
{"type": "finding_verified", "finding_id": "xxx", "is_valid": true}
{"type": "file_complete", "file": "src/main.py", "findings": 1, "tokens": 1200}
```

方案 B: **Structured Logging** (复用现有日志)
```python
# CLI 输出到 stdout，带特殊前缀
print("[DV_PROGRESS]{"type": "file_start", ...}")
print("[DV_AGENT]{"type": "thinking", "message": "..."}")
print("[DV_FINDING]{"type": "new", ...}")
```

**解析流程**:
1. CLIAdapter 按行读取 stdout
2. 识别前缀或解析 JSON
3. 转换为 scan_events 记录
4. 通过 WebSocket 实时推送到前端

**流程**:
1. 接收扫描请求
2. 调用 CLI 子进程
3. **实时解析 CLI 输出，提取**:
   - 当前阶段/引擎/步骤
   - 文件处理进度
   - Token 消耗
   - 新发现漏洞
4. **写入 scan_events 表** (用于 WebSocket 推送)
5. 更新 scans/scan_phases 表状态
6. 解析最终 JSON 结果入库

### S8: API 测试 (P10-08)

**文件**:
- `tests/integration/test_api/test_projects.py`
- `tests/integration/test_api/test_scans.py`
- `tests/unit/test_web/repositories/`

---

## 完成总结 (2026-04-07)

### 已完成任务

| 步骤 | 任务 | 状态 | 完成日期 |
|------|------|------|----------|
| S1 | 数据库设计与迁移 (P10-01) | ✅ | 2026-04-07 |
| S2 | Pydantic 数据模型 (P10-02) | ✅ | 2026-04-07 |
| S3 | FastAPI 项目初始化 (P10-03) | ✅ | 2026-04-07 |
| S4 | Repository 层实现 (P10-06) | ✅ | 2026-04-07 |

### 新增文件 (26 个)

**数据库迁移**:
- `migrations/alembic.ini`
- `migrations/env.py`
- `migrations/script.py.mako`
- `migrations/versions/001_init_schema.py`

**数据模型** (7 个):
- `src/web/models/__init__.py`
- `src/web/models/database.py`
- `src/web/models/project.py`
- `src/web/models/scan.py`
- `src/web/models/finding.py`
- `src/web/models/checkpoint.py`
- `src/web/models/schemas.py`

**Repository 层** (6 个):
- `src/web/repositories/__init__.py`
- `src/web/repositories/base.py`
- `src/web/repositories/project.py`
- `src/web/repositories/scan.py`
- `src/web/repositories/finding.py`
- `src/web/repositories/event.py`

**核心模块** (4 个):
- `src/web/main.py`
- `src/web/core/__init__.py`
- `src/web/core/database.py`
- `src/web/core/config.py`
- `src/web/core/security.py`

**API 路由** (5 个):
- `src/web/api/__init__.py`
- `src/web/api/deps.py`
- `src/web/api/v1/__init__.py`
- `src/web/api/v1/api.py`
- `src/web/api/v1/projects.py` (占位)
- `src/web/api/v1/scans.py` (占位)

**单元测试** (4 个):
- `tests/unit/test_web/__init__.py`
- `tests/unit/test_web/models/__init__.py`
- `tests/unit/test_web/models/test_models.py`
- `tests/unit/test_web/models/test_schemas.py`
- `tests/unit/test_web/repositories/__init__.py`

### 测试结果

| 测试类型 | 通过 | 详情 |
|----------|------|------|
| 数据模型测试 | 10/10 ✅ | SQLAlchemy 模型验证 |
| Schema 测试 | 15/15 ✅ | Pydantic 验证测试 |
| Repository 测试 | 7/7 ✅ | 数据库操作测试 |
| Main 测试 | 9/9 ✅ | FastAPI 应用测试 |
| **总计** | **41/41** ✅ | 100% 通过 |

### 修改文件

- `pyproject.toml` - 添加 web 依赖 (fastapi, uvicorn, sqlalchemy, alembic, asyncpg)
- `docs/ai/current-goal.md` - 创建目标文档
- `docs/ai/current-goal.state.yaml` - 更新状态

### 下一步任务

| 步骤 | 任务 | 优先级 | 状态 |
|------|------|--------|------|
| S5 | 项目管理 API (P10-04) | P1 | in_progress |
| S6 | 扫描任务 API (P10-05) | P0 | pending |
| S7 | CLI 集成服务 (P10-07) | P0 | pending |
| S8 | API 测试 (P10-08) | P1 | pending |

---

## 验收标准

- [ ] 所有 API 端点可正常调用
- [ ] 数据库迁移可执行
- [ ] 单元测试覆盖率 > 80%
- [ ] 集成测试通过
- [ ] OpenAPI 文档自动生成 (`/docs`)
- [ ] 可通过 API 创建项目并启动扫描

---

## 实现检查清单

### 数据库 (P10-01)
- [ ] 创建 Alembic 配置
- [ ] 编写初始迁移脚本
- [ ] 创建 updated_at 触发器
- [ ] 单元测试: 表结构验证

### 数据模型 (P10-02)
- [ ] 枚举类型定义 (ScanStatus/PhaseName/EventType)
- [ ] Project 模型系列
- [ ] Scan 模型系列 (增强版，含 token/finding 统计)
- [ ] ScanPhase 模型 (引擎级追踪)
- [ ] ScanEvent 模型 (事件流)
- [ ] Finding 模型系列
- [ ] Checkpoint 模型系列
- [ ] 请求/响应模型 (ProgressResponse 包含详细统计)

### FastAPI 初始化 (P10-03)
- [ ] 创建目录结构
- [ ] 添加依赖到 pyproject.toml
- [ ] 数据库连接池配置
- [ ] 配置管理 (复用现有 Settings)
- [ ] CORS 中间件
- [ ] 生命周期管理
- [ ] API Key 认证中间件

### Repository 层 (P10-06)
- [ ] AsyncRepository 基类
- [ ] ProjectRepository
- [ ] ScanRepository
- [ ] ScanPhaseRepository (新增)
- [ ] ScanEventRepository (新增)
- [ ] FindingRepository
- [ ] 单元测试

### 项目 API (P10-04)
- [ ] POST /api/v1/projects
- [ ] GET /api/v1/projects (分页)
- [ ] GET /api/v1/projects/{id}
- [ ] PUT /api/v1/projects/{id}
- [ ] DELETE /api/v1/projects/{id}
- [ ] GET /api/v1/projects/{id}/scans
- [ ] 集成测试

### 扫描 API (P10-05)
- [ ] POST /api/v1/scans
- [ ] GET /api/v1/scans
- [ ] GET /api/v1/scans/{id}
- [ ] GET /api/v1/scans/{id}/progress (增强版)
- [ ] GET /api/v1/scans/{id}/phases
- [ ] GET /api/v1/scans/{id}/events
- [ ] GET /api/v1/scans/{id}/agent-conversation (新增)
- [ ] GET /api/v1/scans/{id}/current-file (新增)
- [ ] WebSocket /api/v1/ws/scans/{id}/progress
- [ ] GET /api/v1/scans/{id}/findings
- [ ] GET /api/v1/scans/{id}/report
- [ ] 集成测试

### CLI 集成 (P10-07)
- [ ] CLIAdapter 子进程调用
- [ ] 输出解析器 (提取阶段/引擎/步骤/token/finding)
- [ ] ProgressTracker 服务
- [ ] 事件写入 scan_events 表
- [ ] 进度更新机制
- [ ] 结果入库逻辑
- [ ] 错误处理

### WebSocket 支持 (新增)
- [ ] WebSocket 连接管理器
- [ ] 扫描进度广播服务
- [ ] 事件流订阅机制
- [ ] 心跳与重连处理

### API 测试 (P10-08)
- [ ] 项目 API 测试
- [ ] 扫描 API 测试
- [ ] Repository 测试
- [ ] 端到端测试

---

## 集成点

| 现有组件 | 集成方式 |
|----------|----------|
| `src/core/config/settings.py` | 扩展添加 `DatabaseSettings` |
| CLI `deepvuln` 命令 | 通过子进程调用，解析 JSONL 输出 |
| 现有 Finding 模型 | 映射到数据库 findings 表 |

### CLI 输出改造需求

为支持细粒度进度追踪，现有 CLI 需要增加以下输出：

**1. 文件级别事件**
```python
# 在每个文件处理开始/结束时
log_event("file_start", file=path, index=i, total=n)
log_event("file_complete", file=path, findings=k, tokens=t)
```

**2. Agent 对话输出**
```python
# 在 LLM 调用时
log_event("agent_thinking", role="assistant", message="...", tokens=280)
log_event("adversarial_round", round=1, role="critic", message="...")
```

**3. 对抗验证追踪**
```python
# 在对抗验证时
log_event("adversarial_start", finding_id=xxx, rounds=5)
log_event("finding_verified", finding_id=xxx, is_valid=True)
```

**4. Token 消耗追踪**
```python
# 每次 LLM 调用后
log_event("llm_call", model="gpt-4", tokens_in=150, tokens_out=280)
```

---

## 风险与依赖

| 风险 | 缓解措施 |
|------|----------|
| PostgreSQL 不可用 | 提供 Docker Compose 配置 |
| CLI JSON 输出格式变化 | 版本化 CLI 接口 |
| 异步数据库复杂性 | 使用 SQLAlchemy 2.0 异步模式 |

---

## 里程碑

**v0.95**: Web 服务与持久化
- FastAPI 后端可运行
- PostgreSQL 数据库就绪
- API 端点可调用
