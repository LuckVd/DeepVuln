# DeepVuln 前后端 + 持久化 + 暂停/续扫 架构规划

> 版本: v1.0
> 创建日期: 2026-04-07
> 状态: 规划阶段

---

## 一、整体架构设计

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DeepVuln 系统架构                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐               │
│  │   前端        │─────│   后端        │─────│   数据库      │               │
│  │   (Web UI)    │ API │   (FastAPI)  │ SQL │  (PostgreSQL)│               │
│  │   React + TS  │     │   Python 3.12│     │   持久化存储  │               │
│  └──────────────┘     └──────────────┘     └──────────────┘               │
│         │                    │                    │                        │
│         │                    │                    │                        │
│         ▼                    ▼                    ▼                        │
│   ┌──────────┐        ┌──────────┐        ┌──────────┐                  │
│   │ 扫描管理  │        │ 扫描引擎  │        │ 报告存储  │                  │
│   │ 创建/查看  │        │ CLI 调用  │        │ JSON 结果 │                  │
│   │ 暂停/继续  │        │ 状态同步  │        │ 历史记录  │                  │
│   └──────────┘        └──────────┘        └──────────┘                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 二、数据模型设计

### 2.1 核心数据模型

```sql
-- 项目表
CREATE TABLE projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    source_type VARCHAR(50) NOT NULL,  -- 'local', 'git', 'zip'
    source_path TEXT NOT NULL,
    branch VARCHAR(255),                -- Git 分支
    commit_hash VARCHAR(255),           -- Git commit
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_scan_id INTEGER REFERENCES scans(id),
    metadata JSONB                      -- 存储额外信息
);

-- 扫描任务表
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL,        -- 'pending', 'running', 'paused', 'completed', 'failed', 'cancelled'
    scan_type VARCHAR(50) NOT NULL,     -- 'full', 'base', 'incremental'

    -- 扫描配置
    config JSONB NOT NULL,              -- 扫描配置参数

    -- 进度跟踪
    current_phase VARCHAR(50),          -- 当前执行阶段
    progress_percent INTEGER DEFAULT 0,

    -- 统计信息
    files_scanned INTEGER DEFAULT 0,
    total_files INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,

    -- 时间记录
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    estimated_completion TIMESTAMP,

    -- 错误信息
    error_message TEXT,
    failed_engines JSONB,              -- 失败的引擎信息

    -- 检查点数据（用于暂停/续扫）
    checkpoint_data JSONB,

    -- 结果引用
    report_path TEXT,                   -- 报告文件路径

    UNIQUE(project_id, created_at)     -- 允许同一项目多次扫描
);

-- 扫描阶段记录表（用于续扫时恢复状态）
CREATE TABLE scan_phases (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    phase_name VARCHAR(100) NOT NULL,   -- 'L1_attack_surface', 'L2_semgrep', 'L3_codeql', 'L3_agent'
    status VARCHAR(50) NOT NULL,        -- 'pending', 'running', 'completed', 'failed', 'skipped'
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,

    -- 阶段输出数据
    output_data JSONB,                 -- 阶段输出（可复用）

    -- 错误信息
    error_message TEXT,

    created_at TIMESTAMP DEFAULT NOW()
);

-- 漏洞结果表
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    -- 漏洞信息
    vuln_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence REAL,                    -- 0.0 - 1.0

    -- 位置信息
    file_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,

    -- 详情
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,                      -- 证据代码片段
    remediation TEXT,                   -- 修复建议

    -- 状态
    status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'confirmed', 'false_positive', 'conditional'

    -- 引擎来源
    engine VARCHAR(50) NOT NULL,        -- 'semgrep', 'codeql', 'agent', 'ast_engine'

    -- 额外元数据
    metadata JSONB,

    created_at TIMESTAMP DEFAULT NOW(),

    -- 索引优化
    INDEX idx_findings_scan_severity (scan_id, severity),
    INDEX idx_findings_file_path (file_path),
    INDEX idx_findings_vuln_type (vuln_type)
);

-- 扫描文件表（用于增量扫描）
CREATE TABLE scan_files (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    file_path TEXT NOT NULL,
    file_hash VARCHAR(64) NOT NULL,     -- MD5 hash

    -- 扫描状态
    scan_status VARCHAR(50) NOT NULL,   -- 'pending', 'scanning', 'completed', 'skipped', 'failed'

    -- 结果统计
    findings_count INTEGER DEFAULT 0,

    created_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(scan_id, file_path)
);

-- API 密钥表
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,     -- SHA256 hash
    name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP
);
```

### 2.2 Python 数据模型 (Pydantic)

```python
# src/web/models/project.py

from datetime import datetime
from enum import Enum
from typing import Optional, Literal, Any
from pydantic import BaseModel, Field, field_validator


class SourceType(str, Enum):
    LOCAL = "local"
    GIT = "git"
    ZIP = "zip"


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


# ============================================================================
# 项目模型
# ============================================================================

class ProjectCreate(BaseModel):
    """创建项目请求"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    source_type: SourceType
    source_path: str
    branch: Optional[str] = "main"
    metadata: Optional[dict[str, Any]] = None


class ProjectUpdate(BaseModel):
    """更新项目请求"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class Project(BaseModel):
    """项目模型"""
    id: int
    name: str
    description: Optional[str]
    source_type: SourceType
    source_path: str
    branch: Optional[str]
    commit_hash: Optional[str]
    created_at: datetime
    updated_at: datetime
    last_scan_id: Optional[int]
    metadata: dict[str, Any]

    class Config:
        from_attributes = True


# ============================================================================
# 扫描任务模型
# ============================================================================

class ScanConfig(BaseModel):
    """扫描配置"""
    engines: list[str] = Field(
        default=["semgrep", "codeql", "agent"],
        description="启用的引擎列表"
    )
    max_files: Optional[int] = Field(
        default=50,
        ge=1,
        le=1000,
        description="Agent 最大分析文件数"
    )
    timeout: Optional[int] = Field(
        default=7200,
        ge=60,
        description="扫描超时时间（秒）"
    )
    languages: Optional[list[str]] = None
    depth: Optional[int] = Field(
        default=3,
        ge=1,
        description="调用图深度"
    )


class ScanCreate(BaseModel):
    """创建扫描任务"""
    project_id: int
    scan_type: ScanType = ScanType.FULL
    config: ScanConfig = Field(default_factory=ScanConfig)


class ScanProgress(BaseModel):
    """扫描进度"""
    scan_id: int
    status: ScanStatus
    current_phase: Optional[str]
    progress_percent: int
    files_scanned: int
    total_files: int
    findings_count: int
    started_at: Optional[datetime]
    estimated_completion: Optional[datetime]
    error_message: Optional[str]


class Scan(BaseModel):
    """扫描任务"""
    id: int
    project_id: int
    status: ScanStatus
    scan_type: ScanType
    config: ScanConfig
    current_phase: Optional[str]
    progress_percent: int
    files_scanned: int
    total_files: int
    findings_count: int
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    estimated_completion: Optional[datetime]
    error_message: Optional[str]
    failed_engines: Optional[dict[str, Any]]
    checkpoint_data: Optional[dict[str, Any]]
    report_path: Optional[str]

    class Config:
        from_attributes = True


# ============================================================================
# 漏洞结果模型
# ============================================================================

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    CONDITIONAL = "conditional"
    FALSE_POSITIVE = "false_positive"


class FindingCreate(BaseModel):
    """创建漏洞记录"""
    scan_id: int
    vuln_type: str
    severity: SeverityLevel
    confidence: float = Field(..., ge=0.0, le=1.0)
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    title: str
    description: str
    evidence: Optional[str]
    remediation: Optional[str]
    engine: str
    status: FindingStatus = FindingStatus.PENDING
    metadata: Optional[dict[str, Any]] = None


class Finding(BaseModel):
    """漏洞记录"""
    id: int
    scan_id: int
    vuln_type: str
    severity: SeverityLevel
    confidence: float
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    title: str
    description: str
    evidence: Optional[str]
    remediation: Optional[str]
    engine: str
    status: FindingStatus
    metadata: dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# 检查点模型（用于暂停/续扫）
# ============================================================================

class PhaseName(str, Enum):
    L1_PREPARATION = "L1_preparation"
    L1_ATTACK_SURFACE = "L1_attack_surface"
    L2_SEMGREP = "L2_semgrep"
    L2_CODEQL = "L2_codeql"
    L3_AGENT = "L3_agent"
    L3_ADJUDICATION = "L3_adjudication"
    REPORT_GENERATION = "report_generation"


class PhaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class CheckpointData(BaseModel):
    """检查点数据（扫描状态快照）"""
    scan_id: int
    current_phase: PhaseName

    # 各阶段状态
    phases: dict[str, Any] = Field(
        default_factory=dict,
        description="各阶段的状态和数据"
    )

    # 全局状态
    global_state: dict[str, Any] = Field(
        default_factory=dict,
        description="全局扫描状态"
    )

    # 可恢复数据
    resume_data: dict[str, Any] = Field(
        default_factory=dict,
        description="用于恢复扫描的数据"
    )

    # 时间戳
    saved_at: datetime = Field(default_factory=datetime.now)


class ScanPhase(BaseModel):
    """扫描阶段记录"""
    id: int
    scan_id: int
    phase_name: str
    status: PhaseStatus
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    output_data: Optional[dict[str, Any]]
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
```

---

## 三、后端架构设计 (FastAPI)

### 3.1 目录结构

```
src/web/
├── api/
│   ├── __init__.py
│   ├── deps.py                  # 依赖注入
│   ├── v1/
│   │   ├── __init__.py
│   │   ├── api.py               # 路由聚合
│   │   ├── projects.py          # 项目管理
│   │   ├── scans.py             # 扫描管理
│   │   ├── findings.py          # 漏洞管理
│   │   └── reports.py           # 报告管理
│   └── websocket/
│       └── scans.py             # WebSocket (进度推送)
│
├── core/
│   ├── __init__.py
│   ├── database.py              # 数据库连接
│   ├── config.py                # 配置管理
│   └── security.py              # 认证授权
│
├── services/
│   ├── __init__.py
│   ├── project_service.py       # 项目业务逻辑
│   ├── scan_service.py          # 扫描业务逻辑
│   ├── scan_executor.py         # 扫描执行器（核心）
│   ├── checkpoint_service.py    # 检查点管理
│   └── report_service.py        # 报告生成
│
├── models/
│   ├── __init__.py
│   ├── project.py               # 项目模型
│   ├── scan.py                  # 扫描模型
│   ├── finding.py               # 漏洞模型
│   └── checkpoint.py            # 检查点模型
│
└── main.py                       # FastAPI 应用入口
```

### 3.1 核心 API 端点

```python
# src/web/api/v1/projects.py

from fastapi import APIRouter, HTTPException, Depends
from typing import List

from ..deps import get_db
from ...models.project import Project, ProjectCreate, ProjectUpdate
from ...services.project_service import ProjectService

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=Project)
async def create_project(
    data: ProjectCreate,
    service: ProjectService = Depends()
):
    """创建新项目"""
    return await service.create_project(data)


@router.get("", response_model=List[Project])
async def list_projects(
    skip: int = 0,
    limit: int = 100,
    service: ProjectService = Depends()
):
    """列出所有项目"""
    return await service.list_projects(skip=skip, limit=limit)


@router.get("/{project_id}", response_model=Project)
async def get_project(
    project_id: int,
    service: ProjectService = Depends()
):
    """获取项目详情"""
    project = await service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.put("/{project_id}", response_model=Project)
async def update_project(
    project_id: int,
    data: ProjectUpdate,
    service: ProjectService = Depends()
):
    """更新项目"""
    return await service.update_project(project_id, data)


@router.delete("/{project_id}")
async def delete_project(
    project_id: int,
    service: ProjectService = Depends()
):
    """删除项目"""
    await service.delete_project(project_id)
    return {"message": "Project deleted"}


@router.get("/{project_id}/scans", response_model=List[Scan])
async def get_project_scans(
    project_id: int,
    service: ProjectService = Depends()
):
    """获取项目的扫描历史"""
    return await service.get_scans(project_id)
```

```python
# src/web/api/v1/scans.py

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import List

from ..deps import get_db
from ...models.scan import Scan, ScanCreate, ScanProgress, ScanStatus
from ...services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=Scan)
async def create_scan(
    data: ScanCreate,
    background_tasks: BackgroundTasks,
    service: ScanService = Depends()
):
    """创建并启动扫描任务"""
    scan = await service.create_scan(data)

    # 在后台启动扫描
    background_tasks.add_task(service.run_scan, scan.id)

    return scan


@router.get("", response_model=List[Scan])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    status: ScanStatus = None,
    service: ScanService = Depends()
):
    """列出扫描任务"""
    return await service.list_scans(skip=skip, limit=limit, status=status)


@router.get("/{scan_id}", response_model=Scan)
async def get_scan(
    scan_id: int,
    service: ScanService = Depends()
):
    """获取扫描任务详情"""
    scan = await service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/progress", response_model=ScanProgress)
async def get_scan_progress(
    scan_id: int,
    service: ScanService = Depends()
):
    """获取扫描进度"""
    progress = await service.get_progress(scan_id)
    return progress


@router.post("/{scan_id}/pause")
async def pause_scan(
    scan_id: int,
    service: ScanService = Depends()
):
    """暂停扫描"""
    await service.pause_scan(scan_id)
    return {"message": "Scan paused"}


@router.post("/{scan_id}/resume")
async def resume_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    service: ScanService = Depends()
):
    """继续扫描"""
    await service.resume_scan(scan_id)
    background_tasks.add_task(service.run_scan, scan_id)
    return {"message": "Scan resumed"}


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: int,
    service: ScanService = Depends()
):
    """取消扫描"""
    await service.cancel_scan(scan_id)
    return {"message": "Scan cancelled"}


@router.get("/{scan_id}/findings", response_model=List[Finding])
async def get_scan_findings(
    scan_id: int,
    skip: int = 0,
    limit: int = 100,
    severity: SeverityLevel = None,
    service: ScanService = Depends()
):
    """获取扫描结果"""
    return await service.get_findings(scan_id, skip, limit, severity)


@router.get("/{scan_id}/report")
async def get_scan_report(
    scan_id: int,
    service: ScanService = Depends()
):
    """获取扫描报告（文件下载或预览）"""
    report = await service.get_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
```

```python
# src/web/api/websocket/scans.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json

from ...services.scan_service import ScanService

router = APIRouter()


@router.websocket("/ws/scans/{scan_id}/progress")
async def scan_progress_websocket(
    websocket: WebSocket,
    scan_id: int,
):
    """扫描进度实时推送"""
    await websocket.accept()

    try:
        service = ScanService()

        # 发送当前进度
        progress = await service.get_progress(scan_id)
        await websocket.send_json({
            "type": "progress",
            "data": progress.model_dump()
        })

        # 如果扫描已完成，不需要继续等待
        if progress.status in ["completed", "failed", "cancelled"]:
            await websocket.close()
            return

        # 订阅进度更新
        async for progress_update in service.subscribe_progress(scan_id):
            await websocket.send_json({
                "type": "progress_update",
                "data": progress_update.model_dump()
            })

            if progress_update.status in ["completed", "failed", "cancelled"]:
                break

    except WebSocketDisconnect:
        pass
    finally:
        await websocket.close()
```

---

## 四、暂停/续扫机制设计

### 4.1 检查点数据结构

```python
# src/web/services/checkpoint_service.py

from datetime import datetime
from typing import Any, Optional
from pathlib import Path
import json
import hashlib

from ..models.checkpoint import CheckpointData, PhaseName, PhaseStatus


class CheckpointService:
    """检查点管理服务"""

    def __init__(self, db_session):
        self.db = db_session
        self.checkpoint_dir = Path(".deepvuln/checkpoints")
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    async def save_checkpoint(
        self,
        scan_id: int,
        current_phase: PhaseName,
        phase_data: dict[str, Any],
        global_state: dict[str, Any]
    ) -> str:
        """
        保存检查点

        Args:
            scan_id: 扫描ID
            current_phase: 当前阶段
            phase_data: 各阶段的状态和数据
            global_state: 全局扫描状态
        """
        checkpoint = CheckpointData(
            scan_id=scan_id,
            current_phase=current_phase,
            phases=phase_data,
            global_state=global_state,
            resume_data={
                "can_resume": True,
                "resumable_phases": self._get_resumable_phases(phase_data)
            }
        )

        # 保存到文件
        checkpoint_path = self.checkpoint_dir / f"scan_{scan_id}_checkpoint.json"
        with open(checkpoint_path, "w") as f:
            json.dump(checkpoint.model_dump(), f, indent=2)

        # 更新数据库
        await self.db.execute(
            """UPDATE scans SET
               checkpoint_data = $1,
               current_phase = $2
               WHERE id = $3""",
            checkpoint.model_dump(),
            current_phase.value,
            scan_id
        )

        return str(checkpoint_path)

    async def load_checkpoint(self, scan_id: int) -> Optional[CheckpointData]:
        """加载检查点"""
        # 先从数据库读取
        result = await self.db.fetch_one(
            "SELECT checkpoint_data FROM scans WHERE id = $1",
            scan_id
        )

        if not result or not result["checkpoint_data"]:
            return None

        # 验证文件是否存在
        checkpoint_path = self.checkpoint_dir / f"scan_{scan_id}_checkpoint.json"
        if not checkpoint_path.exists():
            return None

        # 读取文件
        with open(checkpoint_path, "r") as f:
            data = json.load(f)

        return CheckpointData(**data)

    async def can_resume(self, scan_id: int) -> bool:
        """检查是否可以继续扫描"""
        checkpoint = await self.load_checkpoint(scan_id)
        if not checkpoint:
            return False

        # 检查是否有可恢复的阶段
        return len(checkpoint.resume_data.get("resumable_phases", [])) > 0

    def _get_resumable_phases(self, phase_data: dict[str, Any]) -> list[str]:
        """获取可恢复的阶段列表"""
        resumable = []

        for phase_name, phase_info in phase_data.items():
            if phase_info.get("status") in ["completed", "partial"]:
                # 已完成的可以复用结果
                resumable.append(phase_name)
            elif phase_info.get("status") == "failed":
                # 失败的可能需要重试
                if phase_info.get("retryable", True):
                    resumable.append(phase_name)

        return resumable
```

### 4.2 扫描执行器（支持暂停/续扫）

```python
# src/web/services/scan_executor.py

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, Any

from .checkpoint_service import CheckpointService
from ..models.checkpoint import PhaseName, PhaseStatus
from ..models.scan import ScanStatus


class ScanExecutor:
    """扫描执行器 - 支持暂停和续扫"""

    def __init__(self, scan_id: int, db_session, config: ScanConfig):
        self.scan_id = scan_id
        self.db = db_session
        self.config = config
        self.checkpoint_service = CheckpointService(db_session)

        # 控制标志
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # 默认运行
        self._cancel_flag = False

        # 当前阶段状态
        self.current_phase: Optional[PhaseName] = None
        self.phase_data: dict[str, Any] = {}

    async def run(self, resume: bool = False):
        """执行扫描"""
        try:
            await self._update_status(ScanStatus.RUNNING)

            # 如果是续扫，加载检查点
            if resume:
                await self._load_checkpoint()

            # 执行各阶段
            await self._run_phases()

            await self._update_status(ScanStatus.COMPLETED)

        except Exception as e:
            await self._update_status(ScanStatus.FAILED, str(e))
            raise

    async def pause(self):
        """暂停扫描"""
        self._pause_event.clear()
        await self._update_status(ScanStatus.PAUSED)
        await self._save_checkpoint()

    async def resume(self):
        """继续扫描"""
        self._pause_event.set()
        await self._update_status(ScanStatus.RUNNING)

    async def cancel(self):
        """取消扫描"""
        self._cancel_flag = True
        self._pause_event.set()  # 确保不会阻塞在暂停状态
        await self._update_status(ScanStatus.CANCELLED)

    async def _run_phases(self):
        """执行扫描各阶段"""
        phases = [
            PhaseName.L1_PREPARATION,
            PhaseName.L1_ATTACK_SURFACE,
            PhaseName.L2_SEMGREP,
            PhaseName.L2_CODEQL,
            PhaseName.L3_AGENT,
            PhaseName.L3_ADJUDICATION,
            PhaseName.REPORT_GENERATION,
        ]

        for phase in phases:
            # 检查是否取消
            if self._cancel_flag:
                raise RuntimeError("Scan cancelled")

            # 等待暂停结束
            await self._pause_event.wait()

            # 检查是否已完成（续扫时）
            if await self._is_phase_completed(phase):
                continue

            # 执行阶段
            await self._run_phase(phase)

            # 保存检查点
            await self._save_checkpoint()

    async def _run_phase(self, phase: PhaseName):
        """执行单个阶段"""
        self.current_phase = phase
        await self._update_phase(phase, PhaseStatus.RUNNING)

        start_time = datetime.now()

        try:
            # 根据阶段执行不同的扫描逻辑
            if phase == PhaseName.L1_PREPARATION:
                output = await self._run_l1_preparation()
            elif phase == PhaseName.L1_ATTACK_SURFACE:
                output = await self._run_l1_attack_surface()
            elif phase == PhaseName.L2_SEMGREP:
                output = await self._run_l2_semgrep()
            elif phase == PhaseName.L2_CODEQL:
                output = await self._run_l2_codeql()
            elif phase == PhaseName.L3_AGENT:
                output = await self._run_l3_agent()
            elif phase == PhaseName.L3_ADJUDICATION:
                output = await self._run_l3_adjudication()
            elif phase == PhaseName.REPORT_GENERATION:
                output = await self._run_report_generation()

            # 记录成功
            duration = int((datetime.now() - start_time).total_seconds())
            await self._update_phase(phase, PhaseStatus.COMPLETED, duration, output)

            # 保存阶段数据
            self.phase_data[phase.value] = {
                "status": "completed",
                "output": output,
                "duration": duration
            }

        except Exception as e:
            # 记录失败
            await self._update_phase(phase, PhaseStatus.FAILED, error=str(e))
            self.phase_data[phase.value] = {
                "status": "failed",
                "error": str(e),
                "retryable": True
            }
            raise

    async def _is_phase_completed(self, phase: PhaseName) -> bool:
        """检查阶段是否已完成（续扫时）"""
        phase_info = self.phase_data.get(phase.value, {})
        return phase_info.get("status") == "completed"

    async def _save_checkpoint(self):
        """保存检查点"""
        await self.checkpoint_service.save_checkpoint(
            scan_id=self.scan_id,
            current_phase=self.current_phase or PhaseName.L1_PREPARATION,
            phase_data=self.phase_data,
            global_state={
                "config": self.config.model_dump(),
                "paused": not self._pause_event.is_set(),
            }
        )

    async def _load_checkpoint(self):
        """加载检查点（续扫时）"""
        checkpoint = await self.checkpoint_service.load_checkpoint(self.scan_id)
        if not checkpoint:
            raise RuntimeError("No checkpoint found")

        self.current_phase = checkpoint.current_phase
        self.phase_data = checkpoint.phases

    async def _update_phase(
        self,
        phase: PhaseName,
        status: PhaseStatus,
        duration: Optional[int] = None,
        output: Optional[Any] = None,
        error: Optional[str] = None
    ):
        """更新阶段状态到数据库"""
        await self.db.execute(
            """INSERT INTO scan_phases
               (scan_id, phase_name, status, started_at, completed_at, duration_seconds, output_data, error_message)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (scan_id, phase_name)
               DO UPDATE SET status = $3, completed_at = $5, duration_seconds = $6, output_data = $7, error_message = $8
            """,
            self.scan_id,
            phase.value,
            status.value,
            datetime.now() if status == PhaseStatus.RUNNING else None,
            datetime.now() if status == PhaseStatus.COMPLETED else None,
            duration,
            json.dumps(output) if output else None,
            error
        )

    async def _update_status(self, status: ScanStatus, error: Optional[str] = None):
        """更新扫描状态"""
        updates = {
            "status": status.value
        }

        if status == ScanStatus.RUNNING:
            updates["started_at"] = datetime.now()
        elif status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
            updates["completed_at"] = datetime.now()

        if error:
            updates["error_message"] = error

        await self.db.execute(
            f"UPDATE scans SET {', '.join(f'{k} = ${i+1}' for i, k in enumerate(updates.keys())} WHERE id = ${len(updates)+1}",
            *updates.values(),
            self.scan_id
        )
```

---

## 五、前端架构设计 (React + TypeScript)

### 5.1 目录结构

```
frontend/
├── src/
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Header.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   └── Footer.tsx
│   │   ├── project/
│   │   │   ├── ProjectList.tsx
│   │   │   ├── ProjectCard.tsx
│   │   │   └── ProjectForm.tsx
│   │   ├── scan/
│   │   │   ├── ScanList.tsx
│   │   │   ├── ScanCard.tsx
│   │   │   ├── ScanProgress.tsx
│   │   │   └── ScanActions.tsx    # 暂停/继续/取消按钮
│   │   ├── finding/
│   │   │   ├── FindingList.tsx
│   │   │   ├── FindingCard.tsx
│   │   │   └── FindingFilters.tsx
│   │   └── common/
│   │       ├── Button.tsx
│   │       ├── Modal.tsx
│   │       └── ProgressBar.tsx
│   │
│   ├── pages/
│   │   ├── Dashboard.tsx
│   │   ├── Projects.tsx
│   │   ├── Scans.tsx
│   │   └── Findings.tsx
│   │
│   ├── hooks/
│   │   ├── useWebSocket.ts        # WebSocket hook
│   │   ├── useScanProgress.ts     # 扫描进度 hook
│   │   └── useApi.ts              # API 调用 hook
│   │
│   ├── services/
│   │   ├── api.ts                 # API 客户端
│   │   └── websocket.ts           # WebSocket 客户端
│   │
│   ├── stores/
│   │   ├── projectStore.ts       # 项目状态管理
│   │   └── scanStore.ts           # 扫描状态管理
│   │
│   ├── types/
│   │   ├── project.ts
│   │   ├── scan.ts
│   │   └── finding.ts
│   │
│   └── App.tsx
```

### 5.2 关键组件

```typescript
// frontend/src/components/scan/ScanProgress.tsx

import React, { useEffect, useState } from 'react';
import { useScanProgress } from '../../hooks/useScanProgress';
import { ProgressBar } from '../common/ProgressBar';
import { Button } from '../common/Button';
import { Play, Pause, X } from 'lucide-react';

interface ScanProgressProps {
  scanId: number;
}

export function ScanProgress({ scanId }: ScanProgressProps) {
  const { progress, error, isLoading } = useScanProgress(scanId);
  const [actionLoading, setActionLoading] = useState(false);

  const handlePause = async () => {
    setActionLoading(true);
    try {
      await fetch(`/api/v1/scans/${scanId}/pause`, { method: 'POST' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleResume = async () => {
    setActionLoading(true);
    try {
      await fetch(`/api/v1/scans/${scanId}/resume`, { method: 'POST' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleCancel = async () => {
    if (!confirm('确定要取消此扫描吗？')) return;

    setActionLoading(true);
    try {
      await fetch(`/api/v1/scans/${scanId}/cancel`, { method: 'POST' });
    } finally {
      setActionLoading(false);
    }
  };

  if (isLoading) return <div>加载中...</div>;
  if (error) return <div>加载失败: {error.message}</div>;

  const isRunning = progress.status === 'running';
  const isPaused = progress.status === 'paused';
  const isCompleted = progress.status === 'completed';

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold">扫描进度</h3>

        <div className="flex gap-2">
          {isRunning && (
            <Button
              variant="secondary"
              onClick={handlePause}
              disabled={actionLoading}
              icon={<Pause className="w-4 h-4" />}
            >
              暂停
            </Button>
          )}

          {isPaused && (
            <Button
              variant="primary"
              onClick={handleResume}
              disabled={actionLoading}
              icon={<Play className="w-4 h-4" />}
            >
              继续
            </Button>
          )}

          {!isCompleted && (
            <Button
              variant="danger"
              onClick={handleCancel}
              disabled={actionLoading}
              icon={<X className="w-4 h-4" />}
            >
              取消
            </Button>
          )}
        </div>
      </div>

      <ProgressBar
        percent={progress.progress_percent}
        status={progress.status}
      />

      <div className="mt-4 grid grid-cols-4 gap-4 text-sm">
        <div>
          <span className="text-gray-500">当前阶段</span>
          <p className="font-medium">{progress.current_phase || '准备中'}</p>
        </div>
        <div>
          <span className="text-gray-500">已扫描文件</span>
          <p className="font-medium">{progress.files_scanned} / {progress.total_files}</p>
        </div>
        <div>
          <span className="text-gray-500">发现漏洞</span>
          <p className="font-medium">{progress.findings_count}</p>
        </div>
        <div>
          <span className="text-gray-500">预计完成</span>
          <p className="font-medium">
            {progress.estimated_completion
              ? new Date(progress.estimated_completion).toLocaleString()
              : '计算中...'}
          </p>
        </div>
      </div>

      {progress.error_message && (
        <div className="mt-4 p-3 bg-red-50 text-red-700 rounded">
          错误: {progress.error_message}
        </div>
      )}
    </div>
  );
}
```

```typescript
// frontend/src/hooks/useScanProgress.ts

import { useEffect, useState } from 'react';
import { useWebSocket } from './useWebSocket';
import type { ScanProgress as ScanProgressType } from '../types/scan';

export function useScanProgress(scanId: number) {
  const [progress, setProgress] = useState<ScanProgressType | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // WebSocket 实时进度
  const { lastMessage, connected } = useWebSocket(
    `ws://localhost:8000/api/v1/ws/scans/${scanId}/progress`
  );

  // 轮询作为 fallback
  useEffect(() => {
    if (connected) return;  // WebSocket 连接时不需要轮询

    const fetchProgress = async () => {
      try {
        const response = await fetch(`/api/v1/scans/${scanId}/progress`);
        if (!response.ok) throw new Error('获取进度失败');
        const data = await response.json();
        setProgress(data);
        setIsLoading(false);
      } catch (err) {
        setError(err as Error);
        setIsLoading(false);
      }
    };

    fetchProgress();
    const interval = setInterval(fetchProgress, 5000);  // 5秒轮询

    return () => clearInterval(interval);
  }, [scanId, connected]);

  // 处理 WebSocket 消息
  useEffect(() => {
    if (lastMessage) {
      const data = JSON.parse(lastMessage);

      if (data.type === 'progress' || data.type === 'progress_update') {
        setProgress(data.data);
        setIsLoading(false);
      }
    }
  }, [lastMessage]);

  return { progress, error, isLoading };
}
```

---

## 六、实施路线图

### Phase 1: 基础设施 (Week 1-2)

| 任务 | 描述 | 优先级 |
|------|------|--------|
| 数据库设计 | PostgreSQL 表结构设计 | P0 |
| 后端框架 | FastAPI 项目初始化 | P0 |
| 数据库迁移 | Alembic 集成 | P0 |
| 数据模型 | Pydantic 模型定义 | P0 |

### Phase 2: 核心 API (Week 2-3)

| 任务 | 描述 | 优先级 |
|------|------|--------|
| 项目管理 API | CRUD 操作 | P0 |
| 扫描创建 API | 创建扫描任务 | P0 |
| 扫描执行器 | CLI 集成 | P0 |
| 进度查询 API | 状态查询 | P1 |

### Phase 3: 暂停/续扫 (Week 3-4)

| 任务 | 描述 | 优先级 |
|------|------|--------|
| 检查点服务 | 保存/加载检查点 | P0 |
| 阶段状态管理 | 各阶段状态跟踪 | P0 |
| 暂停/继续 API | 控制接口 | P0 |
| 恢复逻辑 | 从检查点恢复 | P0 |

### Phase 4: 前端界面 (Week 4-5)

| 任务 | 描述 | 优先级 |
|------|------|--------|
| 项目列表页 | 查看/创建项目 | P1 |
| 扫描列表页 | 查看/创建扫描 | P1 |
| 扫描进度页 | 实时进度显示 | P1 |
| 暂停/继续控制 | 控制按钮 | P1 |
| WebSocket 集成 | 实时更新 | P2 |

### Phase 5: 报告与结果 (Week 5-6)

| 任务 | 描述 | 优先级 |
|------|------|--------|
| 漏洞列表页 | 分页/过滤/搜索 | P1 |
| 漏洞详情页 | 完整漏洞信息 | P1 |
| 报告生成 | Markdown/PDF 导出 | P2 |
| 历史对比 | 多次扫描对比 | P2 |

---

## 七、技术栈总结

| 层级 | 技术选型 | 说明 |
|------|---------|------|
| **前端** | React 18 + TypeScript | 现代化 UI |
| **前端状态** | Zustand / Jotai | 轻量级状态管理 |
| **前端组件** | Radix UI + Tailwind CSS | 可访问性 + 样式 |
| **后端** | FastAPI + Python 3.12+ | 异步高性能 |
| **数据库** | PostgreSQL 15+ | 关系型 + JSONB |
| **ORM** | SQLAlchemy 2.0 | 异步 ORM |
| **迁移** | Alembic | 数据库版本管理 |
| **实时通信** | WebSocket | 进度推送 |
| **任务队列** | BackgroundTasks | 简单后台任务 |
| **认证** | API Key | 简单认证 |
| **日志** | structlog | 结构化日志 |

---

## 八、与 DeepVuln CLI 的集成

```python
# src/web/services/scan_executor.py

import subprocess
from pathlib import Path

from src.cli.main import main as cli_main


class ScanExecutor:
    """扫描执行器 - 调用 CLI 进行扫描"""

    async def _run_l1_attack_surface(self):
        """运行 L1 攻击面检测"""
        # 保存检查点
        await self._save_checkpoint()

        # 调用 CLI
        cmd = [
            "python", "-m", "src.cli.main",
            "scan", str(self.config.target_path),
            "--mode", "l1",
            "--output", f".deepvuln/temp/scan_{self.scan_id}/l1_results.json"
        ]

        # 执行并监控
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # 实时处理输出（用于进度更新）
        await self._monitor_process(process)

        return_code = await process.wait()

        if return_code != 0:
            raise RuntimeError(f"L1 scan failed with code {return_code}")

        # 读取结果
        result_path = Path(f".deepvuln/temp/scan_{self.scan_id}/l1_results.json")
        return json.loads(result_path.read_text())

    async def _monitor_process(self, process):
        """监控子进程输出，提取进度信息"""
        while True:
            # 检查暂停
            await self._pause_event.wait()

            # 检查取消
            if self._cancel_flag:
                process.kill()
                raise RuntimeError("Scan cancelled")

            # 读取输出
            line = await process.stdout.readline()
            if not line:
                break

            # 解析进度信息
            # CLI 输出格式: "PROGRESS: 50/100 files scanned"
            if b"PROGRESS:" in line:
                # 更新数据库进度
                await self._update_progress_from_line(line.decode())
```

---

## 九、数据库初始化脚本

```sql
-- migrations/001_init.sql

-- 创建扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 创建函数: 自动更新 updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- 应用触发器
CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

---

## 十、API 接口总览

| 方法 | 端点 | 描述 |
|------|------|------|
| POST | `/api/v1/projects` | 创建项目 |
| GET | `/api/v1/projects` | 列出项目 |
| GET | `/api/v1/projects/{id}` | 获取项目详情 |
| PUT | `/api/v1/projects/{id}` | 更新项目 |
| DELETE | `/api/v1/projects/{id}` | 删除项目 |
| GET | `/api/v1/projects/{id}/scans` | 获取项目扫描历史 |
| POST | `/api/v1/scans` | 创建扫描 |
| GET | `/api/v1/scans` | 列出扫描 |
| GET | `/api/v1/scans/{id}` | 获取扫描详情 |
| GET | `/api/v1/scans/{id}/progress` | 获取扫描进度 |
| POST | `/api/v1/scans/{id}/pause` | 暂停扫描 |
| POST | `/api/v1/scans/{id}/resume` | 继续扫描 |
| POST | `/api/v1/scans/{id}/cancel` | 取消扫描 |
| GET | `/api/v1/scans/{id}/findings` | 获取扫描结果 |
| GET | `/api/v1/scans/{id}/report` | 获取扫描报告 |
| WS | `/api/v1/ws/scans/{id}/progress` | 实时进度推送 |

---

*本文档是 DeepVuln v1.0 企业稳定版规划的一部分*
