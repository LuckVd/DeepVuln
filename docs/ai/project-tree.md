# Project Tree

Keep this file compact. Only include important paths.（web-only，CLI 已移除）

```text
src/
├── core/
│   ├── config/             # 配置管理
│   ├── llm/                # LLM 客户端（openai_client）
│   ├── logger/ exceptions/ utils/ models/
│   ├── rule_gating.py      # 规则裁剪
│   ├── final_score.py      # 统一评分
│   └── finding_budget.py   # 误报熔断
├── layers/
│   ├── l1_intelligence/    # L1 情报层
│   │   ├── fetcher / workspace / tech_stack_detector
│   │   ├── attack_surface/  # 攻击面（ast/ + patterns/）
│   │   ├── threat_intel/    # 威胁情报（collectors/sources/storage/scheduler）
│   │   ├── code_structure/ dependency_scanner/ security_analyzer/
│   │   └── build_config/    # 构建配置分析
│   ├── l3_analysis/        # L3 分析层
│   │   ├── engines/         # 四引擎: semgrep/codeql/ast_engine/opencode_agent + logic_vuln_detector(E5)
│   │   ├── build/ call_graph/ # AST/调用图构建（builders + runtime）
│   │   ├── sinks_sources/ pre_filter/  # source/sink 定义与预过滤
│   │   ├── rounds/          # 多轮审计（含 termination/RoundController）
│   │   ├── verification/    # gatekeeper + adversarial 验证
│   │   ├── scoring/scorers/ # multi_dim / attack_surface / codeql / reachability / taint
│   │   ├── prompts/         # exploitability / adversarial / logic_vuln 等
│   │   ├── decision/ strategy/ task/ coverage/ methodology/ codeql/ llm/ incremental/
│   │   └── smart_scanner.py # SmartScanner
│   └── pipeline/           # D1 ScanPipeline（context/phases/progress/checkpoint/scan_pipeline）
├── models/                 # fetcher/workspace 等数据模型
└── web/                    # 唯一用户入口（web-only）
    ├── main.py             # FastAPI 应用
    ├── api/v1/             # scans/auth/stats/llm_configs/system_settings
    ├── services/           # scan_orchestrator / scan_executor / scan_pipeline_adapters
    │                       # adjudication / adversarial / verification / checkpoint / phase_manager
    │                       # attack_surface / report / auth / archive_utils / ...
    ├── tasks/              # Celery: scan_tasks.py
    ├── core/               # celery_app / config / security / limiter（slowapi 限流）
    ├── repositories/ models/
    └── frontend/           # Vite + TS + Tailwind 前端（src/ + index.html）
celery_worker.py            # Celery worker 入口
rules/                      # semgrep/ + codeql/ 规则
migrations/                 # 数据库迁移
scripts/                    # 运维/部署脚本
tests/
├── unit/                   # 单元测试（test_pipeline/ test_l3/ ...）
└── integration/            # 集成测试
docs/
├── ai/                     # AI 工作流状态
│   ├── current-goal.md / current-goal.state.yaml
│   ├── roadmap.md / change-log.md
│   ├── project-summary.md / project-tree.md（本文件）
│   └── constraints/        # global.md / project.md
├── architecture/ api/ plans/
└── docker*.md / MIGRATION_GUIDE.md
```

## Key Entry Points

- `src/web/services/scan_orchestrator.py:ScanOrchestrator.execute_scan()` — Web 扫描主入口（经 D1 改走 `ScanPipeline`，web-only）
- `src/layers/pipeline/scan_pipeline.py:ScanPipeline` — 扫描阶段编排（9 phase，见 `phases.py`）
- `src/layers/l3_analysis/smart_scanner.py:SmartScanner` — 智能扫描器（四引擎联合 + 多轮）
- `src/web/main.py` — FastAPI 应用
- `celery_worker.py` + `src/web/tasks/scan_tasks.py` — Celery 异步任务

## 扫描阶段流（`src/layers/pipeline/phases.py`）

`SOURCE_PREPARATION → ENGINE_SELECTION → ENGINE_EXECUTION → EXPLOITABILITY_VERIFICATION → LOGIC_VULN_DISCOVERY → ADJUDICATION(去重裁决) → ADVERSARIAL(对抗验证) → RESULT_MERGE → TOKEN_STATS`

## Key Config Files

- `pyproject.toml` / `requirements.txt` / `uv.lock` — 项目配置与依赖
- `config.example.toml`（示例）/ `config/`（配置目录）/ `config.local.toml`（本地，不提交）
- `docker-compose*.yml` / `Dockerfile`(+`.lite`) / `docker-config/` — 容器编排（含 web-host / china / tun 变体）
- `start-all.sh` / `start-web.sh` — 启动脚本
