# Project Tree

Keep this file compact. Only include important paths.

```text
src/
├── cli/main.py              # CLI 入口点
├── core/
│   ├── config/              # 配置管理
│   ├── llm/                 # LLM 客户端
│   ├── rule_gating.py       # 规则裁剪
│   ├── final_score.py       # 统一评分
│   └── finding_budget.py    # 误报熔断
├── layers/
│   ├── l1_intelligence/     # L1: 情报层
│   │   ├── fetcher.py       # 资产获取
│   │   ├── workspace.py     # 工作空间
│   │   ├── tech_stack_detector/
│   │   ├── attack_surface/
│   │   └── threat_intel/
│   └── l3_analysis/         # L3: 分析层
│       ├── engines/         # Semgrep/CodeQL/Agent
│       ├── strategy/        # 审计策略
│       ├── rounds/          # 多轮审计
│       └── incremental/     # 增量扫描
└── models/                  # 数据模型
tests/
├── unit/                    # 单元测试
└── integration/             # 集成测试
rules/
├── semgrep/                 # Semgrep 规则
└── codeql/                  # CodeQL 规则
docs/
├── ROADMAP.md               # 项目真实路线图
├── CURRENT_GOAL.md          # 当前目标记录
└── ai/                      # AI 工作流状态
```

## Key Entry Points

- `src/cli/main.py:main()` - 主 CLI 入口
- `src/cli/main.py:run_full_security_scan()` - 完整安全扫描
- `src/layers/l3_analysis/smart_scanner.py:SmartScanner` - 智能扫描器

## Key Config Files

- `pyproject.toml` - 项目配置与依赖
- `config.local.toml` - 本地配置（不提交）
- `config.example.toml` - 配置示例
- `docker-compose.yml` - Docker 编排
- `Dockerfile` - 容器镜像定义
