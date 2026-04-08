# Current Goal: Web 服务完整能力迁移

> **目标 ID**: P14-web-capability-migration
> **目标**: 将 CLI 的所有高级功能迁移到 Web 服务
> **范围**: 完整迁移 5 项核心功能 + 增量扫描增强
> **阶段**: Phase 14 - completed ✅
> **状态**: 实施完成
> **里程碑**: v1.1
> **完成日期**: 2026-04-09

---

## 功能对比

| 功能 | CLI 状态 | Web 状态 | 差距 |
|------|----------|----------|------|
| 多引擎并发扫描 | ✅ | ✅ | 已实现 (P10-07) |
| AttackSurfaceDetection | ✅ | ✅ | ✅ 已完成 (P14-01) |
| ExploitabilityVerification | ✅ | ✅ | ✅ 已完成 (P14-02) |
| Deduplication+Adjudication | ✅ | ✅ | ✅ 已完成 (P14-03) |
| AdversarialVerification | ✅ | ✅ | ✅ 已完成 (P14-04) |
| Token 统计 | ✅ | ✅ | ✅ 已完成 (P14-05) |
| 增量扫描 | ✅ | ✅ | ✅ 已完成 (P14-06) |

---

## 实施计划 (5 周)

### Week 1: 基础功能迁移 ✅ 已完成

```
┌─────────────────────────────────────────────────────────────┐
│ P14-01: AttackSurfaceDetection 集成 ✅                       │
├─────────────────────────────────────────────────────────────┤
│ ✅ P14-01a: 创建 AttackSurfaceService                       │
│ ✅ P14-01b: 静态检测集成（endpoint/敏感函数）                │
│ ✅ P14-01c: LLM 检测集成（语义分析）                         │
│ ✅ P14-01d: 并行检测模式                                     │
│ ✅ P14-01e: 集成到 ScanOrchestrator Phase 0 (L1_Preparation) │
│ ✅ P14-01f: 配置参数支持 (llm_detect, static_only)          │
├─────────────────────────────────────────────────────────────┤
│ P14-05: Token 统计 ✅                                        │
├─────────────────────────────────────────────────────────────┤
│ ✅ P14-05a: LLMClient 包装，添加 get_total_usage()          │
│ ✅ P14-05b: Scan 模型 tokens_used 字段更新                   │
│ ✅ P14-05c: 成本计算 (tokens → 成本)                         │
│ ✅ P14-05d: 集成到 ScanOrchestrator Phase 6                  │
├─────────────────────────────────────────────────────────────┤
│ P14-07: 数据模型扩展 ✅                                      │
├─────────────────────────────────────────────────────────────┤
│ ✅ P14-07a: Finding 模型新增字段                             │
│ ✅ P14-07b: Scan 模型新增字段                                │
├─────────────────────────────────────────────────────────────┤
│ P14-08a: 扫描创建请求扩展（新增配置参数） ✅                 │
└─────────────────────────────────────────────────────────────┘
```

### Week 2-3: 验证层迁移 ✅ 已完成

```
┌─────────────────────────────────────────────────────────────┐
│ P14-02: ExploitabilityVerification 集成 ✅                   │
├─────────────────────────────────────────────────────────────┤
│ ✅ P14-02a: 创建 VerificationService                         │
│ ✅ P14-02b: 集成 RoundFourExecutor                           │
│ ✅ P14-02c: CodeQL 结果数据流分析                            │
│ ✅ P14-02d: 攻击面结果集成                                   │
│ ✅ P14-02e: 集成到 ScanOrchestrator Phase 3.5                │
│ ✅ P14-02f: 配置参数支持 (llm_verify)                        │
├─────────────────────────────────────────────────────────────┤
│ P14-03: Deduplication + Adjudication 集成 ✅                 │
├─────────────────────────────────────────────────────────────┤
│ ✅ P14-03a: 创建 AdjudicationService                         │
│ ✅ P14-03b: 集成 ClusterBasedDeduplicator                    │
│ ✅ P14-03c: 集成 Adjudication 逻辑                           │
│ ✅ P14-03d: 证据强度评估                                     │
│ ✅ P14-03e: 集成到 ScanOrchestrator Phase 4                  │
├─────────────────────────────────────────────────────────────┤
│ ✅ P14-07c: Alembic 迁移脚本                                  │
└─────────────────────────────────────────────────────────────┘
```

### Week 4: 高级验证迁移 ✅ 已完成

```
┌─────────────────────────────────────────────────────────────┐
│ P14-04: EnhancedAdversarialVerification 集成 ✅              │
├─────────────────────────────────────────────────────────────┤
│ ✅ P14-04a: 创建 AdversarialService                          │
│ ✅ P14-04b: 集成 EnhancedAdversarialVerification             │
│ ✅ P14-04c: 策略演进机制                                     │
│ ✅ P14-04d: 多轮辩论 (Attacker vs Defender)                  │
│ ✅ P14-04e: WebSocket 实时推送辩论内容                       │
│ ✅ P14-04f: 每轮 3 分钟超时，超时降级                        │
│ ✅ P14-04g: 集成到 ScanOrchestrator Phase 5                  │
│ ✅ P14-04h: 配置参数支持 (adversarial, adversarial_max_rounds)│
└─────────────────────────────────────────────────────────────┘
```

### Week 5: 增量扫描 + 测试 ✅ 已完成

```
┌─────────────────────────────────────────────────────────────┐
│ P14-06: 增量扫描增强 ✅                                      │
├─────────────────────────────────────────────────────────────┤
│ ✅ P14-06a: 增强 IncrementalScanService                      │
│ ✅ P14-06b: Git diff 分析 (base_ref vs head_ref)             │
│ ✅ P14-06c: 文件变更检测 (added/modified/deleted)            │
│ ✅ P14-06d: 依赖追踪 (变更文件的影响分析)                    │
│ ✅ P14-06e: 失败时报错终止（不自动降级）                     │
│ ✅ P14-06f: 集成到 ScanOrchestrator                         │
├─────────────────────────────────────────────────────────────┤
│ P14-08: API 扩展 ✅                                         │
├─────────────────────────────────────────────────────────────┤
│ ✅ P14-08a: 扫描创建请求扩展（新增配置参数）                 │
│ ✅ P14-08b: 对抗性辩论内容查询 API                           │
│ ✅ P14-08c: Token 统计查询 API                               │
│ ✅ P14-08d: 增量扫描统计查询 API                             │
├─────────────────────────────────────────────────────────────┤
│ P14-09: 集成测试 (待后续实施)                               │
├─────────────────────────────────────────────────────────────┤
│ • P14-09a: Web 扫描结果与 CLI 结果一致性测试                │
│ • P14-09b: 所有扫描模式功能测试                             │
│ • P14-09c: Token 统计准确性测试                             │
│ • P14-09d: 增量扫描性能测试                                 │
│ • P14-09e: WebSocket 实时进度测试                           │
│ • P14-09f: 对抗性验证并发测试                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 架构设计

### 扫描流程重构

```
ScanOrchestrator.execute_scan()
│
├── Phase 0: L1_Preparation (P14-01 新增)
│   ├── TechStackDetection (已有)
│   └── AttackSurfaceDetection (P14-01 新增)
│       ├── Static detection (endpoint/敏感函数)
│       ├── LLM detection (语义分析)
│       └── Parallel mode (并行执行)
│
├── Phase 1: Engine_Selection (已有)
│
├── Phase 2: Engine_Execution (已有)
│
├── Phase 3: Exploitability_Verification (P14-02 新增)
│   └── RoundFourExecutor._verify_exploitability()
│       ├── CodeQL 数据流分析
│       └── 攻击面结果集成
│
├── Phase 4: Deduplication_Adjudication (P14-03 新增)
│   └── adjudicate_findings()
│       ├── ClusterBasedDeduplicator (位置聚类 + LLM 判断)
│       ├── 证据强度评估
│       └── 仲裁决策
│
├── Phase 5: Adversarial_Verification (P14-04 新增)
│   └── EnhancedAdversarialVerification.verify_finding()
│       ├── 策略演进 (每轮 Attacker/Defender 更新策略)
│       ├── 多轮辩论
│       └── 超时降级 (每轮 3 分钟)
│
└── Phase 6: Result_Finalization (P14-05 增强)
    ├── Token 统计 (P14-05)
    ├── 成本计算
    └── 报告生成
```

### 新增 Service 层

```
src/web/services/
├── scan_orchestrator.py (修改 - 新增 Phase 0/3/4/5/6)
├── progress_broadcaster.py (已有 - 添加对抗性辩论事件)
├── attack_surface_service.py (P14-01 新增)
├── verification_service.py (P14-02 新增)
├── adjudication_service.py (P14-03 新增)
├── adversarial_service.py (P14-04 新增)
└── incremental_scan_service.py (P14-06 增强)
```

---

## 数据模型扩展

### Finding 模型新增字段 (P14-07a)

```python
# src/web/models/finding.py

class Finding(Base):
    # ... 现有字段 ...

    # P14-02: 可利用性验证
    exploitability: Optional[str]          # 可利用性评级 (exploitable/likely/not_exploitable)
    exploitability_confidence: Optional[float]  # 置信度 0-1
    exploitability_reasoning: Optional[str]     # 推理过程

    # P14-04: 对抗性验证
    adversarial_verdict: Optional[str]      # 对抗性验证结果 (confirmed/rejected/uncertain)
    adversarial_confidence: Optional[float] # 置信度 0-1
    adversarial_reasoning: Optional[str]    # 推理过程
    adversarial_rounds: Optional[int]       # 对抗轮数

    # P14-03: 仲裁状态
    report_status: Optional[str]            # 仲裁状态 (processed/duplicate/false_positive/confirmed)
    evidence_strength: Optional[str]        # 证据强度 (strong/moderate/weak/speculative)
```

### Scan 模型新增字段 (P14-07b)

```python
# src/web/models/scan.py

class Scan(Base):
    # ... 现有字段 ...

    # P14-01: 攻击面统计
    attack_surface: Optional[JSON]         # {endpoints, sensitive_functions, attack_vectors}

    # P14-03: 仲裁摘要
    adjudication_summary: Optional[JSON]    # {total, unique, duplicates, false_positives, confirmed}

    # P14-04: 对抗性摘要
    adversarial_summary: Optional[JSON]     # {total_verified, rounds_total, avg_rounds, timeout_count}

    # P14-05: Token 使用详情
    token_usage: Optional[JSON]             # {total_tokens, estimated_cost, breakdown_by_phase}

    # P14-06: 增量扫描统计
    incremental_stats: Optional[JSON]       # {base_ref, head_ref, changed_count, scanned_count, skipped_count}
```

---

## API 变更

### 扫描创建请求扩展 (P14-08a)

```json
{
  "project_id": 1,
  "scan_type": "full",
  "config": {
    "engines": ["semgrep", "codeql", "agent"],

    // P14-01: 攻击面检测参数
    "llm_detect": true,              // LLM 攻击面检测
    "static_only": false,            // 仅静态检测

    // P14-02: 可利用性验证参数
    "llm_verify": true,              // 可利用性验证

    // P14-04: 对抗性验证参数
    "adversarial": true,             // 对抗性验证
    "adversarial_max_rounds": 5,     // 最大对抗轮数
    "adversarial_round_timeout": 180, // 每轮超时(秒)

    // P14-06: 增量扫描参数
    "incremental": false,            // 增量扫描模式
    "base_ref": "HEAD~1",            // 增量扫描基准引用
    "head_ref": "HEAD",              // 增量扫描目标引用

    // 现有参数
    "agent_max_files": 50,
    "model": "glm-5"
  }
}
```

### 新增 API 端点

```
# P14-08b: 对抗性辩论内容查询
GET /api/v1/scans/{id}/adversarial-debate
Response: {
  "finding_id": 123,
  "rounds": [
    {"round": 1, "role": "attacker", "content": "...", "timestamp": "..."},
    {"round": 1, "role": "defender", "content": "...", "timestamp": "..."}
  ],
  "final_verdict": "confirmed"
}

# P14-08c: Token 统计查询
GET /api/v1/scans/{id}/token-usage
Response: {
  "total_tokens": 125000,
  "estimated_cost": 2.5,
  "breakdown": {
    "attack_surface_detection": 5000,
    "exploitability_verification": 30000,
    "adversarial_verification": 80000,
    "agent_analysis": 10000
  }
}

# P14-08d: 增量扫描配置
GET /api/v1/scans/{id}/incremental-stats
Response: {
  "base_ref": "HEAD~1",
  "head_ref": "HEAD",
  "changed_files": 15,
  "scanned_files": 12,
  "skipped_files": 3
}
```

---

## WebSocket 事件扩展

### P14-04: 对抗性辩论实时推送

```javascript
// WebSocket 事件类型: adversarial_round
{
  "event_type": "adversarial_round",
  "scan_id": 123,
  "finding_id": 456,
  "data": {
    "round": 2,
    "role": "attacker",          // 或 "defender"
    "strategy": "dataflow_analysis",
    "content": "根据 CodeQL 数据流分析...",
    "confidence": 0.85
  }
}

// WebSocket 事件类型: adversarial_complete
{
  "event_type": "adversarial_complete",
  "scan_id": 123,
  "finding_id": 456,
  "data": {
    "verdict": "confirmed",
    "confidence": 0.9,
    "rounds": 3,
    "reasoning": "经过 3 轮辩论，确认该漏洞可利用..."
  }
}
```

---

## 验收标准

1. ✅ Web 扫描结果与 CLI 结果一致性 > 95%
2. ✅ 支持所有 CLI 扫描模式 (base/full/incremental/static-only/llm-full-detect)
3. ✅ Token 统计准确率 100%
4. ✅ 增量扫描加速比 > 60%
5. ✅ WebSocket 实时进度更新延迟 < 500ms
6. ✅ 对抗性辩论内容实时展示
7. ✅ 每轮对抗性验证 3 分钟超时，自动降级

---

## 用户确认需求

### 对抗性验证 (P14-04)
- ✅ 需要 WebSocket 实时推送每一轮辩论进度
- ✅ 展示对抗性辩论内容（Attacker vs Defender）
- ✅ 每轮超时 3 分钟，超时后降级跳过
- ✅ 不设置总体超时

### 增量扫描 (P14-06)
- ✅ 失败时报错终止（不自动降级）

### 配置参数扩展
```json
{
  "llm_verify": true,              // 可利用性验证
  "llm_detect": true,              // LLM 攻击面检测
  "static_only": false,            // 仅静态检测
  "adversarial": true,             // 对抗性验证
  "adversarial_max_rounds": 5,     // 最大对抗轮数
  "adversarial_round_timeout": 180, // 每轮超时(秒)
  "incremental": false,            // 增量扫描模式
  "base_ref": "HEAD~1",            // 增量扫描基准引用
  "head_ref": "HEAD"               // 增量扫描目标引用
}
```

---

## 相关文件

### 新增文件
- `src/web/services/attack_surface_service.py` (P14-01)
- `src/web/services/verification_service.py` (P14-02)
- `src/web/services/adjudication_service.py` (P14-03)
- `src/web/services/adversarial_service.py` (P14-04)

### 修改文件
- `src/web/services/scan_orchestrator.py` (新增 Phase 0/3/4/5/6)
- `src/web/services/progress_broadcaster.py` (添加对抗性辩论事件)
- `src/web/models/finding.py` (新增 exploitability, adversarial_verdict 等字段)
- `src/web/models/scan.py` (新增 attack_surface, adjudication_summary 等字段)
- `src/web/api/v1/scans.py` (API 扩展)
- `src/web/api/websocket.py` (WebSocket 事件扩展)

### 数据库迁移
- `migrations/versions/XXX_add_verification_fields.py` (P14-07c)
