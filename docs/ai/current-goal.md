# Current Goal

> **状态**: 已完成 ✅
> **目标**: Web UI 打磨与功能增强批次（10 项改进）
> **Goal ID**: web-ui-polish-batch
> **完成日期**: 2026-04-14

---

## 执行结果

所有 6 个批次已独立提交完成：

| 批次 | 描述 | 修复点 | Commit |
|------|------|--------|--------|
| 1 | Critical 运行时崩溃修复 | Fix-01~05 | `6506f39` |
| 2 | 安全漏洞修复 | Fix-06~09 | `efd9dc4` |
| 3 | 后端逻辑修复 | Fix-10~15 | `e6f21af` |
| 4 | 前端 Bug 修复 | Fix-16~19 | `127a8ee` |
| 5 | 代码质量改进 | Fix-20~23 | `9dfdeb7` |
| 6 | 低优先级清理 | Fix-24~25 | `57a858a` |

## 安全扫描结果

| 级别 | 发现 | 是否本次引入 |
|------|------|-------------|
| BLOCKER | `config.py` 硬编码 DB 凭据 | 否（预存问题） |
| HIGH | `main.py` 日志输出 DB URL 明文 | 否（预存问题） |
| MEDIUM | WebSocket 端点无认证 | 否（预存问题） |

## 死代码检测

- **可安全清理**: 5 项（SecurityDepends 类、get_event_broadcaster、_detect_tech_stack wrapper、_deduplicate_findings、create_scan_orchestrator）
- **延后清理**: 4 项（get_quick_assessment x2、get_verdict_explanation、__all__ re-exports）
- **Bug 待修**: 1 项（websocket.py `_running` 属性未初始化）

## 后续建议

1. 清理安全扫描发现的 4 个预存安全问题
2. 清理 5 项高置信度死代码
3. 修复 websocket.py `_running` 属性 bug

---

## Feat Record: 2026-04-14 漏洞详情增强

### 需求描述
FindingDrawer 漏洞详情内容过少，需要显示更多详细内容：发现点代码片段、漏洞利用链、LLM 辩论详细内容和结果、引擎相关信息等。

### 实现方案
将 FindingDrawer 从 3 Tab 扩展为 5 Tab 结构：
- **概览 Tab** (增强): 新增 rule_id、evidence_strength、references 链接、tags 标签、fix_suggestion 修复建议
- **代码证据 Tab** (不变): 已有完善
- **利用链 Tab** (新增): 结构化展示 CPG 攻击路径 Source → Propagation → Sink，显示攻击向量和可利用性评级
- **LLM 辩论 Tab** (新增): 从 API 加载对抗性验证数据，按轮次展示 Attacker/Defender/Arbiter 论点、PoC 代码、利用步骤、过滤措施等
- **元数据 Tab** (增强): 新增评分详情卡片、置信度因子条形图

### 修改文件
- `src/web/models/schemas.py`: FindingResponse 新增 extra_metadata 字段
- `src/web/api/v1/scans.py`: findings 列表 API 返回 extra_metadata
- `src/web/frontend/src/types/models.ts`: 扩展 Finding 类型，新增 CpgPath、AdversarialRound、AdversarialVerdictData、AdversarialDebate 等类型
- `src/web/frontend/src/api/scans.ts`: 新增 getAdversarialDebate API 调用
- `src/web/frontend/src/i18n/translations.ts`: 新增 ~40 条中英文翻译
- `src/web/frontend/src/components/finding/FindingDrawer.tsx`: 完全重构为 5 Tab 结构，新增 VerdictSummary、DebateRoundCard、ArgumentCard、ScoreCard 子组件

### 验证结果
- TypeScript 编译: 本次修改相关文件 0 错误（其他文件 5 个预存错误不影响）
- Tab 空状态处理: 无数据时显示 Alert 提示
- 辩论数据加载: 优先从 extra_metadata 读取，缺失时异步调用 API
