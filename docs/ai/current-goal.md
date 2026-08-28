# Current Goal

> **状态**: ✅ 已立项（2026-08-26）— Phase 19 执行中；**P1–P4 开放问题全部修复关闭 + P19 噪声裁剪 + 第二轮 mini 基线（Recall 100% / safe 零 FP）**
>
> **Goal ID**: phase19-benchmark-eval
> **创建日期**: 2026-08-26
> **上一 goal**: Phase 18 — 精度链路接通与多语言可达性补齐（✅ 2026-08-25 关闭）
> **当前执行**: P1/P3/P4 ✅ + P2 ✅（入口层+ sink 层，三语言攻击路径全通）+ P19 ✅（semgrep 噪声规则剔除）→ **下一步：重启服务跑第三轮 mini 基线，验证全修复联合收益，然后扩 owasp-subset 150 例**

---

## 📊 当前状态快照（新会话先看这个）

### 已完成（截至 2026-08-28，全部已 commit）

**提交主线**（本会话 8/26–8/28，9 个 commit）:
- `af95bb6` 基建 + Phase 19 立项（benchmarks/ 全套、AST 规则 7 条修复、LLM trace、deepseek-v4-flash 接入）
- `695707c` **P1**：semgrep 零 findings（HOME 不可写 → SEMGREP_LOG_FILE 注入 + 相对路径 resolve）
- `cfa807b` **P3**：agent is_suspicious 条目抽离审查队列（include_suspicious_findings 逃生阀）
- `d6fe649` **P4**：java-cmdi 根因（provider 503 + 模型下线）→ deepseek-v4-flash 迁移
- `d0df699` 第二轮 mini 基线落档
- `d987d4e` **P19**：semgrep 噪声规则剔除（use-tls / no-direct-write）
- `9237732` **P2 入口层**：tree-sitter 字节/字符错位（4 处）+ Java Servlet 识别
- `c8f72ee` **P2 收尾**：sink 白名单补 Java 调用类型 + 语言专属 sink pattern

**要点**:

1. **基准基础设施** `benchmarks/`: fetch.sh 五大第三方源 / mini 9 case（vuln-safe 成对）/ OWASP 子集 150 例（seed=42）/ run_benchmark.py（selfcheck + api）
2. **AST 规则**: 7 条编译失败清零（6 条 S-expression + TS 语言加载回退），27/27 编译通过
3. **LLM trace**: `DEEPVULN_LLM_TRACE` JSONL 落盘（不落 api_key）
4. **LLM 模型**: opencode-go / **deepseek-v4-flash**（2026-08-27 从 ox-alpha-free 迁移——该名已下线 401）
5. **第二轮 mini 基线**（9 case 全跑完，P1+P3+P4 后 + deepseek-v4-flash）:
   | conf>= | TP | FP | FN | P | R | F1 |
   |---|---|---|---|---|---|---|
   | 0.0 | 9 | 21 | 0 | 0.300 | **1.000** | 0.462 |
   | 0.7 | 9 | 15 | 0 | 0.375 | **1.000** | 0.545 |
   | 0.8 | 9 | 8 | 0 | 0.529 | **1.000** | 0.692 |

   总 token: **135,273**（27 次 LLM 调用，0 失败）；对比首轮（conf>=0）：TP 8→9（FN 清零）、safe-FP 26→0（P3）、R 0.889→1.0、P 0.235→0.300、F1 0.372→0.462。残余 FP 21 全为 vuln 文件上其他类型（agent 跨类型 + semgrep 通用规则——后者已被 P19 剔除）。
6. **P19 噪声裁剪**: semgrep `use-tls`/`no-direct-write-to-responsewriter` 默认剔除（run3 的 10/21 FP、零 TP）；引擎级验证 go-ssrf 8→2、go-sqli 7→2、go-cmdi 4→1。预期第三轮 FP 21→11、F1 0.46→~0.62。
7. **P2 全链路（入口 + sink 两层）**: 三语言攻击路径全通——java `doGet→exec`、py `ping_host→system`、go `cmdiVulnHandler/ssrfVulnHandler/sqliVulnHandler→sink`（此前全 0，exploitability 全 not_exploitable）。

### 开放问题状态（P1–P4 全部关闭）

| # | 问题 | 影响 | 建议 |
|---|---|---|---|
| ~~P1~~ | ~~Semgrep --config auto 产 0 findings~~ | ~~引擎级检出为空~~ | ✅ **已修复 2026-08-26**：HOME 不可写致 semgrep 启动崩溃（引擎注入 SEMGREP_LOG_FILE）+ 相对路径双解析（resolve）；`HOME=/root` 下 python/go/java mini 均检出，4 项新测试 |
| ~~P2~~ | ~~CPG 可达性全标 not_exploitable~~ | ~~exploitability 判定质量低~~ | ✅ **已修复 2026-08-28**：①入口层（UTF-8 字节错位 + Servlet 识别）；②sink 层（finder 白名单补 Java method_invocation）+ 语言专属 sink pattern（go 补 SSRF/SQL）；三语言攻击路径全通；剩余扩展项：更多 sink 词表可随基准扩 |
| ~~P3~~ | ~~safe 文件 FP 多（agent 产低置信度 suspicious 条目）~~ | ~~Precision 低~~ | ✅ **已修复 2026-08-26**：suspicious 条目抽离为审查队列（默认不进报告，`include_suspicious_findings` 逃生阀可恢复）；DB 模拟 Precision 0.160→0.333、F1 0.271→0.485，零 TP 损失 |
| ~~P4~~ | ~~java-cmdi 漏报（agent 未识别 Runtime.exec 为 cmd_injection）~~ | ~~Recall 缺口~~ | ✅ **已修复 2026-08-27**：根因①run1 时该文件 agent 调用遇 provider 503 → FN；②`ox-alpha-free` 模型名已下线（401）→ 改用 deepseek-v4-flash 后 agent 检出 command_injection conf=1.0；semgrep（P1 后）另检出 tainted-cmd-from-http-request，双引擎覆盖 |

### 后续工作（按优先级）

| # | 项 | 说明 |
|---|---|---|
| N1 | **第三轮 mini 基线** | 重启服务加载全部新代码后重跑 run3 版数字，量化 P19 噪声裁剪（FP 21→11）+ P2 全链路（exploitability 不再是全 not_exploitable）联合收益 |
| N2 | **扩样本 owasp-subset** | 150 例（75正/75负、11 类）跑通后验证泛化；token 预估 1.5M–2M |
| N3 | **残余 FP 类型校准** | 第二轮 FP 21 中 agent 跨类型高置信误报（如 ssrf 文件报 cmdi）；可做 finding 与调用点/入口类型的绑定过滤 |
| N4 | **sink 词表扩展** | CPG 语言专属 pattern 当前覆盖 exec/http/sql/template；随 owasp 11 类（crypto/deserialization 等）扩词表 |
| N5 | **worker checkpoint 修复** | 本轮实际链路中 checkpoint_service 报 "Database not initialized"（沙箱 HOME 环境问题，不影响主流程结果） |

### 环境备忘

```bash
# 本机开发栈（无 docker；sqlite + redis + celery solo）
redis-server --daemonize yes
export DEEPVULN_DB_URL="sqlite+aiosqlite:////opt/pro/DeepVuln/data/deepvuln.db"
export CELERY_BROKER_URL="redis://localhost:6379/0" CELERY_RESULT_BACKEND="redis://localhost:6379/0"
export DEEPVULN_LLM_TRACE="/opt/pro/DeepVuln/data/llm_trace"
export DEEPVULN_SECURITY_JWT_SECRET="<openssl rand hex 32>"  # 或读 /tmp/dv_jwt_secret

# web (uvicorn)
.venv/bin/python -m uvicorn src.web.main:app --host 127.0.0.1 --port 8000

# celery worker（--pool=solo 绕沙箱禁 /dev/shm；必须 -u ALL_PROXY 因 httpx 缺 socksio）
.venv/bin/python -m celery -A src.web.tasks.scan_tasks worker -l info -Q scan --pool=solo
# ↑ 启动前: unset ALL_PROXY all_proxy

# benchmark
DEEPVULN_URL=http://127.0.0.1:8000 DEEPVULN_USER=admin DEEPVULN_PASS=dvbench2026 \
    .venv/bin/python benchmarks/eval/run_benchmark.py --target mini
```

⚠️ admin 密码已改为 dvbench2026（首次 seed 后改密）。DB 在 `data/deepvuln.db`。

---

## Phase 18 归档摘要（2026-06-20 ~ 08-25，已关闭）

第一~七批全部完成并 push：P0 精度链路、P1+P2 三语言 py/go/java CPG 可达性端到端接通、P3 嵌套 sink 进真实 CFG、P4 语言收敛、P5 续扫完整、P6 证据门改读证据结论+gatekeeper 接线、P7 可靠性+C6 引擎级 checkpoint(Tier1/Tier2)、P8 测试真实性。同日(2026-08-25)完成全量体检修复四批。test_l3 全绿 **2079 passed / 0 failed**。详见 `change-log.md` 2026-08-25 各条。

> 以下为 Phase 18 执行期历史记录（供参考，进度以顶部为准）

