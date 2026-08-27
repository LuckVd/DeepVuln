# Current Goal

> **状态**: ✅ 已立项（2026-08-26）— Phase 18 已关闭；**benchmark 基础设施已建成 + 首轮 mini 基线已出数**；Phase 19 开工，按 P1→P3→P4→P2 修基线问题并迭代扩样本
>
> **Goal ID**: phase19-benchmark-eval
> **创建日期**: 2026-08-26
> **上一 goal**: Phase 18 — 精度链路接通与多语言可达性补齐（✅ 2026-08-25 关闭）
> **当前执行**: P1 ✅ + P3 ✅ 已修复（Semgrep 零 findings 根因：HOME 不可写+相对路径双解析；suspicious 条目抽离审查队列，DB 模拟 Precision 0.16→0.333 零 TP 损失）→ 下一步 P4（java-cmdi 补检）

---

## 📊 当前状态快照（新会话先看这个）

### 已完成（本次会话 2026-08-26，未 commit）

1. **state.yaml 对齐**: Phase 18 状态从 active/pending 改为 closed/completed
2. **基准基础设施建成** `benchmarks/`:
   - `fetch.sh`: 一键拉取第三方源到 `third_party/`（gitignore，27MB）——SecurityEval / go-test-bench / django-nv / OWASP BenchmarkJava(testcode 2740 文件 + 真值 CSV) / findsecbugs
   - **mini 集** `mini/`: 每语言 3 例共 9 例（py: sqli/cmdi/eval; go: cmdi/sqli/ssrf; java: cmdi/sqli/crypto），vuln/safe 成对，`truth.json` 含 sink_comment 自检标记 + cwe_keywords 匹配词
   - **OWASP 子集清单** `owasp_subset_manifest.json`: 分层抽 150 例（75 正/75 负，11 类全覆盖），seed=42 可复现
   - **评测脚本** `eval/run_benchmark.py`: selfcheck（离线真值↔文件一致性）+ api（Web API 提交→轮询→拉 findings→P/R/F1）；另有 owasp-subset/owasp-full/securityeval/gotestbench/djangonv 目标
   - `eval/make_owasp_subset.py`: 确定性分层抽样
   - `eval/seed_llm_config.py`: 幂等把 ox-alpha-free 写入 DB llm_configs 表
   - `README.md`: 结构/用法/指标口径

3. **AST 规则修复（7 条编译失败清零）**:
   - 6 条 S-expression 语法修复（django_extra_raw_sql / flask_render_string_template / java_jni_register_natives / go_context_without_deadline / **go_defer_close_file**（根因：go AST block 下有 statement_list 包裹层）/ python_subprocess_shell）
   - `tree_sitter_manager.py`: TypeScript 加载回退——tree_sitter_typescript≥0.23 暴露 `language_typescript/language_tsx` 而非 `.language`
   - 验证: 27/27 查询编译通过；ast/detector/rule 相关单测 246 passed

4. **LLM 调用追踪** `openai_client.py`: env `DEEPVULN_LLM_TRACE=<dir>` 开启 JSONL 落盘（完整 messages + 响应 + usage + 耗时）；不落 api_key

5. **ox-alpha-free 接入**: seed_llm_config.py 幂等写入 DB → agent 扫描与可利用性验证两条链路均使用 opencode-go / ox-alpha-free（ctx 1M / maxTokens 131072 / base_url `https://opencode.ai/zen/go/v1`）；key 从 `~/.dsh/.credentials.yaml` refs 解析

6. **首轮 mini 实测基线**（9 case 全跑完）:
   | conf>= | TP | FP(safe) | FN | P | R | F1 |
   |---|---|---|---|---|---|---|
   | 0.0 | 8 | 26 | 1 | 0.235 | **0.889** | 0.372 |
   | 0.5 | 8 | 11 | 1 | 0.421 | **0.889** | 0.571 |
   | 0.7 | 7 | 6 | 2 | 0.538 | 0.778 | **0.636** |

   总 token: **112,503**（~12.5K/case）; LLM trace 38 条在 `data/llm_trace/llm_trace.jsonl`

### ⚠️ 发现的问题（按优先级，下一步做）

| # | 问题 | 影响 | 建议 |
|---|---|---|---|
| ~~P1~~ | ~~Semgrep --config auto 产 0 findings~~ | ~~引擎级检出为空~~ | ✅ **已修复 2026-08-26**：HOME 不可写致 semgrep 启动崩溃（引擎注入 SEMGREP_LOG_FILE）+ 相对路径双解析（resolve）；`HOME=/root` 下 python/go/java mini 均检出，4 项新测试 |
| **P2** | **CPG 可达性全标 not_exploitable**（reachability=0.10）| exploitability 判定质量低 | Flask/Spring/net-http 入口未被 CPG 识别为外部入口——Phase 18 已知问题，mini 基准首次量化了影响 |
| ~~P3~~ | ~~safe 文件 FP 多（agent 产低置信度 suspicious 条目）~~ | ~~Precision 低~~ | ✅ **已修复 2026-08-26**：suspicious 条目抽离为审查队列（默认不进报告，`include_suspicious_findings` 逃生阀可恢复）；DB 模拟 Precision 0.160→0.333、F1 0.271→0.485，零 TP 损失 |
| **P4** | **java-cmdi 漏报**（agent 未识别 Runtime.exec 为 cmd_injection）| Recall 缺口 | 补 prompt 规则或加 dangerous API 检测（semgrep 已检出 tainted-cmd-from-http-request，可作跨引擎印证） |

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

