# DeepVuln 检测基准（Benchmark）

> 目标：给 py/go/java 三语言的检测链路出 **P/R 数字**（对应 Phase 18 关闭后的"下一步建议①"）。
> 原则：**小、可复现、真值机器可读**。第三方源不进 git（`fetch.sh` 一键恢复），自建的 mini 集与清单进 git。

## 目录结构

```
benchmarks/
├── README.md                      # 本文件
├── fetch.sh                       # 下载/恢复 third_party 全部源
├── mini/                          # ⭐ MINI 集：每语言 3 例，vuln/safe 成对（进 git）
│   ├── python/{sqli,cmdi,eval}/   #   Flask 入口 → sink / safe 对照
│   ├── go/{cmdi,sqli,ssrf}/       #   net/http handler → sink（vuln/ 子目录 + safe/ 子目录）
│   ├── java/{cmdi,sqli,crypto}/   #   Servlet doGet/doPost → sink
│   └── truth.json                 # 真值：CWE + sink 注释标记 + cwe_keywords 匹配词
├── owasp_subset_manifest.json     # OWASP BenchmarkJava 分层子集 150 例真值（进 git）
├── eval/
│   ├── make_owasp_subset.py       # 从 expectedresults-1.2.csv 确定性抽样子集
│   └── run_benchmark.py           # 评测入口（selfcheck / api 两模式）
├── results/                       # 评测报告输出（gitignore）
└── third_party/                   # 第三方基准源（gitignore，fetch.sh 可重建）
    ├── securityeval/              #   Python 片段级：130 样本 / 75 CWE（vulnerable+patched）
    ├── go-test-bench/             #   Go 项目级漏洞应用（Contrast 官方，MIT）
    ├── django-nv/                 #   Python 项目级 Django 应用（NetSPI 维护）
    ├── owasp-benchmark/           #   Java 金标准 testcode 2740 用例 + 真值 CSV
    └── findsecbugs/               #   Java 用例级标注样例（find-sec-bugs src/test 树）
```

## MINI 集（快速冒烟 + P/R）

每语言 3 例，模式取自三大基准的同型 taint 流：

| 语言 | case | CWE | vuln 链路 | safe 对照 |
|---|---|---|---|---|
| python | sqli | CWE-89 | 路由参数 → `%` 拼 SQL → `cursor.execute` | 参数化 `?` |
| python | cmdi | CWE-78 | 路由参数 → `os.system` 拼接 | argv 列表 `shell=False` |
| python | eval | CWE-95 | 路由参数 → `eval()` | `ast.literal_eval` |
| go | cmdi | CWE-78 | query 参数 → `exec.Command("sh","-c",…)` | argv 直传 + 白名单正则 |
| go | sqli | CWE-89 | query 参数 → Sprintf 拼 SQL → `QueryRow` | 占位符参数化 |
| go | ssrf | CWE-918 | query URL → `http.Get` | 前缀白名单校验 |
| java | cmdi | CWE-78 | doGet 参数 → `Runtime.exec` 拼接 | ProcessBuilder + 正则白名单 |
| java | sqli | CWE-89 | doGet 参数 → Statement 拼接 execute | PreparedStatement |
| java | crypto | CWE-327 | `MessageDigest.getInstance("MD5")` | SHA-256 |

约定：vuln 文件恰有一行含 `SINK:` 注释；safe 文件不含任何 `SINK:` 注释。`truth.json` 的
`sink_comment` 与 `cwe_keywords` 分别用于离线自检和 finding 类型匹配。

## OWASP BenchmarkJava 子集

从 `expectedresults-1.2.csv`（2740 例）按类别分层抽取 **150 例（75 正 / 75 负，覆盖全部 11 类）**，
seed=42 可复现。评测时脚本把选中的 `.java` 暂存到 `results/owasp_stage/` 再整体扫描，
避免未选中用例产生噪声。

## 用法

```bash
# 0) 拉取第三方源（约 27MB，可重复执行断点续拉）
bash benchmarks/fetch.sh

# 1) 离线自检（不需要 Web 服务）：真值标注 ↔ 文件一致性
python3 benchmarks/eval/run_benchmark.py --target mini --mode selfcheck
python3 benchmarks/eval/run_benchmark.py --target owasp-subset --mode selfcheck

# 2) 走 Web API 实测 P/R（需先起 docker-compose-web 或本地 web 服务）
export DEEPVULN_URL=http://127.0.0.1:8000
export DEEPVULN_USER=admin DEEPVULN_PASS=...        # 或 DEEPVULN_API_KEY=...
python3 benchmarks/eval/run_benchmark.py --target mini --engines semgrep,ast,codeql
python3 benchmarks/eval/run_benchmark.py --target owasp-subset --engines semgrep,ast,codeql

# 3) 探索性目标（只报 finding 计数分布，无自动真值）
python3 benchmarks/eval/run_benchmark.py --target securityeval
python3 benchmarks/eval/run_benchmark.py --target gotestbench
python3 benchmarks/eval/run_benchmark.py --target djangonv
```

报告落在 `benchmarks/results/<tag>_<target>/report.json`（含逐 case 明细便于排查漏报误报）。

## 指标口径

- **mini**：TP = vuln 文件上的 finding 且类型关键词命中该 case 的 `cwe_keywords`；
  FP = safe 文件上任何 finding，或 vuln 文件上类型不符的 finding；FN = 无 TP 的 case。
  输出 overall P/R/F1 + 分语言 recall。
- **owasp-subset**：按用例文件归属。正样本有 ≥1 finding 记 TP（否则 FN）；负样本有 finding 记 FP（否则 TN）。
- **探索性目标**：无自动真值，只输出引擎/vuln_type 分布，供人工分析。

## 可观测性（跑分时看什么）

| 数据 | 位置 | 说明 |
|---|---|---|
| Token 消耗 | `GET /api/v1/scans/{id}/token-usage` | 总量 + prompt/completion 分项 + 预算百分比（聚合自 scan 记录） |
| Agent 会话 | `GET /api/v1/scans/{id}/agent-conversation` | agent 引擎的完整多轮对话存档 |
| 对抗辩论 | `GET /api/v1/scans/{id}/adversarial-debate` | attacker/defender/arbiter 各轮记录（开启 adversarial 时） |
| 验证结论流 | `GET /api/v1/scans/{id}/events` | 含逐 finding 的 verification_result 事件 |
| **LLM 原始报文** | `$DEEPVULN_LLM_TRACE/llm_trace.jsonl` | 每次调用的完整 messages + 响应全文 + usage + 耗时（opt-in，见下） |
| 运行日志 | stderr（Rich）；可设 `DEEPVULN_LOGGING_FILE` 落盘 | `DEEPVULN_LOGGING_LEVEL=DEBUG` 提级 |

**开启 LLM 报文追踪**：在 web/celery 进程环境设 `DEEPVULN_LLM_TRACE=<目录>`
（如 compose 的 environment 或 `.env`），例如 `DEEPVULN_LLM_TRACE=./data/llm_trace`。
该 env 在每次调用时读取，不设即关闭；不落 api_key。

## 注意事项

1. 片段级源（SecurityEval/findsecbugs）主要衡量**引擎检出率**；项目级源（mini/django.nV/go-test-bench/Benchmark）
   才会走完 入口识别 → CPG 可达性 → 多轮裁决 全链路。
2. 默认引擎集由服务端 `DEFAULT_SCAN_ENGINES` 决定；LLM 相关环节（agent/llm_verify/adversarial）
   会显著影响耗时与结果，对比测试时请固定 `--engines` 与 `--config-json`。
3. 本机无 CodeQL 时相关维度走降级路径，P/R 数字反映的是降级形态。
