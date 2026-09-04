#!/usr/bin/env python3
"""DeepVuln 基准评测脚本。

模式：
  --mode selfcheck   离线自检（真值标注 ↔ 文件一致性），不需要 Web 服务
  --mode api         走 DeepVuln Web API 提交扫描并统计 P/R（默认）

目标：
  mini               benchmarks/mini 三语言 9 例（vuln/safe 成对，P/R）
  owasp-subset       owasp_subset_manifest.json 抽取的 BenchmarkJava 子集（P/R，先暂存再扫）
  owasp-full         全量 2740 用例目录（探索性，只报计数）
  securityeval       SecurityEval Testcases_Insecure_Code（探索性）
  gotestbench        go-test-bench 项目级（探索性）
  djangonv           django.nV 项目级（探索性）

环境变量：
  DEEPVULN_URL       默认 http://127.0.0.1:8000
  DEEPVULN_USER / DEEPVULN_PASS   JWT 登录（可选）
  DEEPVULN_API_KEY   API key（可选）

示例：
  python3 benchmarks/eval/run_benchmark.py --target mini --mode selfcheck
  python3 benchmarks/eval/run_benchmark.py --target mini \
      --engines semgrep,ast,codeql --api-url http://127.0.0.1:8000
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BENCH_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = BENCH_ROOT.parent
MINI_ROOT = BENCH_ROOT / "mini"
TRUTH_PATH = MINI_ROOT / "truth.json"
MANIFEST_PATH = BENCH_ROOT / "owasp_subset_manifest.json"
RESULTS_DIR = BENCH_ROOT / "results"

TERMINAL_STATUSES = {"completed", "failed", "cancelled", "error"}
EXPLORATORY_TARGETS = {
    "securityeval": "third_party/securityeval/Testcases_Insecure_Code",
    "gotestbench": "third_party/go-test-bench",
    "djangonv": "third_party/django-nv",
    "owasp-full": "third_party/owasp-benchmark/testcode",
}


# --------------------------------------------------------------------------- HTTP 客户端
class ApiClient:
    def __init__(self, base_url: str, timeout: int = 120) -> None:
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.token: str | None = None
        self.api_key = os.environ.get("DEEPVULN_API_KEY")
        user, passwd = os.environ.get("DEEPVULN_USER"), os.environ.get("DEEPVULN_PASS")
        if user and passwd and not self.api_key:
            self._login(user, passwd)

    def _login(self, user: str, passwd: str) -> None:
        data = self.request("POST", "/api/v1/auth/login",
                            payload={"username": user, "password": passwd})
        for key in ("access_token", "token", "accessToken"):
            if isinstance(data, dict) and data.get(key):
                self.token = data[key]
                break
            if isinstance(data, dict) and isinstance(data.get("data"), dict):
                self.token = data["data"].get(key)
        print(f"[auth] 登录{'成功' if self.token else '失败（响应无 token 字段）'}")

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        elif self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    def request(self, method: str, path: str, payload: dict | None = None,
                raw: bool = False) -> dict:
        req = urllib.request.Request(
            self.base + path, data=json.dumps(payload).encode() if payload is not None else None,
            headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode()
                return json.loads(body) if body and not raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:500]
            raise SystemExit(f"[err] HTTP {exc.code} {method} {path}: {detail}") from exc


# --------------------------------------------------------------------------- 扫描生命周期
def create_and_run_scan(api: ApiClient, source_path: Path, name: str,
                        engines: list[str] | None, extra_config: dict,
                        poll_timeout: int) -> dict:
    config: dict = dict(extra_config or {})
    if engines:
        config["engines"] = engines
    payload = {
        "name": name,
        "source_type": "local",
        "source_path": str(source_path),
        "scan_type": "full",
    }
    if config:
        payload["config"] = config
    created = api.request("POST", "/api/v1/scans", payload)
    scan_id = created.get("id") or created.get("data", {}).get("id")
    if scan_id is None:
        raise SystemExit(f"[err] 创建扫描未返回 id: {json.dumps(created)[:300]}")
    api.request("POST", f"/api/v1/scans/{scan_id}/start")
    return _poll(api, scan_id, poll_timeout)


def _poll(api: ApiClient, scan_id, poll_timeout: int) -> dict:
    deadline = time.time() + poll_timeout
    last = ""
    while time.time() < deadline:
        snap = api.request("GET", f"/api/v1/scans/{scan_id}")
        status = str(snap.get("status", ""))
        if status != last:
            print(f"  [scan {scan_id}] status -> {status}")
            last = status
        if status in TERMINAL_STATUSES:
            return snap
        time.sleep(10)
    raise TimeoutError(f"扫描 {scan_id} 超过 {poll_timeout}s 未结束")


def fetch_findings(api: ApiClient, scan_id, page_size: int = 200) -> list[dict]:
    items: list[dict] = []
    page = 1
    while True:
        resp = api.request("GET", f"/api/v1/scans/{scan_id}/findings?page={page}&page_size={page_size}")
        batch = (resp.get("findings") or resp.get("items") or []) if isinstance(resp, dict) else []
        items.extend(batch)
        total = int(resp.get("total", len(items)))
        if len(items) >= total or not batch:
            break
        page += 1
    return items


# --------------------------------------------------------------------------- 匹配与指标
def _finding_text(f: dict) -> str:
    return " ".join(str(f.get(k) or "") for k in ("vuln_type", "title")).lower()


def _basename(p: str | None) -> str:
    return Path(p or "").name.lower()


_SINK_FAMILY_TOKENS: dict[str, tuple[str, ...]] = {
    "sql-injection": ("sql", "sqli"),
    "command-injection": ("command", "cmd", "cmdi"),
    "code-injection": ("code", "eval"),
    "ssrf": ("ssrf",),
    "weak-hash": ("md5", "sha1", "weak", "crypto", "hash"),
}


def _family_tokens(case) -> tuple[str, ...]:
    """Type-family tokens for a case, derived from its sink_comment.

    Audit 2026-09 fix: matching on the raw ``cwe_keywords`` swallowed
    cross-type FPs — the generic keyword "injection" matched
    *any* ``*_injection`` vuln_type, so a command_injection finding on a
    sql case was counted as a duplicate TP instead of an FP (and the
    reverse inflated precision in both directions). Family tokens are
    distinctive per type so cross-type findings never match.
    """
    comment = str(case.get("sink_comment") or "").lower()
    for sig, tokens in _SINK_FAMILY_TOKENS.items():
        if sig in comment:
            return tokens
    # Fallback: keep the case's own keywords minus generic carriers.
    return tuple(
        kw for kw in (case.get("cwe_keywords") or [])
        if kw not in ("injection", "rce", "dynamic", "exec", "process",
                      "outbound", "fetch", "broken crypto")
    )


def _rel_to_case(p: str, case) -> str:
    """Normalize a finding path to be comparable with case vuln/safe files.

    Finding file_paths are relative to the *case scan directory* (e.g.
    ``vuln/main.go``, ``safe/main.go``) or absolute; truth files are
    relative to MINI_ROOT (e.g. ``go/sqli/vuln/main.go``). Return the
    case-dir-relative form from either.
    """
    p = (p or "").replace("\\", "/")
    case_dir = (case.get("dir") or "").replace("\\", "/").rstrip("/")
    if case_dir and case_dir + "/" in p:
        p = p.split(case_dir + "/", 1)[1]
    elif "://" in p:  # pragma: no cover - not expected for mini
        p = p.split("://", 1)[1]
    return p.strip("/").lower()


def evaluate_mini_cases(findings: list[dict], truth: dict) -> dict:
    """按 case 归属判定：TP=vuln 文件且类型关键词匹配；FP=safe 文件任何 finding 或类型不符。

    Audit 2026-09 fix: findings are tagged with their case id by
    ``run_mini`` (``_benchmark_case``), and file attribution uses the
    case-relative path (``vuln/...`` vs ``safe/...``) instead of basenames.
    Basename matching silently swallowed real safe-file FPs: all Go cases
    share ``main.go`` and every Java pair shares a Servlet name, so the old
    ``all_vuln_bases`` dict collapsed cases and same-type findings on safe
    files were mis-attributed to other cases' vuln files.
    """
    tp, fn = [], []
    fp_safe, fp_other = [], []
    hit: set[str] = set()

    case_by_id = {c["id"]: c for c in truth["cases"]}

    for f in findings:
        cid = f.get("_benchmark_case")
        if cid is not None and cid in case_by_id:
            case = case_by_id[cid]
        else:
            # Untagged finding (external use): attribute by unique case-relative
            # path match; ambiguous → unknown-file FP rather than a guess.
            base_l = Path(f.get("file_path") or "").name.lower()
            candidates = [c for c in truth["cases"]
                          if _rel_to_case(c["vuln_file"], c) == base_l
                          or _rel_to_case(c["safe_file"], c) == base_l]
            if len(candidates) != 1:
                fp_other.append({"case": None, "reason": "unknown-file", "finding": f})
                continue
            case = candidates[0]
            cid = case["id"]

        vuln_rel = _rel_to_case(case["vuln_file"], case)
        safe_rel = _rel_to_case(case["safe_file"], case)
        fpath = _rel_to_case(f.get("file_path") or "", case)
        text = _finding_text(f)
        text_ok = any(tok in text for tok in _family_tokens(case))

        if fpath == vuln_rel and text_ok:
            if cid not in hit:
                hit.add(cid)
                tp.append({"case": cid, "cwe": case["cwe"], "finding": f})
            # else: duplicate of an already-counted TP — ignore.
        elif fpath == vuln_rel:
            fp_other.append({"case": cid, "reason": "type-mismatch", "finding": f})
        elif fpath == safe_rel:
            fp_safe.append({"safe_file": safe_rel, "finding": f})
        else:
            fp_other.append({"case": cid, "reason": "unknown-file", "finding": f})

    for case in truth["cases"]:
        if case["id"] not in hit:
            fn.append({"case": case["id"], "cwe": case["cwe"]})
    return {"tp": tp, "fp_safe": fp_safe, "fp_other": fp_other, "fn": fn}


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return round(precision, 3), round(recall, 3), round(f1, 3)


def summarize_mini(m: dict, truth: dict) -> dict:
    tp, fp, fn = len(m["tp"]), len(m["fp_safe"]) + len(m["fp_other"]), len(m["fn"])
    p, r, f1 = prf(tp, fp, fn)
    by_lang = defaultdict(lambda: {"tp": 0, "fn": 0})
    lang_of = {c["id"]: c["language"] for c in truth["cases"]}
    for t in m["tp"]:
        by_lang[lang_of[t["case"]]]["tp"] += 1
    for x in m["fn"]:
        by_lang[lang_of[x["case"]]]["fn"] += 1
    langs = {}
    for lang, v in sorted(by_lang.items()):
        lp, lr, lf1 = prf(v["tp"], 0, v["fn"])
        langs[lang] = {"tp": v["tp"], "fn": v["fn"], "recall": lr}
    return {
        "overall": {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1},
        "by_language": langs,
        "detail": m,
    }


# --------------------------------------------------------------------------- 自检
def selfcheck_mini() -> int:
    truth = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))
    ok = True
    for case in truth["cases"]:
        vuln = MINI_ROOT / case["vuln_file"]
        safe = MINI_ROOT / case["safe_file"]
        problems: list[str] = []
        if not vuln.exists():
            problems.append(f"缺文件 {vuln}")
        else:
            hits = [ln for ln in vuln.read_text(encoding="utf-8").splitlines()
                    if case["sink_comment"] in ln]
            if len(hits) != 1:
                problems.append(f"{vuln.name} 中 sink_comment 出现 {len(hits)} 次（应为 1）")
        if not safe.exists():
            problems.append(f"缺文件 {safe}")
        elif "SINK:" in safe.read_text(encoding="utf-8"):
            problems.append(f"{safe} 不应含 SINK 注释")
        if problems:
            ok = False
            print(f"[FAIL] {case['id']}: " + "; ".join(problems))
        else:
            print(f"[ok] {case['id']} ({case['language']}, {case['cwe']})")
    print("===> selfcheck " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def selfcheck_owasp() -> int:
    if not MANIFEST_PATH.exists():
        print("[FAIL] 缺少 owasp_subset_manifest.json —— 先跑 make_owasp_subset.py")
        return 1
    man = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    missing = [c["file"] for c in man["cases"]
               if not (BENCH_ROOT / "third_party/owasp-benchmark/testcode" / c["file"]).exists()]
    if missing:
        print(f"[FAIL] {len(missing)} 个用例缺源文件")
        return 1
    print(f"[ok] manifest {man['selected']} 例（pos={man['pos_count']} neg={man['neg_count']}）源文件齐全")
    print("===> selfcheck PASS")
    return 0


# --------------------------------------------------------------------------- 各 target 运行
def stage_owasp_subset() -> Path:
    man = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    stage = RESULTS_DIR / "owasp_stage"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    src_root = BENCH_ROOT / "third_party/owasp-benchmark/testcode"
    for c in man["cases"]:
        shutil.copy2(src_root / c["file"], stage / c["file"])
    print(f"[stage] 暂存 {len(man['cases'])} 个用例 -> {stage}")
    return stage


def run_owasp_subset(api: ApiClient, args) -> dict:
    man = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    stage = stage_owasp_subset()
    snap = create_and_run_scan(api, stage, f"benchmark-owasp-subset-{args.tag}",
                               args.engines, args.config_json, args.poll_timeout)
    findings = fetch_findings(api, snap["id"])
    print(f"[findings] 共 {len(findings)} 条")

    flagged: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        flagged[_basename(f.get("file_path"))].append(f)
    tp, fp, fn, tn = 0, 0, 0, 0
    detail_rows = []
    for c in man["cases"]:
        found = flagged.get(_basename(c["file"]), [])
        if c["real_vuln"] and found:
            tp += 1
        elif c["real_vuln"]:
            fn += 1
        elif found:
            fp += 1
        else:
            tn += 1
        detail_rows.append({**c, "found": len(found),
                            "engines": sorted({f.get("engine") for f in found})})
    p, r, f1 = prf(tp, fp, fn)
    result = {
        "target": "owasp-subset", "scan_id": snap.get("id"), "status": snap.get("status"),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": p, "recall": r, "f1": f1, "raw_findings_count": len(findings),
        "per_case": detail_rows,
    }
    _print_confusion(result)
    return result


def run_mini(api: ApiClient, args) -> dict:
    truth = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))
    all_findings: list[dict] = []
    scans = []
    for case in truth["cases"]:
        case_dir = MINI_ROOT / case["dir"]
        print(f"[scan] case {case['id']} ({case['dir']})")
        snap = create_and_run_scan(api, case_dir, f"benchmark-mini-{case['id']}-{args.tag}",
                                   args.engines, args.config_json, args.poll_timeout)
        fs = fetch_findings(api, snap["id"])
        print(f"  -> status={snap.get('status')} findings={len(fs)}")
        scans.append({"case": case["id"], "scan_id": snap.get("id"), "status": snap.get("status")})
        # Tag each finding with its case so evaluation never has to guess
        # from (colliding) basenames.
        for f in fs:
            f["_benchmark_case"] = case["id"]
        all_findings.extend(fs)
    matched = evaluate_mini_cases(all_findings, truth)
    summary = summarize_mini(matched, truth)
    result = {"target": "mini", "scans": scans, "raw_findings_count": len(all_findings),
              **summary}
    o = summary["overall"]
    print(f"\n[mini 结果] TP={o['tp']} FP={o['fp']}(safe:{len(summary['detail']['fp_safe'])}) "
          f"FN={o['fn']}  P={o['precision']} R={o['recall']} F1={o['f1']}")
    for lang, v in summary["by_language"].items():
        print(f"  - {lang:<7} tp={v['tp']} fn={v['fn']} recall={v['recall']}")
    return result


def run_exploratory(api: ApiClient, target: str, args) -> dict:
    rel = EXPLORATORY_TARGETS[target]
    path = REPO_ROOT / rel
    if not path.exists():
        raise SystemExit(f"[err] 目标不存在: {path}（先跑 benchmarks/fetch.sh）")
    snap = create_and_run_scan(api, path, f"benchmark-{target}-{args.tag}",
                              args.engines, args.config_json, args.poll_timeout)
    findings = fetch_findings(api, snap["id"])
    by_engine = defaultdict(int)
    by_type = defaultdict(int)
    for f in findings:
        by_engine[f.get("engine")] += 1
        by_type[f.get("vuln_type")] += 1
    result = {
        "target": target, "path": rel, "scan_id": snap.get("id"), "status": snap.get("status"),
        "findings_total": len(findings),
        "by_engine": dict(sorted(by_engine.items(), key=lambda x: -x[1])),
        "by_vuln_type": dict(sorted(by_type.items(), key=lambda x: -x[1])[:20]),
    }
    print(f"\n[{target}] status={snap.get('status')} findings={len(findings)}")
    print(f"  by engine: {result['by_engine']}")
    print(f"  top vuln types: {list(result['by_vuln_type'].items())[:8]}")
    return result


def _print_confusion(r: dict) -> None:
    c = r["confusion"]
    print(f"\n[owasp-subset] TP={c['tp']} FP={c['fp']} FN={c['fn']} TN={c['tn']}  "
          f"P={r['precision']} R={r['recall']} F1={r['f1']}")


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="mini",
                    choices=["mini", "owasp-subset"] + list(EXPLORATORY_TARGETS))
    ap.add_argument("--mode", default="api", choices=["api", "selfcheck"])
    ap.add_argument("--api-url", default=os.environ.get("DEEPVULN_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--engines", default=None,
                    help="逗号分隔，如 semgrep,ast,codeql；缺省用服务端默认引擎")
    ap.add_argument("--config-json", default="{}", help="追加进 ScanConfig 的 JSON 片段")
    ap.add_argument("--poll-timeout", type=int, default=3600)
    ap.add_argument("--tag", default=datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    args = ap.parse_args()

    if args.mode == "selfcheck":
        if args.target == "mini":
            return selfcheck_mini()
        if args.target == "owasp-subset":
            return selfcheck_owasp()
        print("[warn] 该目标无自检逻辑，跳过")
        return 0

    args.engines = [e.strip() for e in args.engines.split(",")] if args.engines else None
    try:
        args.config_json = json.loads(args.config_json)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[err] --config-json 不是合法 JSON: {exc}") from exc

    api = ApiClient(args.api_url)
    if args.target == "mini":
        result = run_mini(api, args)
    elif args.target == "owasp-subset":
        result = run_owasp_subset(api, args)
    else:
        result = run_exploratory(api, args.target, args)

    out_dir = RESULTS_DIR / f"{args.tag}_{args.target}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "report.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[report] 已写出 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
