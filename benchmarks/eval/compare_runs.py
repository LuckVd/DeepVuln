#!/usr/bin/env python3
"""对比两个 mini 基准运行报告（如 run3 vs run4），输出 P/R/F1 与 FP 构成差异。

用法:
  python3 benchmarks/eval/compare_runs.py run3 run4
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"


def load(tag: str) -> dict:
    p = RESULTS / f"{tag}_mini" / "report.json"
    if not p.exists():
        sys.exit(f"[err] 找不到 {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def fpb_breakdown(report: dict) -> dict:
    """FP 按 engine / rule 归类（不重复计数）。"""
    by_engine: Counter[str] = Counter()
    by_rule: Counter[str] = Counter()
    seen: set = set()
    det = report.get("detail", {})
    for group in ("fp_safe", "fp_other"):
        for ent in det.get(group, []):
            f = ent.get("finding") or {}
            key = (f.get("file_path"), f.get("line_start"), f.get("vuln_type"), f.get("engine"))
            if key in seen:
                continue
            seen.add(key)
            engine = f.get("engine") or "?"
            by_engine[engine] += 1
            em = f.get("extra_metadata") or {}
            rule = (em.get("semgrep_metadata") or {}).get("rule_id")
            rule = rule or f.get("vuln_type") or "?"
            by_rule[f"{engine}:{rule}"] += 1
    return {"by_engine": dict(by_engine), "by_rule": dict(by_rule)}


def cpg_stats(report: dict) -> dict:
    """TP/FP findings 中 cpg_path 非空与 exploitability_verification 口径分布。"""
    total = nonempty = 0
    expl: Counter[str] = Counter()
    for group in ("tp", "fp_safe", "fp_other"):
        for ent in report.get("detail", {}).get(group, []):
            f = ent.get("finding") or {}
            total += 1
            if f.get("cpg_path"):
                nonempty += 1
            em = f.get("extra_metadata") or {}
            ev = em.get("exploitability_verification") or {}
            if isinstance(ev, dict):
                label = str(ev.get("result") or ev.get("conclusion") or ev.get("exploitable") or "?")
            else:
                label = str(ev)
            expl[label] += 1
    return {"total_findings": total, "cpg_path_nonempty": nonempty, "exploitability": dict(expl)}


def main() -> int:
    tags = sys.argv[1:] or ["run3", "run4"]
    if len(tags) != 2:
        sys.exit("用法: compare_runs.py <tagA> <tagB>")
    a, b = load(tags[0]), load(tags[1])
    print(f"== {tags[0]} vs {tags[1]} ==")
    for t, r in (tags[0], a), (tags[1], b):
        o = r["overall"]
        print(f"[{t}] TP={o['tp']} FP={o['fp']} FN={o['fn']} "
              f"P={o['precision']} R={o['recall']} F1={o['f1']} raw={r['raw_findings_count']}")
    print("\n-- FP 构成 (engine) --")
    for t, r in (tags[0], a), (tags[1], b):
        print(f"[{t}] {fpb_breakdown(r)['by_engine']}")
    print("\n-- FP 构成 (engine:rule) 前 12 --")
    for t, r in (tags[0], a), (tags[1], b):
        top = sorted(fpb_breakdown(r)["by_rule"].items(), key=lambda x: -x[1])[:12]
        print(f"[{t}] {dict(top)}")
    print("\n-- CPG / exploitability (仅新 run) --")
    for t, r in (tags[1], b), (tags[0], a):
        print(f"[{t}] {cpg_stats(r)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())