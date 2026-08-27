#!/usr/bin/env python3
"""从 OWASP BenchmarkJava 真值 CSV 抽取分层子集，生成评测清单。

用法：
    python3 benchmarks/eval/make_owasp_subset.py [--total 150] [--seed 42]

输出：benchmarks/owasp_subset_manifest.json
    {"source_csv": ..., "staged_dir_note": ..., "cases": [
        {"test": "BenchmarkTest00001", "file": "BenchmarkTest00001.java",
         "real_vuln": true, "category": "pathtraver", "cwe": 22}, ...]}

抽样策略（确定性，seed 可复现）：
  - 正/负样本约各半（正样本 = real vulnerability == true）
  - 按 category 分层配额（大类别多抽、小类别保底），保证覆盖全部 11 类
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

BENCH_ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = BENCH_ROOT / "third_party" / "owasp-benchmark" / "expectedresults-1.2.csv"
OUT_PATH = BENCH_ROOT / "owasp_subset_manifest.json"


def load_rows() -> list[dict]:
    rows: list[dict] = []
    with CSV_PATH.open(newline="", encoding="utf-8") as fh:
        # 首行是注释头：# test name, category, real vulnerability, cwe, ...
        reader = csv.reader(fh)
        header = next(reader)
        assert header[0].startswith("#"), f"意外 CSV 头: {header}"
        for rec in reader:
            if len(rec) < 4:
                continue
            rows.append(
                {
                    "test": rec[0].strip(),
                    "category": rec[1].strip(),
                    "real_vuln": rec[2].strip().lower() == "true",
                    "cwe": int(rec[3]),
                }
            )
    return rows


def stratified_sample(rows: list[dict], total: int, seed: int) -> list[dict]:
    rng = random.Random(seed)

    pos = defaultdict(list)
    neg = defaultdict(list)
    for r in rows:
        (pos if r["real_vuln"] else neg)[r["category"]].append(r)

    n_pos = total // 2
    n_neg = total - n_pos

    def allocate(buckets: dict[str, list[dict]], quota: int) -> list[dict]:
        """按类别大小比例分配配额，小类别至少保底 2 个。"""
        cats = sorted(buckets)
        weights = {c: max(len(buckets[c]), 1) for c in cats}
        wsum = sum(weights.values())
        alloc = {c: max(2, round(quota * weights[c] / wsum)) for c in cats}
        # 收敛到 quota
        while sum(alloc.values()) > quota:
            big = max(alloc, key=lambda c: alloc[c])
            if alloc[big] <= 2:
                break
            alloc[big] -= 1
        picked: list[dict] = []
        for c in cats:
            pool = buckets[c][:]
            rng.shuffle(pool)
            take = min(alloc[c], quota - len(picked), len(pool))
            picked.extend(pool[:take])
            if len(picked) >= quota:
                break
        return picked

    chosen = allocate(pos, n_pos) + allocate(neg, n_neg)
    rng.shuffle(chosen)
    return chosen


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--total", type=int, default=150)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rows = load_rows()
    print(f"[csv] 共 {len(rows)} 行用例")
    subset = stratified_sample(rows, args.total, args.seed)

    missing = [
        r["test"]
        for r in subset
        if not (BENCH_ROOT / "third_party/owasp-benchmark/testcode" / f"{r['test']}.java").exists()
    ]
    if missing:
        raise SystemExit(f"[err] {len(missing)} 个用例缺源文件，如 {missing[:5]}")

    cases = [
        {
            "test": r["test"],
            "file": f"{r['test']}.java",
            "real_vuln": r["real_vuln"],
            "category": r["category"],
            "cwe": r["cwe"],
        }
        for r in subset
    ]
    manifest = {
        "version": 1,
        "seed": args.seed,
        "source_csv": str(CSV_PATH.relative_to(BENCH_ROOT)),
        "total_pool": len(rows),
        "selected": len(cases),
        "pos_count": sum(1 for c in cases if c["real_vuln"]),
        "neg_count": sum(1 for c in cases if not c["real_vuln"]),
        "category_dist": dict(Counter(c["category"] for c in cases)),
        "cases": cases,
    }
    OUT_PATH.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[ok] 写出 {OUT_PATH} ({len(cases)} 例, pos={manifest['pos_count']} neg={manifest['neg_count']})")
    print(f"[ok] 类别分布: {manifest['category_dist']}")


if __name__ == "__main__":
    main()
