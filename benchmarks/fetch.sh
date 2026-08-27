#!/usr/bin/env bash
# Download third-party benchmark sources into benchmarks/third_party/.
#
# 组成（对应 docs/ai 调研结论，全部为公开仓库）：
#   1. securityeval      Python 片段级（130 样本 / 75 CWE，vulnerable+patched 对照）
#   2. go-test-bench     Go 项目级漏洞应用（Contrast 官方，MIT）
#   3. django-nv         Python 项目级 Django 应用（NetSPI 维护）
#   4. owasp-benchmark   Java 金标准——只抽取 testcode 源码树 + 真值 CSV（全仓 ~75MB 太大）
#   5. findsecbugs       Java 用例级标注样例（src/test 树，可选补充）
#
# 所有产物落在 third_party/ 下（已 gitignore），可随时删除后重跑本脚本恢复。
set -uo pipefail
cd "$(dirname "$0")"

DL="${BENCH_DL_DIR:-$(mktemp -d)}"
mkdir -p third_party "$DL"

log() { echo "[fetch] $*"; }

fetch_tgz() { # fetch_tgz <owner/repo> <outfile> <branch...>
    local repo="$1" out="$2"; shift 2
    local br
    for br in "$@"; do
        log "GET $repo ($br)"
        if curl -fsSL --retry 2 --max-time 900 -o "$DL/$out" \
            "https://codeload.github.com/${repo}/tar.gz/refs/heads/${br}"; then
            return 0
        fi
    done
    echo "[fetch] FAILED: $repo" >&2
    return 1
}

# ---------------------------------------------------------------- 1. SecurityEval
if [ ! -d third_party/securityeval ]; then
    fetch_tgz s2e-lab/SecurityEval securityeval.tgz main && \
    mkdir -p third_party/securityeval && \
    tar xzf "$DL/securityeval.tgz" -C third_party/securityeval --strip-components=1 && \
    log "securityeval ok ($(du -sh third_party/securityeval | cut -f1))"
else log "securityeval 已存在，跳过"; fi

# ---------------------------------------------------------------- 2. go-test-bench
if [ ! -d third_party/go-test-bench ]; then
    fetch_tgz Contrast-Security-OSS/go-test-bench gotestbench.tgz main && \
    mkdir -p third_party/go-test-bench && \
    tar xzf "$DL/gotestbench.tgz" -C third_party/go-test-bench --strip-components=1 && \
    log "go-test-bench ok ($(du -sh third_party/go-test-bench | cut -f1))"
else log "go-test-bench 已存在，跳过"; fi

# ---------------------------------------------------------------- 3. django.nV
if [ ! -d third_party/django-nv ]; then
    fetch_tgz NetSPI/django.nV djangonv.tgz master && \
    mkdir -p third_party/django-nv && \
    tar xzf "$DL/djangonv.tgz" -C third_party/django-nv --strip-components=1 && \
    log "django-nv ok ($(du -sh third_party/django-nv | cut -f1))"
else log "django-nv 已存在，跳过"; fi

# ---------------------------------------------------------------- 4. OWASP BenchmarkJava（只取 testcode + 真值 CSV）
if [ ! -d third_party/owasp-benchmark/testcode ]; then
    fetch_tgz OWASP-Benchmark/BenchmarkJava benchmarkjava.tgz master && \
    rm -rf "$DL/BenchmarkJava-master" && \
    tar xzf "$DL/benchmarkjava.tgz" -C "$DL" && \
    mkdir -p third_party/owasp-benchmark && \
    cp -r "$DL/BenchmarkJava-master/src/main/java/org/owasp/benchmark/testcode" \
        third_party/owasp-benchmark/testcode && \
    cp "$DL"/BenchmarkJava-master/*.csv third_party/owasp-benchmark/ ; \
    log "owasp-benchmark ok (testcode $(ls third_party/owasp-benchmark/testcode | wc -l) files; csv $(ls third_party/owasp-benchmark/*.csv 2>/dev/null | wc -l))"
else log "owasp-benchmark 已存在，跳过"; fi

# ---------------------------------------------------------------- 5. findsecbugs（src/test 用例树）
if [ ! -d third_party/findsecbugs ]; then
    fetch_tgz find-sec-bugs/find-sec-bugs findsecbugs.tgz master && \
    mkdir -p third_party/findsecbugs && \
    tar xzf "$DL/findsecbugs.tgz" -C third_party/findsecbugs --strip-components=1 && \
    log "findsecbugs ok ($(du -sh third_party/findsecbugs | cut -f1))"
else log "findsecbugs 已存在，跳过"; fi

log "完成。third_party 总大小: $(du -sh third_party | cut -f1)"
