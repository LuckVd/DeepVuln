#!/usr/bin/env bash
set -euo pipefail

FILE="${1:-docs/reports/cleanup-notes.md}"

if [[ ! -f "$FILE" ]]; then
  echo "Cleanup check passed: no cleanup notes file"
  exit 0
fi

if grep -E '^- \[ \]' "$FILE" >/dev/null; then
  echo "Cleanup check failed: unresolved cleanup items remain"
  exit 2
fi

echo "Cleanup check passed"
