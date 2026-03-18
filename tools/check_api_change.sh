#!/usr/bin/env bash
set -euo pipefail

STATUS_FILE="${1:-}"

if [[ -z "$STATUS_FILE" || ! -f "$STATUS_FILE" ]]; then
  echo "Usage: tools/check_api_change.sh <git-status-file>"
  exit 1
fi

if grep -E '^[ MADRCU]+\s+(docs/api/|src/api/|src/routes/|src/controllers/|src/endpoints/)' "$STATUS_FILE" >/dev/null; then
  echo "API change detected: extra review required"
  exit 2
fi

echo "No API change detected"
