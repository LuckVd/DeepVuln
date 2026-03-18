#!/usr/bin/env bash
set -euo pipefail

INTENT_FILE="${1:-}"
STATUS_FILE="${2:-}"

if [[ -z "$INTENT_FILE" || -z "$STATUS_FILE" ]]; then
  echo "Usage: tools/check_scope.sh <change-intent-file> <git-status-file>"
  exit 1
fi

if [[ ! -f "$INTENT_FILE" || ! -f "$STATUS_FILE" ]]; then
  echo "Scope check failed: missing input file"
  exit 1
fi

if ! grep -q "planned_files:" "$INTENT_FILE"; then
  echo "Scope check failed: missing planned_files"
  exit 1
fi

echo "Scope check passed (minimal)"
