#!/usr/bin/env bash
set -euo pipefail

STATUS_FILE="${1:-}"
CHANGE_INTENT_FILE="${2:-}"

yaml_true() {
  local file="$1"
  local key="$2"
  [[ -f "$file" ]] || return 1
  grep -Eq "^${key}: +(true|yes|approved)$" "$file"
}

if [[ -z "$STATUS_FILE" || ! -f "$STATUS_FILE" ]]; then
  echo "Usage: tools/check_protection.sh <git-status-file>"
  exit 1
fi

if grep -E '^\?\? |^[ MADRCU]+\s+(\.claude/|tools/)' "$STATUS_FILE" >/dev/null; then
  if [[ -n "$CHANGE_INTENT_FILE" ]] && yaml_true "$CHANGE_INTENT_FILE" "core_change_acknowledged"; then
    echo "Protection check passed (core file changes acknowledged)"
    exit 0
  fi
  echo "Protection check: core files changed; explicit confirmation required"
  exit 2
fi

if grep -E '^[ MADRCU]+\s+(docs/goals/|docs/roadmap/|docs/history/)' "$STATUS_FILE" >/dev/null; then
  if [[ -n "$CHANGE_INTENT_FILE" ]] && yaml_true "$CHANGE_INTENT_FILE" "stable_change_acknowledged"; then
    echo "Protection check passed (stable planning changes acknowledged)"
    exit 0
  fi
  echo "Protection check: stable files changed; proposal required"
  exit 3
fi

echo "Protection check passed"
