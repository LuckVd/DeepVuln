#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_STATUS="$(mktemp)"
REPORT="$ROOT_DIR/docs/reports/commit-gate-latest.md"
CHANGE_INTENT="${1:-$ROOT_DIR/docs/changes/sessions/latest-change.yaml}"
AUTH_MODE="${2:-auto}"
TASK_BOARD="$ROOT_DIR/docs/goals/CURRENT_TASKS.yaml"

cleanup() {
  rm -f "$TMP_STATUS"
}
trap cleanup EXIT

cd "$ROOT_DIR"
git status --short --untracked-files=all > "$TMP_STATUS"

PASS=true
API_NEEDED=false
AUTH_RESULT=""
PROTECTION_RESULT=""
GOAL_RESULT=""
SCOPE_RESULT=""
CLEANUP_RESULT=""
TASK_RESULT=""
STRUCTURE_RESULT=""
API_RESULT="not-run"

run_check() {
  local label="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    printf '%s' "$output"
    return 0
  fi
  printf '%s' "$output"
  return 1
}

if AUTH_RESULT="$(run_check auth "$ROOT_DIR/tools/check_commit_authorization.sh" "$AUTH_MODE")"; then
  :
else
  PASS=false
fi

if PROTECTION_RESULT="$(run_check protection "$ROOT_DIR/tools/check_protection.sh" "$TMP_STATUS" "$CHANGE_INTENT")"; then
  :
else
  PASS=false
fi

if GOAL_RESULT="$(run_check goal "$ROOT_DIR/tools/check_goal.sh" "$ROOT_DIR/docs/goals/CURRENT_GOAL.yaml")"; then
  :
else
  PASS=false
fi

if TASK_RESULT="$(run_check tasks "$ROOT_DIR/tools/check_tasks.sh" "$TASK_BOARD" commit)"; then
  :
else
  PASS=false
fi

if SCOPE_RESULT="$(run_check scope "$ROOT_DIR/tools/check_scope.sh" "$CHANGE_INTENT" "$TMP_STATUS")"; then
  :
else
  PASS=false
fi

if CLEANUP_RESULT="$(run_check cleanup "$ROOT_DIR/tools/check_cleanup.sh" "$ROOT_DIR/docs/reports/cleanup-notes.md")"; then
  :
else
  PASS=false
fi

if STRUCTURE_RESULT="$(run_check structure "$ROOT_DIR/tools/check_structure_sync.sh" "$TMP_STATUS")"; then
  :
else
  PASS=false
fi

if grep -E '^[ MADRCU]+\s+(docs/api/|src/api/|src/routes/|src/controllers/|src/endpoints/)' "$TMP_STATUS" >/dev/null; then
  API_NEEDED=true
  if API_RESULT="$(run_check api "$ROOT_DIR/tools/check_api_change.sh" "$TMP_STATUS")"; then
    :
  else
    PASS=false
  fi
fi

{
  echo "# Commit Gate Report"
  echo
  echo "- Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "- Change intent: ${CHANGE_INTENT#$ROOT_DIR/}"
  echo "- Authorization mode: $AUTH_MODE"
  echo "- Overall result: $( $PASS && echo PASS || echo FAIL )"
  echo
  echo "## Checks"
  echo
  echo "- Authorization: $AUTH_RESULT"
  echo "- Protection: $PROTECTION_RESULT"
  echo "- Goal: $GOAL_RESULT"
  echo "- Tasks: $TASK_RESULT"
  echo "- Structure: $STRUCTURE_RESULT"
  echo "- Scope: $SCOPE_RESULT"
  echo "- Cleanup: $CLEANUP_RESULT"
  if $API_NEEDED; then
    echo "- API: $API_RESULT"
  else
    echo "- API: not-needed"
  fi
  echo
  echo "## Changed Files"
  if [[ -s "$TMP_STATUS" ]]; then
    sed 's/^/- /' "$TMP_STATUS"
  else
    echo "- none"
  fi
  echo
  echo "## Next Action"
  if $PASS; then
    echo "- Gate passed. You may proceed inside /proj-commit."
  else
    echo "- Gate failed. Resolve the reported issues, including unfinished tasks or checkpoints, before any commit."
  fi
} > "$REPORT"

$PASS
