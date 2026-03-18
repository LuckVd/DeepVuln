#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_STATUS="$(mktemp)"
REPORT_FILE="$ROOT_DIR/docs/reports/check-latest.md"
CHANGE_INTENT="${1:-$ROOT_DIR/docs/changes/sessions/latest-change.yaml}"
TASK_BOARD="$ROOT_DIR/docs/goals/CURRENT_TASKS.yaml"

cleanup() {
  rm -f "$TMP_STATUS"
}
trap cleanup EXIT

cd "$ROOT_DIR"
git status --short --untracked-files=all > "$TMP_STATUS"

PASS=true
API_NEEDED=false
PROTECTION_RESULT=""
GOAL_RESULT=""
SCOPE_RESULT=""
CLEANUP_RESULT=""
TASK_RESULT=""
STRUCTURE_RESULT=""
API_RESULT="not-run"
READY_STATE=true
MISSING_STATE=()

run_check() {
  local output
  if output="$("$@" 2>&1)"; then
    printf '%s' "$output"
    return 0
  fi
  printf '%s' "$output"
  return 1
}

if PROTECTION_RESULT="$(run_check "$ROOT_DIR/tools/check_protection.sh" "$TMP_STATUS" "$CHANGE_INTENT")"; then
  :
else
  PASS=false
fi

if GOAL_RESULT="$(run_check "$ROOT_DIR/tools/check_goal.sh" "$ROOT_DIR/docs/goals/CURRENT_GOAL.yaml")"; then
  :
else
  PASS=false
fi

if TASK_RESULT="$(run_check "$ROOT_DIR/tools/check_tasks.sh" "$TASK_BOARD" check)"; then
  :
else
  PASS=false
fi

if SCOPE_RESULT="$(run_check "$ROOT_DIR/tools/check_scope.sh" "$CHANGE_INTENT" "$TMP_STATUS")"; then
  :
else
  PASS=false
fi

if CLEANUP_RESULT="$(run_check "$ROOT_DIR/tools/check_cleanup.sh" "$ROOT_DIR/docs/reports/cleanup-notes.md")"; then
  :
else
  PASS=false
fi

if STRUCTURE_RESULT="$(run_check "$ROOT_DIR/tools/check_structure_sync.sh" "$TMP_STATUS")"; then
  :
else
  PASS=false
fi

if grep -E '^[ MADRCU]+\s+(docs/api/|src/api/|src/routes/|src/controllers/|src/endpoints/)' "$TMP_STATUS" >/dev/null; then
  API_NEEDED=true
  if API_RESULT="$(run_check "$ROOT_DIR/tools/check_api_change.sh" "$TMP_STATUS")"; then
    :
  else
    PASS=false
  fi
fi

for required in "$ROOT_DIR/.claude/project.yaml" "$ROOT_DIR/docs/goals/CURRENT_GOAL.yaml" "$TASK_BOARD" "$CHANGE_INTENT"; do
  if [[ ! -f "$required" ]]; then
    READY_STATE=false
    MISSING_STATE+=("${required#$ROOT_DIR/}")
  fi
done

{
  echo "# Check Report"
  echo
  echo "- Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "- Change intent: ${CHANGE_INTENT#$ROOT_DIR/}"
  echo "- Overall result: $( $PASS && echo PASS || echo FAIL )"
  echo
  echo "## Readiness"
  if $READY_STATE; then
    echo "- Project state is ready for proj-check"
  else
    echo "- Missing prerequisites:"
    printf '%s\n' "${MISSING_STATE[@]}" | sed 's/^/  - /'
  fi
  echo
  echo "## Review Summary"
  echo "- Goal match: $GOAL_RESULT"
  echo "- Task board: $TASK_RESULT"
  echo "- Structure sync: $STRUCTURE_RESULT"
  echo "- Protection: $PROTECTION_RESULT"
  echo "- Scope drift: $SCOPE_RESULT"
  echo "- Cleanup: $CLEANUP_RESULT"
  if $API_NEEDED; then
    echo "- API risk: $API_RESULT"
  else
    echo "- API risk: not-needed"
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
    echo "- Checks passed. Continue development or proceed to /proj-commit when ready."
  elif ! $READY_STATE; then
    echo "- Fill the missing prerequisites, then rerun /proj-check."
  else
    echo "- Resolve the failing checks or pending checkpoints before proceeding."
  fi
} > "$REPORT_FILE"

$PASS
