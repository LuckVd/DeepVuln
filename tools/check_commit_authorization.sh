#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-auto}"
TASK_FILE="$ROOT_DIR/docs/goals/CURRENT_TASKS.yaml"

if [[ "$MODE" == "approved" ]]; then
  echo "Commit authorization: approved"
  exit 0
fi

if [[ "$MODE" == "denied" ]]; then
  echo "Commit authorization: denied"
  exit 1
fi

if [[ ! -f "$TASK_FILE" ]]; then
  echo "Commit authorization: denied (missing task board)"
  exit 1
fi

AUTH_STATUS="$(awk '
  /^    - id: ccp-001/ { in_target=1; next }
  /^    - id: / && in_target { exit }
  in_target && /^      owner: / {
    owner=$2
    next
  }
  in_target && /^      status: / {
    status=$2
    next
  }
  in_target && /^      status_updated_by: / {
    updated_by=$2
    next
  }
  END {
    if (status == "done" && (updated_by == "user" || updated_by == "shared")) {
      print "approved"
    } else if (status == "done" && owner == "user" && updated_by == "") {
      print "approved_legacy_user_owner"
    } else if (status == "done") {
      print "done_without_user_confirmation"
    } else {
      print "pending"
    }
  }
' "$TASK_FILE")"

case "$AUTH_STATUS" in
  approved)
    echo "Commit authorization: approved via ccp-001"
    exit 0
    ;;
  approved_legacy_user_owner)
    echo "Commit authorization: approved via ccp-001 legacy user-owned done state"
    exit 0
    ;;
  done_without_user_confirmation)
    echo "Commit authorization: denied (ccp-001 is done but not confirmed by user/shared)"
    exit 1
    ;;
  *)
    echo "Commit authorization: denied (ccp-001 is not yet user-confirmed)"
    exit 1
    ;;
esac
