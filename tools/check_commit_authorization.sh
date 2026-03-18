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

# 查找所有 before_commit 类型的检查点
AUTH_STATUS="$(awk '
  /^    - id: ccp-/ { in_target=1; ccp_id=$3; next }
  /^    - id: / && in_target { in_target=0 }
  in_target && /^      stage_gate: before_commit/ { is_commit_checkpoint=1; next }
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
  in_target && /^    - id:/ || /^$/ {
    if (is_commit_checkpoint) {
      results[ccp_id] = status "|" owner "|" updated_by
      is_commit_checkpoint=0
    }
    in_target=0
  }
  END {
    # 检查所有 commit checkpoint
    all_done=1
    user_confirmed=1
    for (id in results) {
      split(results[id], parts, "|")
      s=parts[1]
      o=parts[2]
      u=parts[3]
      if (s != "done") {
        all_done=0
        print id ":pending"
      } else if (u != "user" && u != "shared") {
        user_confirmed=0
      }
    }
    if (all_done && user_confirmed) {
      print "approved"
    } else if (all_done) {
      print "done_without_user_confirmation"
    }
  }
' "$TASK_FILE")"

case "$AUTH_STATUS" in
  approved)
    echo "Commit authorization: approved via commit checkpoints"
    exit 0
    ;;
  done_without_user_confirmation)
    echo "Commit authorization: denied (commit checkpoint is done but not confirmed by user/shared)"
    exit 1
    ;;
  *pending*)
    echo "Commit authorization: denied (commit checkpoint is not yet user-confirmed)"
    exit 1
    ;;
  *)
    echo "Commit authorization: denied (no valid commit checkpoint found)"
    exit 1
    ;;
esac
