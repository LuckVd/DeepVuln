#!/usr/bin/env bash
set -euo pipefail

TASK_FILE="${1:-}"
MODE="${2:-check}"

if [[ -z "$TASK_FILE" ]]; then
  echo "Usage: tools/check_tasks.sh <task-file> [check|commit]"
  exit 1
fi

if [[ ! -f "$TASK_FILE" ]]; then
  echo "Task check failed: missing task board $TASK_FILE"
  exit 1
fi

if [[ "$MODE" != "check" && "$MODE" != "commit" ]]; then
  echo "Task check failed: invalid mode $MODE"
  exit 1
fi

SUMMARY="$(awk -v mode="$MODE" '
  /^    - id: / {
    item_count++
    item_type=""
    item_status=""
    item_gate=""
  }
  /^      type: / { item_type=$2 }
  /^      status: / { item_status=$2 }
  /^      stage_gate: / {
    item_gate=$2
    if (item_status == "blocked") {
      blocked++
    }
    if (item_type == "checkpoint" && item_gate == "before_check" && item_status != "done") {
      pending_before_check++
    }
    if (item_type == "checkpoint" && item_gate == "before_commit" && item_status != "done") {
      pending_before_commit++
    }
    # commit 模式下只检查 checkpoint，不检查普通 task
    if (mode == "commit" && item_type == "checkpoint" && item_status != "done") {
      open_items++
    }
  }
  END {
    printf "%d %d %d %d %d\n", item_count, blocked, pending_before_check, pending_before_commit, open_items
  }
' "$TASK_FILE")"

read -r item_count blocked pending_before_check pending_before_commit open_items <<<"$SUMMARY"

if [[ "$item_count" -eq 0 ]]; then
  echo "Task check failed: task board is empty"
  exit 1
fi

if [[ "$blocked" -gt 0 ]]; then
  echo "Task check failed: blocked work remains on the task board"
  exit 2
fi

if [[ "$MODE" == "check" && "$pending_before_check" -gt 0 ]]; then
  echo "Task check failed: before_check checkpoints are still pending"
  exit 3
fi

if [[ "$MODE" == "commit" && "$open_items" -gt 0 ]]; then
  echo "Task check failed: unfinished tasks or checkpoints remain"
  exit 4
fi

if [[ "$MODE" == "commit" && "$pending_before_commit" -gt 0 ]]; then
  echo "Task check failed: before_commit checkpoints are still pending"
  exit 5
fi

echo "Task check passed"
