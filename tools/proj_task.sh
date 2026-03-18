#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/tools/lib/native_command_parse.sh"

if [[ $# -gt 0 && "$1" != --* ]]; then
  BRIEF="$(join_freeform_args "$@")"
  NORMALIZED="$(normalize_command_text "$BRIEF")"

  case "$NORMALIZED" in
    *列出*任务*|*查看*任务*|*任务列表*|list*)
      exec "$ROOT_DIR/tools/update_task.sh" --list
      ;;
  esac

  TASK_ID="$(extract_task_id_from_text "$NORMALIZED" || true)"
  STATUS="$(infer_task_status_from_text "$NORMALIZED" || true)"
  NOTE="$(extract_note_from_text "$BRIEF" || true)"
  UPDATED_BY="$(infer_updated_by_from_text "$NORMALIZED")"

  if [[ -z "$TASK_ID" || -z "$STATUS" ]]; then
    echo "Could not infer task action. Use examples like '/proj-task 开始 task-001' or '/proj-task 完成 ucp-001，备注 用户已确认'." >&2
    exit 1
  fi

  ARGS=(--id "$TASK_ID" --status "$STATUS" --by "$UPDATED_BY")
  if [[ -n "$NOTE" ]]; then
    ARGS+=(--note "$NOTE")
  fi
  exec "$ROOT_DIR/tools/update_task.sh" "${ARGS[@]}"
fi

exec "$ROOT_DIR/tools/update_task.sh" "$@"
