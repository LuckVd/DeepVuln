#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/tools/lib/native_command_parse.sh"

if [[ $# -gt 0 && "$1" == --* ]]; then
  exec "$ROOT_DIR/tools/plan_current.sh" "$@"
fi

BRIEF="$(join_freeform_args "$@")"
if [[ -z "$BRIEF" ]]; then
  exec "$ROOT_DIR/tools/plan_current.sh" "$@"
fi

TITLE="$(infer_title_from_text "$BRIEF")"
OBJECTIVE="$(normalize_text_line "$BRIEF")"
WORK_TYPE="$(infer_work_type "$BRIEF")"
MODE="new"

if [[ "$BRIEF" == *调整* || "$BRIEF" == *adjust* || "$BRIEF" == *继续优化* ]]; then
  MODE="adjust"
fi

TASK_ARGS=()
CHECKPOINT_ARGS=()
USER_CHECKPOINT_ARGS=()

while IFS= read -r sentence; do
  [[ -z "$sentence" ]] && continue
  if infer_user_checkpoint_sentence "$sentence"; then
    USER_CHECKPOINT_ARGS+=(--user-checkpoint "$sentence")
  elif infer_checkpoint_sentence "$sentence"; then
    CHECKPOINT_ARGS+=(--checkpoint "$sentence")
  else
    TASK_ARGS+=(--task "$sentence")
  fi
done < <(split_sentences "$BRIEF")

if [[ ${#TASK_ARGS[@]} -eq 0 ]]; then
  TASK_ARGS+=(--task "$TITLE")
fi

exec "$ROOT_DIR/tools/plan_current.sh" \
  --mode "$MODE" \
  --title "$TITLE" \
  --objective "$OBJECTIVE" \
  --work-type "$WORK_TYPE" \
  "${TASK_ARGS[@]}" \
  "${CHECKPOINT_ARGS[@]}" \
  "${USER_CHECKPOINT_ARGS[@]}"
