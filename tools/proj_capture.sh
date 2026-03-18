#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/tools/lib/native_command_parse.sh"

if [[ $# -gt 0 && "$1" == --* ]]; then
  exec "$ROOT_DIR/tools/capture_item.sh" "$@"
fi

BRIEF="$(join_freeform_args "$@")"
if [[ -z "$BRIEF" ]]; then
  exec "$ROOT_DIR/tools/capture_item.sh" "$@"
fi

TITLE="$(infer_title_from_text "$BRIEF")"
TYPE="$(infer_capture_type "$BRIEF")"
PRIORITY="$(infer_priority "$BRIEF")"
DECISION="$(infer_decision "$BRIEF")"

exec "$ROOT_DIR/tools/capture_item.sh" \
  --title "$TITLE" \
  --type "$TYPE" \
  --priority "$PRIORITY" \
  --decision "$DECISION" \
  --source "proj-capture:native"
