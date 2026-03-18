#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/tools/lib/native_command_parse.sh"

if [[ $# -gt 0 && "$1" == --* ]]; then
  exec "$ROOT_DIR/tools/init_workspace.sh" "$@"
fi

BRIEF="$(join_freeform_args "$@")"
if [[ -z "$BRIEF" ]]; then
  exec "$ROOT_DIR/tools/init_workspace.sh" "$@"
fi

TMP_BRIEF="$(mktemp)"
trap 'rm -f "$TMP_BRIEF"' EXIT
build_init_brief_from_text "$BRIEF" "$TMP_BRIEF"

exec "$ROOT_DIR/tools/init_workspace.sh" --source "$TMP_BRIEF"
