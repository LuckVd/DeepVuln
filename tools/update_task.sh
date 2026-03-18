#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TASK_FILE="$ROOT_DIR/docs/goals/CURRENT_TASKS.yaml"

TASK_ID=""
STATUS=""
NOTE=""
UPDATED_BY="user"
LIST_ONLY="no"

usage() {
  cat <<'EOF'
Usage:
  tools/proj_task.sh --list
  tools/proj_task.sh --id <task-id> --status <todo|in_progress|blocked|done> [options]

Options:
  --list
  --id <task-id>
  --status <todo|in_progress|blocked|done>
  --note <text>
  --by <user|ai|shared>
  --help
EOF
}

list_tasks() {
  awk '
    /^    - id: / {
      if (id != "") {
        print "- " id " | " title " | " type " | " status " | " stage_gate
      }
      id=$3
      title=""
      type=""
      status=""
      stage_gate=""
      next
    }
    /^      title: / {
      title=$0
      sub(/^      title: "/, "", title)
      sub(/"$/, "", title)
      next
    }
    /^      type: / { type=$2; next }
    /^      status: / { status=$2; next }
    /^      stage_gate: / { stage_gate=$2; next }
    END {
      if (id != "") {
        print "- " id " | " title " | " type " | " status " | " stage_gate
      }
    }
  ' "$TASK_FILE"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) LIST_ONLY="yes"; shift ;;
    --id) TASK_ID="${2:-}"; shift 2 ;;
    --status) STATUS="${2:-}"; shift 2 ;;
    --note) NOTE="${2:-}"; shift 2 ;;
    --by) UPDATED_BY="${2:-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ! -f "$TASK_FILE" ]]; then
  echo "Task file not found: $TASK_FILE" >&2
  exit 1
fi

if [[ "$LIST_ONLY" == "yes" ]]; then
  echo "# Current Tasks"
  echo
  echo "- id | title | type | status | gate"
  list_tasks
  exit 0
fi

if [[ -z "$TASK_ID" || -z "$STATUS" ]]; then
  echo "Missing required options: --id and --status" >&2
  exit 1
fi

case "$STATUS" in
  todo|in_progress|blocked|done) ;;
  *)
    echo "Invalid status: $STATUS" >&2
    exit 1
    ;;
esac

case "$UPDATED_BY" in
  user|ai|shared) ;;
  *)
    echo "Invalid updater: $UPDATED_BY" >&2
    exit 1
    ;;
esac

TMP_FILE="$(mktemp)"
UPDATED_AT="$(date '+%Y-%m-%d %H:%M:%S %Z')"

awk -v task_id="$TASK_ID" -v new_status="$STATUS" -v note="$NOTE" -v updated_at="$UPDATED_AT" -v updated_by="$UPDATED_BY" '
  BEGIN {
    found=0
    in_target=0
    note_written=0
    audit_written=0
  }
  /^  updated_at: / {
    print "  updated_at: \"" updated_at "\""
    next
  }
  /^    - id: / {
    if (in_target) {
      if (note != "" && !note_written) {
        print "      status_note: \"" note "\""
      }
      if (!audit_written) {
        print "      status_updated_at: \"" updated_at "\""
        print "      status_updated_by: " updated_by
      }
    }
    current_id=$3
    in_target=(current_id == task_id)
    if (in_target) {
      found=1
      note_written=0
      audit_written=0
    }
    print
    next
  }
  in_target && /^      status: / {
    print "      status: " new_status
    if (note != "") {
      print "      status_note: \"" note "\""
      note_written=1
    }
    print "      status_updated_at: \"" updated_at "\""
    print "      status_updated_by: " updated_by
    audit_written=1
    next
  }
  in_target && /^      status_note: / {
    if (note == "") {
      print
    }
    next
  }
  in_target && /^      status_updated_at: / { next }
  in_target && /^      status_updated_by: / { next }
  {
    print
  }
  END {
    if (in_target) {
      if (note != "" && !note_written) {
        print "      status_note: \"" note "\""
      }
      if (!audit_written) {
        print "      status_updated_at: \"" updated_at "\""
        print "      status_updated_by: " updated_by
      }
    }
    if (!found) {
      exit 5
    }
  }
' "$TASK_FILE" > "$TMP_FILE" || {
  rm -f "$TMP_FILE"
  echo "Task update failed: task id not found: $TASK_ID" >&2
  exit 1
}

mv "$TMP_FILE" "$TASK_FILE"

echo "Updated task: $TASK_ID"
echo "Status: $STATUS"
echo "Updated by: $UPDATED_BY"
if [[ -n "$NOTE" ]]; then
  echo "Note: $NOTE"
fi
