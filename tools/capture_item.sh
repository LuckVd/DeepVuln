#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INBOX_FILE="$ROOT_DIR/docs/goals/INBOX.yaml"
CURRENT_GOAL_FILE="$ROOT_DIR/docs/goals/CURRENT_GOAL.yaml"
CURRENT_TASKS_FILE="$ROOT_DIR/docs/goals/CURRENT_TASKS.yaml"

TYPE="followup"
TITLE=""
SOURCE="proj-capture"
PRIORITY="medium"
DECISION="schedule_later"
LINKED_GOAL=""
STATUS="open"

usage() {
  cat <<'EOF'
Usage:
  tools/proj_capture.sh --title <text> [options]

Options:
  --type <interrupt|bug|idea|followup>
  --title <text>
  --source <text>
  --priority <high|medium|low>
  --decision <do_now|schedule_later|ignore>
  --linked-goal <text>
  --status <open|closed>
  --help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type)
      TYPE="${2:-}"
      shift 2
      ;;
    --title)
      TITLE="${2:-}"
      shift 2
      ;;
    --source)
      SOURCE="${2:-}"
      shift 2
      ;;
    --priority)
      PRIORITY="${2:-}"
      shift 2
      ;;
    --decision)
      DECISION="${2:-}"
      shift 2
      ;;
    --linked-goal)
      LINKED_GOAL="${2:-}"
      shift 2
      ;;
    --status)
      STATUS="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$TITLE" ]]; then
  echo "Missing required option: --title" >&2
  exit 1
fi

case "$TYPE" in
  interrupt|bug|idea|followup) ;;
  *)
    echo "Invalid type: $TYPE" >&2
    exit 1
    ;;
esac

case "$PRIORITY" in
  high|medium|low) ;;
  *)
    echo "Invalid priority: $PRIORITY" >&2
    exit 1
    ;;
esac

case "$DECISION" in
  do_now|schedule_later|ignore) ;;
  *)
    echo "Invalid decision: $DECISION" >&2
    exit 1
    ;;
esac

case "$STATUS" in
  open|closed) ;;
  *)
    echo "Invalid status: $STATUS" >&2
    exit 1
    ;;
esac

mkdir -p "$(dirname "$INBOX_FILE")"

if [[ ! -f "$INBOX_FILE" ]]; then
  cat > "$INBOX_FILE" <<'EOF'
items:
EOF
fi

STAMP="$(date +%Y%m%d%H%M%S)"
ITEM_ID="inbox-$STAMP"

if [[ -z "$LINKED_GOAL" && -f "$ROOT_DIR/docs/goals/CURRENT_GOAL.yaml" ]]; then
  LINKED_GOAL="$(sed -n 's/^  title: "\(.*\)"/\1/p' "$ROOT_DIR/docs/goals/CURRENT_GOAL.yaml" | head -n 1)"
fi

{
  echo "  - id: $ITEM_ID"
  echo "    type: $TYPE"
  echo "    title: \"$TITLE\""
  echo "    source: $SOURCE"
  echo "    priority: $PRIORITY"
  echo "    decision: $DECISION"
  echo "    linked_goal: \"${LINKED_GOAL}\""
  echo "    status: $STATUS"
} >> "$INBOX_FILE"

if [[ "$TYPE" == "interrupt" && "$DECISION" == "do_now" && -f "$CURRENT_GOAL_FILE" ]]; then
  sed -i 's/^  status: .*/  status: interrupted/' "$CURRENT_GOAL_FILE"
  echo "Current goal status updated to interrupted"
fi

if [[ "$DECISION" == "do_now" && -f "$CURRENT_TASKS_FILE" ]]; then
  TMP_TASKS="$(mktemp)"
  awk '
    /^task_board:/ { print; next }
    /^  updated_at:/ {
      print "  updated_at: \"" strftime("%Y-%m-%d %H:%M:%S %Z") "\""
      next
    }
    { print }
  ' "$CURRENT_TASKS_FILE" > "$TMP_TASKS"
  mv "$TMP_TASKS" "$CURRENT_TASKS_FILE"
fi

echo "Captured inbox item: $ITEM_ID"
echo "Type: $TYPE"
echo "Decision: $DECISION"
