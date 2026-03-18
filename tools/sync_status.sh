#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CURRENT_GOAL_FILE="$ROOT_DIR/docs/goals/CURRENT_GOAL.yaml"
GOAL_HISTORY_FILE="$ROOT_DIR/docs/goals/GOAL_HISTORY.md"
COMMIT_HISTORY_FILE="$ROOT_DIR/docs/history/COMMIT_HISTORY.md"
INBOX_FILE="$ROOT_DIR/docs/goals/INBOX.yaml"

GOAL_STATUS=""
GOAL_NOTE=""
COMMIT_ID=""
COMMIT_SUMMARY=""
RESOLVE_INBOX_IDS=()

usage() {
  cat <<'EOF'
Usage:
  tools/sync_status.sh [options]

Options:
  --goal-status <in_progress|blocked|interrupted|completed>
  --goal-note <text>
  --commit-id <short-id>
  --commit-summary <text>
  --resolve-inbox <id>     Repeatable
  --help

Notes:
  - goal history is appended when --goal-status is provided
  - commit history is appended when --commit-id and --commit-summary are provided
  - resolved inbox items are marked closed
EOF
}

close_inbox_item() {
  local item_id="$1"
  local tmp
  tmp="$(mktemp)"
  awk -v target="$item_id" '
    /^  - id: / {
      in_target = ($3 == target)
    }
    {
      if (in_target && $1 == "status:") {
        print "    status: closed"
      } else {
        print
      }
    }
  ' "$INBOX_FILE" > "$tmp"
  mv "$tmp" "$INBOX_FILE"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --goal-status)
      GOAL_STATUS="${2:-}"
      shift 2
      ;;
    --goal-note)
      GOAL_NOTE="${2:-}"
      shift 2
      ;;
    --commit-id)
      COMMIT_ID="${2:-}"
      shift 2
      ;;
    --commit-summary)
      COMMIT_SUMMARY="${2:-}"
      shift 2
      ;;
    --resolve-inbox)
      RESOLVE_INBOX_IDS+=("${2:-}")
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

TODAY="$(date +%F)"
NOW="$(date '+%Y-%m-%d %H:%M')"

if [[ -n "$GOAL_STATUS" ]]; then
  if [[ -f "$CURRENT_GOAL_FILE" ]]; then
    sed -i "s/^  status: .*/  status: $GOAL_STATUS/" "$CURRENT_GOAL_FILE"
    GOAL_TITLE="$(sed -n 's/^  title: "\(.*\)"/\1/p' "$CURRENT_GOAL_FILE" | head -n 1)"
  else
    GOAL_TITLE="(missing current goal)"
  fi
  if [[ -z "$GOAL_NOTE" ]]; then
    GOAL_NOTE="Updated by sync_status.sh"
  fi
  printf '| %s | %s | %s | %s |\n' "$TODAY" "$GOAL_TITLE" "$GOAL_STATUS" "$GOAL_NOTE" >> "$GOAL_HISTORY_FILE"
fi

if [[ -n "$COMMIT_ID" || -n "$COMMIT_SUMMARY" ]]; then
  if [[ -z "$COMMIT_ID" || -z "$COMMIT_SUMMARY" ]]; then
    echo "Both --commit-id and --commit-summary are required together" >&2
    exit 1
  fi
  if grep -q '| - | - | No commits recorded in the rebuilt workspace yet |' "$COMMIT_HISTORY_FILE"; then
    tmp="$(mktemp)"
    grep -v '| - | - | No commits recorded in the rebuilt workspace yet |' "$COMMIT_HISTORY_FILE" > "$tmp"
    mv "$tmp" "$COMMIT_HISTORY_FILE"
  fi
  printf '| %s | %s | %s |\n' "$NOW" "$COMMIT_ID" "$COMMIT_SUMMARY" >> "$COMMIT_HISTORY_FILE"
fi

if [[ -f "$INBOX_FILE" && ${#RESOLVE_INBOX_IDS[@]} -gt 0 ]]; then
  for item_id in "${RESOLVE_INBOX_IDS[@]}"; do
    close_inbox_item "$item_id"
  done
fi

echo "Sync complete"
if [[ -n "$GOAL_STATUS" ]]; then
  echo "- Goal status updated: $GOAL_STATUS"
fi
if [[ -n "$COMMIT_ID" ]]; then
  echo "- Commit history appended: $COMMIT_ID"
fi
if [[ ${#RESOLVE_INBOX_IDS[@]} -gt 0 ]]; then
  echo "- Closed inbox items: ${RESOLVE_INBOX_IDS[*]}"
fi
