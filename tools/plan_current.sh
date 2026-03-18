#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CURRENT_GOAL_FILE="$ROOT_DIR/docs/goals/CURRENT_GOAL.yaml"
CURRENT_TASKS_FILE="$ROOT_DIR/docs/goals/CURRENT_TASKS.yaml"
INBOX_FILE="$ROOT_DIR/docs/goals/INBOX.yaml"
ROADMAP_FILE="$ROOT_DIR/docs/roadmap/ROADMAP.md"
ARCHIVE_DIR="$ROOT_DIR/docs/history/plan-archives"
REPORT_FILE="$ROOT_DIR/docs/reports/plan-current-latest.md"

MODE="new"
TITLE=""
PRIORITY="high"
OBJECTIVE=""
PHASE="Phase 1"
WORK_TYPE="code"
SYNC_ROADMAP="no"
ROADMAP_FOCUS=""
ACCEPTANCE_ITEMS=()
IN_SCOPE_ITEMS=()
OUT_OF_SCOPE_ITEMS=()
IMPACTED_MODULES=()
TASK_ITEMS=()
CHECKPOINT_ITEMS=()
USER_CHECKPOINT_ITEMS=()
ARCHIVED_FILES=()
ASSUMPTIONS=()
UNCERTAINTIES=()
RESOLVED_INBOX_IDS=()
REQUIRED_SYNC_DOCS=()

usage() {
  cat <<'EOF'
Usage:
  tools/proj_plan.sh --title <goal-title> --objective <text> [options]

Options:
  --mode <new|adjust>
  --title <goal-title>
  --priority <high|medium|low>
  --objective <text>
  --phase <phase-name>
  --work-type <code|api|schema|doc|refactor>
  --acceptance <text>          Repeatable
  --in-scope <text>            Repeatable
  --out-of-scope <text>        Repeatable
  --impact <module>            Repeatable
  --task <text>                Repeatable
  --checkpoint <text>          Repeatable
  --user-checkpoint <text>     Repeatable
  --resolve-inbox <id>         Repeatable
  --sync-roadmap <yes|no>
  --roadmap-focus <text>
  --help
EOF
}

archive_file() {
  local src="$1"
  if [[ -f "$src" ]]; then
    mkdir -p "$ARCHIVE_DIR"
    local stamp base target
    stamp="$(date +%Y%m%d-%H%M%S)"
    base="$(basename "$src")"
    target="$ARCHIVE_DIR/$stamp-$base"
    cp "$src" "$target"
    ARCHIVED_FILES+=("$target")
  fi
}

close_inbox_item() {
  local item_id="$1"
  local tmp
  tmp="$(mktemp)"
  awk -v target="$item_id" '
    /^  - id: / { in_target = ($3 == target) }
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

write_task_item() {
  local id="$1"
  local title="$2"
  local type="$3"
  local owner="$4"
  local status="$5"
  local stage_gate="$6"
  local work_type="$7"
  local done_definition="$8"
  shift 8
  local required_docs=("$@")

  echo "    - id: $id"
  echo "      title: \"$title\""
  echo "      type: $type"
  echo "      owner: $owner"
  echo "      status: $status"
  echo "      stage_gate: $stage_gate"
  echo "      work_type: $work_type"
  echo "      goal_link: \"$TITLE\""
  echo "      done_definition: \"$done_definition\""
  echo "      required_sync_docs:"
  if [[ ${#required_docs[@]} -eq 0 ]]; then
    echo "        - none"
  else
    local doc
    for doc in "${required_docs[@]}"; do
      echo "        - $doc"
    done
  fi
}

infer_required_sync_docs() {
  case "$1" in
    api)
      printf '%s\n' "docs/api/API.md" "docs/context/apis/**" "docs/context/files/**"
      ;;
    schema)
      printf '%s\n' "docs/context/models/**" "docs/context/files/**"
      ;;
    doc)
      printf '%s\n' "docs/context/structure/**"
      ;;
    refactor)
      printf '%s\n' "docs/context/functions/**" "docs/context/files/**"
      ;;
    *)
      printf '%s\n' "docs/context/files/**"
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --title) TITLE="${2:-}"; shift 2 ;;
    --priority) PRIORITY="${2:-}"; shift 2 ;;
    --objective) OBJECTIVE="${2:-}"; shift 2 ;;
    --phase) PHASE="${2:-}"; shift 2 ;;
    --work-type) WORK_TYPE="${2:-}"; shift 2 ;;
    --acceptance) ACCEPTANCE_ITEMS+=("${2:-}"); shift 2 ;;
    --in-scope) IN_SCOPE_ITEMS+=("${2:-}"); shift 2 ;;
    --out-of-scope) OUT_OF_SCOPE_ITEMS+=("${2:-}"); shift 2 ;;
    --impact) IMPACTED_MODULES+=("${2:-}"); shift 2 ;;
    --task) TASK_ITEMS+=("${2:-}"); shift 2 ;;
    --checkpoint) CHECKPOINT_ITEMS+=("${2:-}"); shift 2 ;;
    --user-checkpoint) USER_CHECKPOINT_ITEMS+=("${2:-}"); shift 2 ;;
    --resolve-inbox) RESOLVED_INBOX_IDS+=("${2:-}"); shift 2 ;;
    --sync-roadmap) SYNC_ROADMAP="${2:-}"; shift 2 ;;
    --roadmap-focus) ROADMAP_FOCUS="${2:-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ "$MODE" != "new" && "$MODE" != "adjust" ]]; then
  echo "Invalid mode: $MODE" >&2
  exit 1
fi

if [[ -z "$TITLE" || -z "$OBJECTIVE" ]]; then
  echo "Missing required options: --title and --objective" >&2
  exit 1
fi

case "$WORK_TYPE" in
  code|api|schema|doc|refactor) ;;
  *)
    echo "Invalid work type: $WORK_TYPE" >&2
    exit 1
    ;;
esac

if [[ ${#ACCEPTANCE_ITEMS[@]} -eq 0 ]]; then
  ACCEPTANCE_ITEMS=("Primary acceptance criteria confirmed for $TITLE")
  ASSUMPTIONS+=("Acceptance criteria defaulted to a single implementation-safe statement.")
fi

if [[ ${#IN_SCOPE_ITEMS[@]} -eq 0 ]]; then
  IN_SCOPE_ITEMS=("Current implementation slice for $TITLE")
  ASSUMPTIONS+=("In-scope defaults to the current implementation slice.")
fi

if [[ ${#OUT_OF_SCOPE_ITEMS[@]} -eq 0 ]]; then
  OUT_OF_SCOPE_ITEMS=("Unconfirmed follow-up work")
  ASSUMPTIONS+=("Unconfirmed follow-up work stays out of scope.")
fi

if [[ ${#IMPACTED_MODULES[@]} -eq 0 ]]; then
  IMPACTED_MODULES=("planning-state")
  ASSUMPTIONS+=("Impacted modules default to planning-state when not provided.")
fi

if [[ ${#TASK_ITEMS[@]} -eq 0 ]]; then
  TASK_ITEMS=(
    "Break the current implementation into one validated slice"
    "Implement and verify the accepted slice"
  )
  ASSUMPTIONS+=("Task board was seeded with a default two-step execution path.")
fi

if [[ ${#CHECKPOINT_ITEMS[@]} -eq 0 && ${#USER_CHECKPOINT_ITEMS[@]} -eq 0 ]]; then
  USER_CHECKPOINT_ITEMS=("Confirm scope and acceptance criteria")
  ASSUMPTIONS+=("A user checkpoint was added to preserve an explicit intervention point.")
fi

if [[ "$MODE" == "adjust" ]]; then
  archive_file "$CURRENT_GOAL_FILE"
  archive_file "$CURRENT_TASKS_FILE"
  if [[ "$SYNC_ROADMAP" == "yes" ]]; then
    archive_file "$ROADMAP_FILE"
  fi
fi

TODAY="$(date +%F)"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S %Z')"
TASK_BOARD_PATH="docs/goals/CURRENT_TASKS.yaml"
DECISION_POINTS=()
mapfile -t REQUIRED_SYNC_DOCS < <(infer_required_sync_docs "$WORK_TYPE")

{
  echo "task_board:"
  echo "  goal_title: \"$TITLE\""
  echo "  linked_phase: \"$PHASE\""
  echo "  updated_at: \"$TIMESTAMP\""
  echo "  items:"

  task_idx=1
  for item in "${TASK_ITEMS[@]}"; do
    id="$(printf 'task-%03d' "$task_idx")"
    write_task_item "$id" "$item" "task" "ai" "todo" "anytime" "$WORK_TYPE" "Implementation evidence exists for: $item" "${REQUIRED_SYNC_DOCS[@]}"
    task_idx=$((task_idx + 1))
  done

  checkpoint_idx=1
  for item in "${CHECKPOINT_ITEMS[@]}"; do
    id="$(printf 'cp-%03d' "$checkpoint_idx")"
    DECISION_POINTS+=("$id")
    write_task_item "$id" "$item" "checkpoint" "shared" "todo" "before_check" "doc" "Checkpoint confirmed for: $item" "docs/context/structure/README.md"
    checkpoint_idx=$((checkpoint_idx + 1))
  done

  user_idx=1
  for item in "${USER_CHECKPOINT_ITEMS[@]}"; do
    id="$(printf 'ucp-%03d' "$user_idx")"
    DECISION_POINTS+=("$id")
    write_task_item "$id" "$item" "checkpoint" "user" "todo" "before_check" "doc" "User confirmation recorded for: $item" "docs/context/structure/README.md"
    user_idx=$((user_idx + 1))
  done

  id="ccp-001"
  DECISION_POINTS+=("$id")
  write_task_item "$id" "Approve readiness to commit" "checkpoint" "user" "todo" "before_commit" "doc" "User explicitly approves the commit gate outcome" "docs/context/structure/README.md"
} > "$CURRENT_TASKS_FILE"

{
  echo "goal:"
  echo "  title: \"$TITLE\""
  echo "  status: in_progress"
  echo "  priority: \"$PRIORITY\""
  echo "  objective: \"$OBJECTIVE\""
  echo "  linked_phase: \"$PHASE\""
  echo "  task_board: \"$TASK_BOARD_PATH\""
  echo "  work_type: \"$WORK_TYPE\""
  echo "  decision_points:"
  for item in "${DECISION_POINTS[@]}"; do
    echo "    - $item"
  done
  echo "  acceptance_criteria:"
  for item in "${ACCEPTANCE_ITEMS[@]}"; do
    echo "    - $item"
  done
  echo "  in_scope:"
  for item in "${IN_SCOPE_ITEMS[@]}"; do
    echo "    - $item"
  done
  echo "  out_of_scope:"
  for item in "${OUT_OF_SCOPE_ITEMS[@]}"; do
    echo "    - $item"
  done
  echo "  impacted_modules:"
  for item in "${IMPACTED_MODULES[@]}"; do
    echo "    - $item"
  done
  echo "  required_sync_docs:"
  for item in "${REQUIRED_SYNC_DOCS[@]}"; do
    echo "    - $item"
  done
  echo "  required_checks:"
  echo "    - constitution"
  echo "    - protection"
  echo "    - scope"
  echo "    - goal"
  echo "    - tasks"
  echo "  notes:"
  echo "    - Planned by /proj-plan on $TODAY"
  echo "    - Mode: $MODE"
} > "$CURRENT_GOAL_FILE"

if [[ "$SYNC_ROADMAP" == "yes" ]]; then
  if [[ -z "$ROADMAP_FOCUS" ]]; then
    ROADMAP_FOCUS="$TITLE"
    ASSUMPTIONS+=("Roadmap focus defaults to the goal title when not provided.")
  fi
  {
    echo "# Roadmap"
    echo
    echo "## Phase Overview"
    echo
    echo "| Phase | Goal | Status |"
    echo "|---|---|---|"
    echo "| $PHASE | $TITLE | in_progress |"
    echo "| Phase 2 | Follow-up work after current goal | todo |"
    echo
    echo "## Current Focus"
    echo
    echo "- $ROADMAP_FOCUS"
  } > "$ROADMAP_FILE"
fi

if [[ -f "$INBOX_FILE" && ${#RESOLVED_INBOX_IDS[@]} -gt 0 ]]; then
  for item_id in "${RESOLVED_INBOX_IDS[@]}"; do
    close_inbox_item "$item_id"
  done
fi

{
  echo "# Plan Current Report"
  echo
  echo "- Timestamp: $TIMESTAMP"
  echo "- Mode: $MODE"
  echo "- Goal title: $TITLE"
  echo "- Objective: $OBJECTIVE"
  echo "- Linked phase: $PHASE"
  echo "- Work type: $WORK_TYPE"
  echo "- Roadmap sync: $SYNC_ROADMAP"
  echo "- Required sync docs: ${REQUIRED_SYNC_DOCS[*]}"
  if [[ ${#RESOLVED_INBOX_IDS[@]} -eq 0 ]]; then
    echo "- Resolved inbox items: none"
  else
    echo "- Resolved inbox items: ${RESOLVED_INBOX_IDS[*]}"
  fi
  echo
  echo "## Checkpoints"
  for item in "${CHECKPOINT_ITEMS[@]}"; do
    echo "- shared: $item"
  done
  for item in "${USER_CHECKPOINT_ITEMS[@]}"; do
    echo "- user: $item"
  done
  echo "- user: Approve readiness to commit"
  echo
  echo "## Archived Files"
  if [[ ${#ARCHIVED_FILES[@]} -eq 0 ]]; then
    echo "- none"
  else
    for item in "${ARCHIVED_FILES[@]}"; do
      echo "- $item"
    done
  fi
  echo
  echo "## Assumptions"
  if [[ ${#ASSUMPTIONS[@]} -eq 0 ]]; then
    echo "- none"
  else
    for item in "${ASSUMPTIONS[@]}"; do
      echo "- $item"
    done
  fi
  echo
  echo "## Uncertainties"
  if [[ ${#UNCERTAINTIES[@]} -eq 0 ]]; then
    echo "- none"
  else
    for item in "${UNCERTAINTIES[@]}"; do
      echo "- $item"
    done
  fi
} > "$REPORT_FILE"

echo "Planned current goal in $MODE mode"
echo "Goal: $TITLE"
echo "Task board: $TASK_BOARD_PATH"
