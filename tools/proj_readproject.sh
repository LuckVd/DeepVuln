#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/tools/lib/project_state.sh"
source "$ROOT_DIR/tools/lib/structure_sync.sh"
source "$ROOT_DIR/tools/lib/native_command_parse.sh"

MODE="snapshot"

if [[ $# -gt 0 && "$1" != --* ]]; then
  BRIEF="$(join_freeform_args "$@")"
  MODE="$(infer_read_mode_from_text "$BRIEF")"
  set --
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)
      MODE="full"
      shift
      ;;
    --snapshot)
      MODE="snapshot"
      shift
      ;;
    --help|-h)
      cat <<'EOF'
Usage:
  tools/proj_readproject.sh
  tools/proj_readproject.sh --full
  tools/proj_readproject.sh 看完整上下文

Default output is a short execution snapshot. Use --full for the complete
project context view.
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

TMP_STATUS="$(mktemp)"
trap 'rm -f "$TMP_STATUS"' EXIT
(
  cd "$ROOT_DIR"
  git status --short --untracked-files=all > "$TMP_STATUS"
)

goal_title=""
goal_status=""
goal_priority=""
goal_objective=""
project_name=""
project_type=""
primary_language=""
open_inbox_count=0
high_inbox_count=0
do_now_count=0
phase_title=""
missing_items=()
next_actions=()

if [[ -f "$PROJECT_FILE" ]]; then
  project_name="$(yaml_scalar "$PROJECT_FILE" "name")"
  project_type="$(yaml_scalar "$PROJECT_FILE" "type")"
  primary_language="$(yaml_scalar "$PROJECT_FILE" "primary_language")"
else
  missing_items+=(".claude/project.yaml")
fi

if [[ -f "$CURRENT_GOAL_FILE" ]]; then
  goal_title="$(yaml_scalar "$CURRENT_GOAL_FILE" "title")"
  goal_status="$(yaml_scalar "$CURRENT_GOAL_FILE" "status")"
  goal_priority="$(yaml_scalar "$CURRENT_GOAL_FILE" "priority")"
  goal_objective="$(yaml_scalar "$CURRENT_GOAL_FILE" "objective")"
else
  missing_items+=("docs/goals/CURRENT_GOAL.yaml")
fi

if [[ ! -f "$CURRENT_TASKS_FILE" ]]; then
  missing_items+=("docs/goals/CURRENT_TASKS.yaml")
fi

if [[ ! -f "$CHANGE_INTENT_FILE" ]]; then
  missing_items+=("docs/changes/sessions/latest-change.yaml")
fi

if [[ ! -f "$CLEANUP_FILE" ]]; then
  missing_items+=("docs/reports/cleanup-notes.md")
fi

open_inbox_count="$(count_inbox_by_field "status" "open")"
high_inbox_count="$(count_inbox_by_field "priority" "high")"
do_now_count="$(count_inbox_by_field "decision" "do_now")"
phase_title="$(active_phase)"

pending_before_check="$(task_gate_pending_count "before_check")"
pending_before_commit="$(task_gate_pending_count "before_commit")"
blocked_tasks="$(task_summary_count "task" "blocked")"
blocked_checkpoints="$(task_summary_count "checkpoint" "blocked")"
risk_flags_output="$(latest_change_intent_risk_flags || true)"
report_names_output="$(latest_report_names || true)"
roadmap_focus_output="$(roadmap_focus || true)"
structure_missing_output="$(required_structure_files_missing || true)"
pending_sync_output="$(list_pending_sync_items "$TMP_STATUS" || true)"
active_task_title="$(task_first_title_by_status task in_progress)"
next_task_title="$(task_first_title_by_status task todo)"
next_before_check_title="$(task_first_gate_title before_check)"
next_before_commit_title="$(task_first_gate_title before_commit)"
next_before_check_id="$(task_first_gate_id before_check)"
next_before_commit_id="$(task_first_gate_id before_commit)"
mode_label="${goal_status:-unknown}"

print_snapshot() {
  echo "# Project Snapshot"
  echo
  echo "## Project"
  if [[ -n "$project_name" ]]; then
    echo "- Name: $project_name"
    echo "- Type: ${project_type:-unknown}"
    echo "- Primary language: ${primary_language:-unknown}"
    echo "- Phase: ${phase_title:-none}"
    echo "- Mode: $mode_label"
  else
    echo "- Project definition missing"
  fi

  echo
  echo "## Current Focus"
  if [[ -n "$goal_title" ]]; then
    echo "- Goal: $goal_title"
    echo "- Goal status: ${goal_status:-unknown}"
    echo "- Work type: $(yaml_scalar "$CURRENT_GOAL_FILE" "work_type")"
    if [[ -n "$active_task_title" ]]; then
      echo "- Active task: $active_task_title"
    elif [[ -n "$next_task_title" ]]; then
      echo "- Next task: $next_task_title"
    else
      echo "- No active task recorded"
    fi
    if [[ -n "$next_before_check_title" ]]; then
      echo "- Next checkpoint: $next_before_check_title"
    elif [[ -n "$next_before_commit_title" ]]; then
      echo "- Next commit checkpoint: $next_before_commit_title"
    else
      echo "- No open checkpoints"
    fi
  else
    echo "- No current goal recorded"
  fi

  echo
  echo "## Action Board"
  if [[ -f "$CURRENT_TASKS_FILE" ]]; then
    echo "- In-progress tasks: $(task_summary_count task in_progress)"
    echo "- Todo tasks: $(task_summary_count task todo)"
    echo "- Blocked tasks: $blocked_tasks"
    echo "- User checkpoints before check: $pending_before_check"
    echo "- Commit checkpoints before commit: $pending_before_commit"
  else
    echo "- Task board missing"
  fi
  echo "- Inbox open: $open_inbox_count"
  echo "- Inbox do_now: $do_now_count"

  echo
  echo "## Sync Risk"
  if [[ -n "$structure_missing_output" ]]; then
    echo "- Constraint files missing"
  else
    echo "- Constraint files present"
  fi
  if [[ -n "$pending_sync_output" ]]; then
    echo "- Pending sync targets detected"
    printf '%s\n' "$pending_sync_output" | sed 's/^/  - /'
  else
    echo "- No pending structure sync targets"
  fi
  if [[ -n "$risk_flags_output" ]]; then
    echo "- Risk flags detected"
    printf '%s\n' "$risk_flags_output" | sed 's/^/  - /'
  else
    echo "- Change-intent risk flags: none"
  fi

  echo
  echo "## Readiness"
  if [[ "$blocked_tasks" -gt 0 || "$blocked_checkpoints" -gt 0 ]]; then
    echo "- Coding: blocked"
  else
    echo "- Coding: ready"
  fi
  if [[ "$pending_before_check" -gt 0 ]]; then
    echo "- Check: blocked by ${next_before_check_title:-before_check checkpoints}"
  else
    echo "- Check: ready"
  fi
  if [[ "$pending_before_commit" -gt 0 ]]; then
    echo "- Commit: blocked by ${next_before_commit_title:-before_commit checkpoints}"
  elif [[ "$(task_summary_count task todo)" -gt 0 || "$(task_summary_count task in_progress)" -gt 0 ]]; then
    echo "- Commit: blocked by incomplete tasks"
  else
    echo "- Commit: ready"
  fi

  echo
  echo "## Next Command"
  if [[ ${#next_actions[@]} -gt 0 ]]; then
    printf '%s\n' "${next_actions[0]}" | sed 's/^/- /'
  else
    echo "- Run /proj-plan or /proj-init to establish project state"
  fi
}

print_full() {
  echo "# Project Read Summary"
  echo
  echo "## Project"
  if [[ -n "$project_name" ]]; then
    echo "- Name: $project_name"
    echo "- Type: $project_type"
    echo "- Primary language: $primary_language"
  else
    echo "- Project definition missing"
  fi

  echo
  echo "## Current Phase"
  if [[ -n "$phase_title" ]]; then
    echo "- Active phase: $phase_title"
  else
    echo "- No active phase recorded"
  fi
  if [[ -n "$roadmap_focus_output" ]]; then
    printf '%s\n' "$roadmap_focus_output"
  fi

  echo
  echo "## Current Goal"
  if [[ -n "$goal_title" ]]; then
    echo "- Title: $goal_title"
    echo "- Status: $goal_status"
    echo "- Priority: $goal_priority"
    echo "- Objective: $goal_objective"
    echo "- Acceptance criteria:"
    if yaml_list_items "$CURRENT_GOAL_FILE" "acceptance_criteria" | sed 's/^/  - /'; then
      :
    fi
  else
    echo "- No current goal recorded"
  fi

  echo
  echo "## Task Board"
  if [[ -f "$CURRENT_TASKS_FILE" ]]; then
    echo "- Open tasks: $(task_summary_count task todo)"
    echo "- In-progress tasks: $(task_summary_count task in_progress)"
    echo "- Blocked tasks: $blocked_tasks"
    echo "- Pending check checkpoints: $pending_before_check"
    echo "- Pending commit checkpoints: $pending_before_commit"
    echo "- Blocked checkpoints: $blocked_checkpoints"
    if [[ "$pending_before_check" -gt 0 ]]; then
      echo "- Waiting on before_check checkpoints:"
      task_gate_blocked_titles "before_check" | sed 's/^/  - /'
    fi
    if [[ "$pending_before_commit" -gt 0 ]]; then
      echo "- Waiting on before_commit checkpoints:"
      task_gate_blocked_titles "before_commit" | sed 's/^/  - /'
    fi
  else
    echo "- Task board missing"
  fi

  echo
  echo "## Structure Constraints"
  if [[ -n "$structure_missing_output" ]]; then
    echo "- Missing constraint files:"
    printf '%s\n' "$structure_missing_output" | sed 's/^/  - /'
  else
    echo "- Constraint files are present"
  fi
  if [[ -n "$pending_sync_output" ]]; then
    echo "- Pending sync targets from current changes:"
    printf '%s\n' "$pending_sync_output" | sed 's/^/  - /'
  else
    echo "- No structure-sync gaps detected from current changes"
  fi

  echo
  echo "## Inbox"
  echo "- Open items: $open_inbox_count"
  echo "- High priority items: $high_inbox_count"
  echo "- Immediate items: $do_now_count"

  echo
  echo "## Change Status"
  if [[ -f "$CHANGE_INTENT_FILE" ]]; then
    echo "- Latest change goal: $(latest_change_intent_goal)"
    if [[ -n "$risk_flags_output" ]]; then
      echo "- Risk flags:"
      printf '%s\n' "$risk_flags_output" | sed 's/^/  - /'
    else
      echo "- Risk flags: none"
    fi
  else
    echo "- Change intent missing"
  fi

  echo
  echo "## Workspace Risks"
  if [[ ${#missing_items[@]} -eq 0 ]]; then
    echo "- Missing state files: none"
  else
    echo "- Missing state files:"
    printf '%s\n' "${missing_items[@]}" | sed 's/^/  - /'
  fi
  if [[ -f "$CLEANUP_FILE" ]] && grep -E '^- \[ \]' "$CLEANUP_FILE" >/dev/null; then
    echo "- Cleanup notes still contain unresolved items"
  else
    echo "- Cleanup notes are clear"
  fi

  echo
  echo "## Latest Reports"
  if [[ -n "$report_names_output" ]]; then
    printf '%s\n' "$report_names_output" | sed 's/^/- /'
  else
    echo "- none"
  fi

  echo
  echo "## Suggested Next Action"
  printf '%s\n' "${next_actions[@]}" | sed 's/^/- /'
}

if [[ ${#missing_items[@]} -gt 0 ]]; then
  next_actions+=("/proj-init")
fi
if [[ "$do_now_count" -gt 0 ]]; then
  next_actions+=("/proj-readproject --full")
fi
if [[ "$pending_before_check" -gt 0 ]]; then
  next_actions+=("/proj-task --id ${next_before_check_id:-<checkpoint-id>} --status done --by user --note \"...\"")
fi
if [[ "$pending_before_commit" -gt 0 ]]; then
  next_actions+=("/proj-task --id ${next_before_commit_id:-<checkpoint-id>} --status done --by user --note \"...\"")
fi
if [[ "$blocked_tasks" -gt 0 || "$blocked_checkpoints" -gt 0 ]]; then
  next_actions+=("/proj-task --list")
fi
if [[ ${#next_actions[@]} -eq 0 && -n "$goal_title" ]]; then
  next_actions+=("/proj-check")
fi
if [[ ${#next_actions[@]} -eq 0 ]]; then
  next_actions+=("/proj-plan")
fi

if [[ "$MODE" == "full" ]]; then
  print_full
else
  print_snapshot
fi
