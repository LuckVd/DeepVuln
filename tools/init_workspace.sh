#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE_DIR="$ROOT_DIR/docs/history/init-archives"

MODE="bootstrap"
SOURCE_PATH=""
PROJECT_NAME="ClaudeDevKit"
PROJECT_TYPE="governance-workbench"
PROJECT_DESCRIPTION="Single-project AI development governance workspace"
PRIMARY_LANGUAGE="markdown"
GOAL_TITLE="Bootstrap workspace from /proj-init"
GOAL_PRIORITY="high"
GOAL_OBJECTIVE="Initialize the workspace from the provided design input."
GOAL_PHASE="Phase 1"
CURRENT_FOCUS="Initialize workspace state and review assumptions"
STACK_ITEMS=$'    - markdown\n    - yaml\n    - shell'
ACCEPTANCE_ITEMS=$'    - Workspace state files are created.\n    - Current goal is defined.\n    - Roadmap has at least one active phase.'
IN_SCOPE_ITEMS=$'    - state files\n    - roadmap\n    - current goal\n    - current task board'
OUT_OF_SCOPE_ITEMS=$'    - deep automation\n    - runtime product implementation'
IMPACTED_MODULES=$'    - governance-core\n    - planning-state\n    - context-docs'
ROADMAP_ROWS=$'| Phase 1 | Initialize workspace from new design | in_progress |\n| Phase 2 | Execute current goal | todo |'
ASSUMPTIONS=()
UNCERTAINTIES=()
ARCHIVED_FILES=()
MODULE_PATHS=()

usage() {
  cat <<'EOF'
Usage:
  tools/proj_init.sh --source <design-doc> [options]

Options:
  --mode <bootstrap|reinit|adopt>
  --source <path>
  --project-name <name>
  --project-type <type>
  --project-description <text>
  --primary-language <name>
  --goal-title <text>
  --goal-priority <high|medium|low>
  --goal-objective <text>
  --goal-phase <text>
  --current-focus <text>
  --help
EOF
}

apply_mode_defaults() {
  case "$MODE" in
    bootstrap|reinit)
      return 0
      ;;
    adopt)
      PROJECT_DESCRIPTION="Existing project adopted into ClaudeDevKit governance workflow"
      GOAL_TITLE="Adopt existing project into ClaudeDevKit"
      GOAL_OBJECTIVE="Capture the current project state, install governance files, and define the next executable slice without reconstructing full history."
      CURRENT_FOCUS="Adopt the live repository and define the next delivery slice"
      ACCEPTANCE_ITEMS=$'    - Governance workspace files are installed in the existing repository.\n    - Current project state is summarized from the live codebase.\n    - A current goal and task board exist for work from today onward.'
      IN_SCOPE_ITEMS=$'    - governance workspace bootstrap\n    - current project snapshot\n    - next executable slice'
      OUT_OF_SCOPE_ITEMS=$'    - reconstructing full historical task history\n    - auto-closing past milestones without review'
      ROADMAP_ROWS=$'| Phase 1 | Adopt the existing repository into ClaudeDevKit | in_progress |\n| Phase 2 | Execute the current in-flight slice | todo |\n| Phase 3 | Tighten checks and cleanup | todo |'
      ;;
    *)
      echo "Invalid mode: $MODE" >&2
      exit 1
      ;;
  esac
}

archive_if_exists() {
  local rel="$1"
  local src="$ROOT_DIR/$rel"
  if [[ -f "$src" ]]; then
    local stamp base target
    stamp="$(date +%Y%m%d-%H%M%S)"
    base="$(basename "$rel")"
    target="$ARCHIVE_DIR/$stamp-$base"
    cp "$src" "$target"
    ARCHIVED_FILES+=("$target")
  fi
}

extract_section_block() {
  local section="$1"
  awk -v section="$section" '
    $0 == "## " section { in_section=1; next }
    /^## / && in_section { exit }
    in_section { print }
  ' "$SOURCE_PATH"
}

extract_project_field() {
  local label="$1"
  extract_section_block "Project" | sed -n "s/^- ${label}: //p" | head -n 1
}

extract_goal_field() {
  local label="$1"
  extract_section_block "Current Goal" | sed -n "s/^- ${label}: //p" | head -n 1
}

extract_nested_items() {
  local section="$1"
  local label="$2"
  extract_section_block "$section" | awk -v label="$label" '
    $0 == "- " label ":" { capture=1; next }
    capture && /^- / { exit }
    capture && /^  - / {
      sub(/^  - /, "")
      print
    }
  '
}

extract_plain_items() {
  local section="$1"
  extract_section_block "$section" | sed -n 's/^- //p'
}

build_indented_list() {
  local prefix="$1"
  shift
  local item out=""
  for item in "$@"; do
    [[ -z "$item" ]] && continue
    out+="${prefix}${item}"$'\n'
  done
  printf '%s' "${out%$'\n'}"
}

populate_from_brief() {
  local value idx status phase_text
  local roadmap_items acceptance_items in_scope_items out_scope_items module_items

  value="$(extract_project_field "Name")"
  [[ -n "$value" ]] && PROJECT_NAME="$value"
  value="$(extract_project_field "Type")"
  [[ -n "$value" ]] && PROJECT_TYPE="$value"
  value="$(extract_project_field "Description")"
  [[ -n "$value" ]] && PROJECT_DESCRIPTION="$value"
  value="$(extract_project_field "Primary language")"
  if [[ -n "$value" ]]; then
    PRIMARY_LANGUAGE="$value"
    STACK_ITEMS="    - ${PRIMARY_LANGUAGE}"$'\n'"    - markdown"$'\n'"    - yaml"$'\n'"    - shell"
  fi

  value="$(extract_goal_field "Title")"
  [[ -n "$value" ]] && GOAL_TITLE="$value"
  value="$(extract_goal_field "Objective")"
  [[ -n "$value" ]] && GOAL_OBJECTIVE="$value"

  mapfile -t roadmap_items < <(extract_plain_items "Roadmap")
  if [[ ${#roadmap_items[@]} -gt 0 ]]; then
    ROADMAP_ROWS=""
    idx=0
    for phase_text in "${roadmap_items[@]}"; do
      [[ -z "$phase_text" ]] && continue
      status="todo"
      if [[ $idx -eq 0 ]]; then
        status="in_progress"
        GOAL_PHASE="${phase_text%%:*}"
        CURRENT_FOCUS="${phase_text#*: }"
      fi
      ROADMAP_ROWS+="| ${phase_text%%:*} | ${phase_text#*: } | ${status} |"$'\n'
      idx=$((idx + 1))
    done
    ROADMAP_ROWS="${ROADMAP_ROWS%$'\n'}"
  fi

  mapfile -t acceptance_items < <(extract_nested_items "Current Goal" "Acceptance")
  if [[ ${#acceptance_items[@]} -gt 0 ]]; then
    ACCEPTANCE_ITEMS="$(build_indented_list "    - " "${acceptance_items[@]}")"
  fi

  mapfile -t in_scope_items < <(extract_nested_items "Current Goal" "In scope")
  if [[ ${#in_scope_items[@]} -gt 0 ]]; then
    IN_SCOPE_ITEMS="$(build_indented_list "    - " "${in_scope_items[@]}")"
  fi

  mapfile -t out_scope_items < <(extract_nested_items "Current Goal" "Out of scope")
  if [[ ${#out_scope_items[@]} -gt 0 ]]; then
    OUT_OF_SCOPE_ITEMS="$(build_indented_list "    - " "${out_scope_items[@]}")"
  fi

  mapfile -t module_items < <(extract_plain_items "Modules")
  if [[ ${#module_items[@]} -gt 0 ]]; then
    MODULE_PATHS=("${module_items[@]}")
    IMPACTED_MODULES="$(build_indented_list "    - " "${module_items[@]}")"
  fi
}

build_project_modules_block() {
  if [[ ${#MODULE_PATHS[@]} -eq 0 ]]; then
    cat <<'EOF'
  product-code:
    path:
      - src/**
    status: todo
    level: active
EOF
    return
  fi

  local idx=1 path
  for path in "${MODULE_PATHS[@]}"; do
    cat <<EOF
  app-module-$idx:
    path:
      - $path
    status: todo
    level: active
    note: Derived from project brief module path $path
EOF
    idx=$((idx + 1))
  done
}

write_modules_doc() {
  {
    echo "# Modules"
    echo
    echo "| Module | Paths | Level | Note |"
    echo "|---|---|---|---|"
    echo "| governance-core | \`.claude/**\`, \`tools/**\` | core | Governance rules and helpers |"
    echo "| planning-state | \`docs/goals/**\`, \`docs/roadmap/**\`, \`docs/history/**\` | stable | Planning and history state |"
    echo "| context-docs | \`docs/context/**\`, \`docs/api/**\`, \`README.md\` | active | Context and contract docs |"
    if [[ ${#MODULE_PATHS[@]} -eq 0 ]]; then
      echo "| product-code | \`src/**\` | active | Default application code area |"
    else
      local idx=1 path
      for path in "${MODULE_PATHS[@]}"; do
        echo "| app-module-$idx | \`$path\` | active | Derived from the project brief |"
        idx=$((idx + 1))
      done
    fi
  } > "$ROOT_DIR/docs/context/MODULES.md"
}

write_api_doc() {
  {
    echo "# API"
    echo
    if printf '%s\n' "${MODULE_PATHS[@]}" | grep -qi 'api'; then
      echo "## Expected Contract Areas"
      echo
      echo "- Authentication endpoints for the current goal"
      echo "- Application routes or handlers derived from module paths"
      echo
      echo "## Source Context"
      echo
      echo "- Project: $PROJECT_NAME"
      echo "- Current goal: $GOAL_TITLE"
      echo
      echo "## Notes"
      echo
      echo "- This file was initialized from the project brief."
      echo "- Refine concrete request/response contracts as implementation begins."
    else
      echo "This workspace does not define a runtime API yet."
      echo
      echo "When product code is added, keep the contract summary here and treat it as a fact source."
    fi
  } > "$ROOT_DIR/docs/api/API.md"
}

write_structure_docs() {
  mkdir -p \
    "$ROOT_DIR/docs/context/structure" \
    "$ROOT_DIR/docs/context/files" \
    "$ROOT_DIR/docs/context/apis" \
    "$ROOT_DIR/docs/context/functions" \
    "$ROOT_DIR/docs/context/models"

  cat > "$ROOT_DIR/docs/context/structure/STRUCTURE_CONTRACT.yaml" <<'EOF'
contract:
  version: 1
  top_level_paths:
    - .claude/
    - docs/
    - README.md
    - src/
    - tools/
  modules:
    - name: governance-core
      paths:
        - .claude/**
        - tools/**
      role: workflows_and_policies
      sync_docs:
        - docs/context/structure/README.md
    - name: planning-state
      paths:
        - docs/goals/**
        - docs/roadmap/**
        - docs/history/**
      role: project_state
      sync_docs:
        - docs/context/files/README.md
    - name: product-code
      paths:
        - src/**
      role: runtime_code
      sync_docs:
        - docs/context/files/README.md
        - docs/context/functions/README.md
        - docs/api/API.md
        - docs/context/apis/README.md
        - docs/context/models/README.md
  file_classes:
    - name: api_files
      paths:
        - src/api/**
        - src/routes/**
        - src/controllers/**
        - src/endpoints/**
      sync_docs:
        - docs/api/API.md
        - docs/context/apis/README.md
    - name: function_files
      paths:
        - src/services/**
        - src/controllers/**
        - src/utils/**
      sync_docs:
        - docs/context/functions/README.md
    - name: model_files
      paths:
        - src/models/**
        - schema/**
        - config/**
      sync_docs:
        - docs/context/models/README.md
    - name: structure_files
      paths:
        - .claude/**
        - tools/**
      sync_docs:
        - docs/context/structure/README.md
EOF

  cat > "$ROOT_DIR/docs/context/structure/SYNC_RULES.yaml" <<'EOF'
rules:
  - id: source_files_need_file_index
    when_changed:
      - src/**
      - schema/**
      - config/**
    require_docs:
      - docs/context/files/**
  - id: api_changes_need_api_docs
    when_changed:
      - src/api/**
      - src/routes/**
      - src/controllers/**
      - src/endpoints/**
    require_docs:
      - docs/api/API.md
      - docs/context/apis/**
  - id: function_changes_need_function_docs
    when_changed:
      - src/services/**
      - src/controllers/**
      - src/utils/**
    require_docs:
      - docs/context/functions/**
  - id: model_changes_need_model_docs
    when_changed:
      - src/models/**
      - schema/**
      - config/**
    require_docs:
      - docs/context/models/**
  - id: workflow_changes_need_structure_docs
    when_changed:
      - .claude/**
      - tools/**
    require_docs:
      - docs/context/structure/**
EOF

  cat > "$ROOT_DIR/docs/context/structure/README.md" <<'EOF'
# Structure Constraints

This directory defines the enforceable structure and synchronization rules for the project.

## Fact Sources

- `STRUCTURE_CONTRACT.yaml`: allowed paths, module roles, and sync obligations
- `SYNC_RULES.yaml`: change-triggered documentation sync rules

## Human Summary

- `.claude/` and `tools/` are governance-core and require structure doc updates when changed.
- `docs/goals/`, `docs/roadmap/`, and `docs/history/` are planning-state.
- `src/` is the runtime code area and must sync file, function, API, and model docs as applicable.
EOF

  cat > "$ROOT_DIR/docs/context/files/README.md" <<'EOF'
# File Index

Tracks structure-level files by area so humans and checks can answer:
- what each file is for
- where a new file should live
- which docs must be updated when a file changes

## Current Split

- `governance-core.md`: `.claude/**`, `tools/**`
- `planning-state.md`: `docs/goals/**`, `docs/roadmap/**`, `docs/history/**`
- `product-code.md`: reserved for `src/**`
EOF

  cat > "$ROOT_DIR/docs/context/files/governance-core.md" <<'EOF'
# Governance Core Files

| Path | Role | Sync Requirement |
|---|---|---|
| `.claude/CONSTITUTION.md` | top-level workflow rules | update `docs/context/structure/README.md` when rules change |
| `.claude/commands/**` | command contracts | update command docs and structure docs when behavior changes |
| `.claude/workflows/**` | workflow steps | update workflow docs and structure docs when behavior changes |
| `.claude/policies/**` | policy sources for checks and scope control | update related checks and structure docs when policy semantics change |
| `.claude/templates/**` | reusable framework templates | update init/adopt docs when template semantics change |
| `tools/*.sh` | local execution helpers | update structure docs and relevant README sections when behavior changes |
EOF

  cat > "$ROOT_DIR/docs/context/files/planning-state.md" <<'EOF'
# Planning State Files

| Path | Role | Sync Requirement |
|---|---|---|
| `docs/goals/CURRENT_GOAL.yaml` | current objective and acceptance criteria | update together with `CURRENT_TASKS.yaml` when scope changes |
| `docs/goals/CURRENT_TASKS.yaml` | executable task/checkpoint board | update together with goal when work type or sync docs change |
| `docs/goals/INBOX.yaml` | interrupts and follow-ups | keep only open items active |
| `docs/roadmap/ROADMAP.md` | phase-level direction | update when current phase direction changes |
EOF

  cat > "$ROOT_DIR/docs/context/files/product-code.md" <<'EOF'
# Product Code Files

No runtime product code is indexed yet.

When `src/**` starts carrying implementation, split this index by domain and register:
- file path
- responsibility
- public exports
- dependent docs (`API`, `functions`, `models`)
EOF

  cat > "$ROOT_DIR/docs/context/apis/README.md" <<'EOF'
# API Index

No runtime API is defined yet.

When API-facing code is added, split docs by domain, for example:
- `auth.md`
- `users.md`
- `admin.md`

Each entry must cover routes, request shape, response shape, error cases, and source handlers.
EOF

  cat > "$ROOT_DIR/docs/context/functions/README.md" <<'EOF'
# Function Index

No runtime structural functions are indexed yet.

Track only structural functions:
- service entrypoints
- controller handlers
- shared public utilities
- key state transition functions
EOF

  cat > "$ROOT_DIR/docs/context/models/README.md" <<'EOF'
# Model Index

No runtime models or schemas are indexed yet.

When data structures are introduced, record:
- schema or model name
- file path
- field meaning
- compatibility notes
- dependent APIs or services
EOF

  cat > "$ROOT_DIR/docs/context/DEPENDENCY_MAP.md" <<'EOF'
# Dependency Map

## Allowed High-Level Dependencies

- `tools/**` may depend on project state files under `docs/goals/**` and `docs/roadmap/**`
- `.claude/**` defines policies and workflows; it should not depend on runtime `src/**`
- `src/**` may depend on internal runtime modules, but governance docs must not depend on runtime code to remain readable without execution

## Current State

- No runtime dependency graph is defined yet because `src/` is still empty.
EOF
}

write_task_board() {
  local timestamp="$1"
  if [[ "$MODE" == "adopt" ]]; then
    cat > "$ROOT_DIR/docs/goals/CURRENT_TASKS.yaml" <<EOF
task_board:
  goal_title: "$GOAL_TITLE"
  linked_phase: "$GOAL_PHASE"
  updated_at: "$timestamp"
  items:
    - id: task-001
      title: "Review the inferred project snapshot"
      type: task
      owner: ai
      status: todo
      stage_gate: anytime
      work_type: code
      goal_link: "$GOAL_TITLE"
      done_definition: "The generated repository summary matches the live project state closely enough to continue planning"
      required_sync_docs:
        - docs/context/files/README.md
    - id: task-002
      title: "Define the next executable slice for the in-flight work"
      type: task
      owner: ai
      status: todo
      stage_gate: anytime
      work_type: code
      goal_link: "$GOAL_TITLE"
      done_definition: "A current goal slice exists for the next delivery step after adoption"
      required_sync_docs:
        - docs/context/files/README.md
    - id: ucp-001
      title: "Confirm inferred scope and active delivery target"
      type: checkpoint
      owner: user
      status: todo
      stage_gate: before_check
      work_type: doc
      goal_link: "$GOAL_TITLE"
      done_definition: "User confirms the adoption summary and the current goal boundary"
      required_sync_docs:
        - docs/context/structure/README.md
    - id: ccp-001
      title: "Approve readiness to commit"
      type: checkpoint
      owner: user
      status: todo
      stage_gate: before_commit
      work_type: doc
      goal_link: "$GOAL_TITLE"
      done_definition: "User explicitly approves the commit gate outcome"
      required_sync_docs:
        - docs/context/structure/README.md
EOF
    return
  fi

  cat > "$ROOT_DIR/docs/goals/CURRENT_TASKS.yaml" <<EOF
task_board:
  goal_title: "$GOAL_TITLE"
  linked_phase: "$GOAL_PHASE"
  updated_at: "$timestamp"
  items:
    - id: task-001
      title: "Review extracted workspace assumptions"
      type: task
      owner: ai
      status: todo
      stage_gate: anytime
      work_type: code
      goal_link: "$GOAL_TITLE"
      done_definition: "Extracted assumptions are summarized and ready for review"
      required_sync_docs:
        - docs/context/files/README.md
    - id: task-002
      title: "Refine the current goal into executable slices"
      type: task
      owner: ai
      status: todo
      stage_gate: anytime
      work_type: code
      goal_link: "$GOAL_TITLE"
      done_definition: "A smaller task plan exists for the active goal"
      required_sync_docs:
        - docs/context/files/README.md
    - id: ucp-001
      title: "Confirm scope and acceptance criteria"
      type: checkpoint
      owner: user
      status: todo
      stage_gate: before_check
      work_type: doc
      goal_link: "$GOAL_TITLE"
      done_definition: "User confirms the active goal boundaries"
      required_sync_docs:
        - docs/context/structure/README.md
    - id: ccp-001
      title: "Approve readiness to commit"
      type: checkpoint
      owner: user
      status: todo
      stage_gate: before_commit
      work_type: doc
      goal_link: "$GOAL_TITLE"
      done_definition: "User explicitly approves the commit gate outcome"
      required_sync_docs:
        - docs/context/structure/README.md
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --source) SOURCE_PATH="${2:-}"; shift 2 ;;
    --project-name) PROJECT_NAME="${2:-}"; shift 2 ;;
    --project-type) PROJECT_TYPE="${2:-}"; shift 2 ;;
    --project-description) PROJECT_DESCRIPTION="${2:-}"; shift 2 ;;
    --primary-language) PRIMARY_LANGUAGE="${2:-}"; shift 2 ;;
    --goal-title) GOAL_TITLE="${2:-}"; shift 2 ;;
    --goal-priority) GOAL_PRIORITY="${2:-}"; shift 2 ;;
    --goal-objective) GOAL_OBJECTIVE="${2:-}"; shift 2 ;;
    --goal-phase) GOAL_PHASE="${2:-}"; shift 2 ;;
    --current-focus) CURRENT_FOCUS="${2:-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$SOURCE_PATH" ]]; then
  echo "Missing required option: --source <design-doc>" >&2
  exit 1
fi

if [[ ! -f "$SOURCE_PATH" ]]; then
  echo "Source file not found: $SOURCE_PATH" >&2
  exit 1
fi

mkdir -p "$ARCHIVE_DIR"

apply_mode_defaults

if [[ "$MODE" == "reinit" || "$MODE" == "adopt" ]]; then
  archive_if_exists ".claude/project.yaml"
  archive_if_exists "docs/goals/CURRENT_GOAL.yaml"
  archive_if_exists "docs/goals/CURRENT_TASKS.yaml"
  archive_if_exists "docs/goals/INBOX.yaml"
  archive_if_exists "docs/roadmap/ROADMAP.md"
fi

if ! grep -qi "phase" "$SOURCE_PATH"; then
  UNCERTAINTIES+=("Source does not clearly define roadmap phases.")
fi

if ! grep -qi "goal\|目标\|objective" "$SOURCE_PATH"; then
  UNCERTAINTIES+=("Source does not clearly define the current goal.")
fi

populate_from_brief

ASSUMPTIONS+=("The first active goal should start immediately after initialization.")
ASSUMPTIONS+=("A default task board was created so the goal can be executed in smaller slices.")
if [[ "$MODE" == "adopt" ]]; then
  ASSUMPTIONS+=("Repository history before adoption is summarized as context and is not reconstructed as task history.")
fi

INIT_DATE="$(date +%F)"
INIT_TS="$(date '+%Y-%m-%d %H:%M:%S %Z')"
SOURCE_ABS="$(cd "$(dirname "$SOURCE_PATH")" && pwd)/$(basename "$SOURCE_PATH")"

mkdir -p \
  "$ROOT_DIR/.claude" \
  "$ROOT_DIR/docs/changes/sessions" \
  "$ROOT_DIR/docs/goals" \
  "$ROOT_DIR/docs/roadmap" \
  "$ROOT_DIR/docs/reports" \
  "$ROOT_DIR/docs/history" \
  "$ROOT_DIR/docs/history/init-archives" \
  "$ROOT_DIR/docs/context" \
  "$ROOT_DIR/docs/api"

cat > "$ROOT_DIR/.claude/project.yaml" <<EOF
project:
  name: "$PROJECT_NAME"
  type: "$PROJECT_TYPE"
  description: "$PROJECT_DESCRIPTION"
  primary_language: "$PRIMARY_LANGUAGE"
  stack:
$STACK_ITEMS

modules:
  governance-core:
    path:
      - .claude/**
      - tools/**
    status: active
    level: core
  planning-state:
    path:
      - docs/goals/**
      - docs/roadmap/**
      - docs/history/**
    status: active
    level: stable
  context-docs:
    path:
      - docs/context/**
      - docs/api/**
      - README.md
    status: active
    level: active
$(build_project_modules_block)

fact_sources:
  highest:
    - .claude/project.yaml
    - docs/goals/CURRENT_GOAL.yaml
    - docs/goals/CURRENT_TASKS.yaml
    - docs/goals/INBOX.yaml
  medium:
    - docs/roadmap/ROADMAP.md
    - docs/context/FACT_SOURCES.md
    - docs/context/structure/STRUCTURE_CONTRACT.yaml
    - docs/context/structure/SYNC_RULES.yaml
    - docs/api/API.md
  derived:
    - docs/reports/review-latest.md
    - docs/history/COMMIT_HISTORY.md

required_cleanup:
  - remove_or_mark_replaced_plans
  - update_current_goal_when_scope_changes
  - update_current_tasks_when_scope_changes
  - keep_inbox_only_for_open_items
  - flag_dead_code_or_dead_docs_in_review
EOF

cat > "$ROOT_DIR/docs/goals/CURRENT_GOAL.yaml" <<EOF
goal:
  title: "$GOAL_TITLE"
  status: in_progress
  priority: "$GOAL_PRIORITY"
  objective: "$GOAL_OBJECTIVE"
  linked_phase: "$GOAL_PHASE"
  task_board: "docs/goals/CURRENT_TASKS.yaml"
  work_type: "code"
  decision_points:
    - ucp-001
    - ccp-001
  acceptance_criteria:
$ACCEPTANCE_ITEMS
  in_scope:
$IN_SCOPE_ITEMS
  out_of_scope:
$OUT_OF_SCOPE_ITEMS
  impacted_modules:
$IMPACTED_MODULES
  required_sync_docs:
    - docs/context/files/README.md
  required_checks:
    - constitution
    - protection
    - scope
    - goal
    - tasks
  notes:
    - Initialized by /proj-init on $INIT_DATE
EOF

write_task_board "$INIT_TS"

cat > "$ROOT_DIR/docs/goals/INBOX.yaml" <<EOF
items:
  - id: inbox-seed-001
    type: followup
    title: "Review unresolved init assumptions"
    source: proj-init
    priority: medium
    decision: schedule_later
    linked_goal: "$GOAL_TITLE"
    status: open
EOF

cat > "$ROOT_DIR/docs/changes/sessions/latest-change.yaml" <<EOF
goal: $GOAL_TITLE
intent: $GOAL_OBJECTIVE
planned_files:
  - .claude/**
  - tools/**
  - docs/**
$(if printf '%s\n' "${MODULE_PATHS[@]}" | grep -q .; then
    printf '%s\n' "${MODULE_PATHS[@]}" | sed 's#^#  - #'
  else
    printf '%s\n' "  - src/**"
  fi)
do_not_touch:
  - .git/**
risk_flags:
  - init_state_change
verification_plan:
  - run /proj-readproject to confirm the adopted snapshot
  - review the inferred goal, tasks, and sync docs before /proj-check
EOF

cat > "$ROOT_DIR/docs/reports/cleanup-notes.md" <<'EOF'
# Cleanup Notes

- No cleanup items recorded at initialization time.
EOF

cat > "$ROOT_DIR/docs/roadmap/ROADMAP.md" <<EOF
# Roadmap

## Phase Overview

| Phase | Goal | Status |
|---|---|---|
$ROADMAP_ROWS

## Current Focus

- $CURRENT_FOCUS
EOF

cat > "$ROOT_DIR/docs/context/INIT_SOURCE.md" <<EOF
# Init Source

- Mode: $MODE
- Source: $SOURCE_ABS
- Timestamp: $INIT_TS
- Operator: /proj-init
- Intent: rebuild workspace state from the provided design input
EOF

write_modules_doc
write_api_doc
write_structure_docs

{
  echo "# Init Report"
  echo
  echo "- Mode: $MODE"
  echo "- Source: $SOURCE_ABS"
  echo "- Timestamp: $INIT_TS"
  echo "- Generated files:"
  echo "  - .claude/project.yaml"
  echo "  - docs/goals/CURRENT_GOAL.yaml"
  echo "  - docs/goals/CURRENT_TASKS.yaml"
  echo "  - docs/goals/INBOX.yaml"
  echo "  - docs/changes/sessions/latest-change.yaml"
  echo "  - docs/roadmap/ROADMAP.md"
  echo "  - docs/context/INIT_SOURCE.md"
  echo "  - docs/context/MODULES.md"
  echo "  - docs/api/API.md"
  echo "  - docs/context/structure/STRUCTURE_CONTRACT.yaml"
  echo "  - docs/context/structure/SYNC_RULES.yaml"
  echo "  - docs/context/structure/README.md"
  echo "  - docs/context/files/README.md"
  echo "  - docs/context/apis/README.md"
  echo "  - docs/context/functions/README.md"
  echo "  - docs/context/models/README.md"
  echo "  - docs/context/DEPENDENCY_MAP.md"
  echo "  - docs/reports/cleanup-notes.md"
  echo
  echo "- Archived files:"
  if [[ ${#ARCHIVED_FILES[@]} -eq 0 ]]; then
    echo "  - none"
  else
    for item in "${ARCHIVED_FILES[@]}"; do
      echo "  - $item"
    done
  fi
  echo
  echo "- Assumptions:"
  for item in "${ASSUMPTIONS[@]}"; do
    echo "  - $item"
  done
  echo
  echo "- Uncertainties:"
  if [[ ${#UNCERTAINTIES[@]} -eq 0 ]]; then
    echo "  - none"
  else
    for item in "${UNCERTAINTIES[@]}"; do
      echo "  - $item"
    done
  fi
  echo
  echo "- Cleanup actions:"
  if [[ "$MODE" == "reinit" ]]; then
    echo "  - replaced planning files were archived before rewrite"
  else
    echo "  - initial state written from template set"
  fi
  echo "  - current goal, task board, and roadmap were regenerated"
  echo "  - inbox was reset to unresolved init follow-up"
} > "$ROOT_DIR/docs/reports/init-latest.md"

echo "Initialized workspace in $MODE mode"
echo "Source: $SOURCE_ABS"
