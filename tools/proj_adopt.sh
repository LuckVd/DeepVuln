#!/usr/bin/env bash
set -euo pipefail

FRAMEWORK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$FRAMEWORK_ROOT/tools/lib/native_command_parse.sh"
TARGET_DIR=""
FORCE=0
GOAL_TITLE=""
GOAL_OBJECTIVE=""

usage() {
  cat <<'EOF'
Usage:
  tools/proj_adopt.sh --target <project-path> [options]
  tools/proj_adopt.sh 接管 <project-path> [当前目标...]

Options:
  --target <path>           Existing project to adopt into ClaudeDevKit
  --goal-title <text>       Override the inferred current goal title
  --goal-objective <text>   Override the inferred current goal objective
  --force                   Overwrite ClaudeDevKit-managed command files if present
  --help, -h                Show this help
EOF
}

if [[ $# -gt 0 && "$1" != --* ]]; then
  BRIEF="$(join_freeform_args "$@")"
  TARGET_DIR="$(extract_path_from_text "$BRIEF" || true)"
  GOAL_TITLE="$(extract_adopt_goal_title_from_text "$BRIEF" || true)"
  if [[ -n "$GOAL_TITLE" ]]; then
    GOAL_OBJECTIVE="Adopt the live repository into ClaudeDevKit and focus next on: $GOAL_TITLE"
  fi
  if [[ "$(infer_force_flag_from_text "$BRIEF")" == "yes" ]]; then
    FORCE=1
  fi
  if [[ -z "$TARGET_DIR" ]]; then
    echo "Could not infer target path from request. Use /proj-adopt 接管 /path/to/project or --target <path>." >&2
    exit 1
  fi
  set --
fi

abs_path() {
  local path="$1"
  (cd "$path" && pwd)
}

managed_relpaths() {
  (
    cd "$FRAMEWORK_ROOT"
    find .claude tools -type f | sort
    if [[ -f "docs/usage/CLAUDE_COMMAND_EXAMPLES.md" ]]; then
      printf '%s\n' "docs/usage/CLAUDE_COMMAND_EXAMPLES.md"
    fi
  )
}

detect_primary_language() {
  local target="$1"
  if [[ -f "$target/pyproject.toml" || -f "$target/requirements.txt" ]]; then
    echo "python"
  elif [[ -f "$target/go.mod" ]]; then
    echo "go"
  elif [[ -f "$target/Cargo.toml" ]]; then
    echo "rust"
  elif [[ -f "$target/pom.xml" || -f "$target/build.gradle" || -f "$target/build.gradle.kts" ]]; then
    echo "java"
  elif [[ -f "$target/package.json" ]]; then
    if [[ -f "$target/tsconfig.json" ]] || find "$target" -type f \( -name '*.ts' -o -name '*.tsx' \) | head -n 1 | grep -q .; then
      echo "typescript"
    else
      echo "javascript"
    fi
  else
    echo "unknown"
  fi
}

detect_project_type() {
  local target="$1"
  if [[ -f "$target/package.json" ]]; then
    if [[ -d "$target/src/pages" || -d "$target/src/app" || -d "$target/app" || -f "$target/next.config.js" || -f "$target/next.config.ts" || -f "$target/vite.config.ts" || -f "$target/vite.config.js" ]]; then
      echo "web-application"
      return
    fi
  fi
  if [[ -d "$target/cmd" || -d "$target/internal" || -d "$target/api" || -d "$target/server" ]]; then
    echo "service"
    return
  fi
  if [[ -d "$target/lib" || -d "$target/packages" ]]; then
    echo "library"
    return
  fi
  echo "application"
}

collect_module_paths() {
  local target="$1"
  local candidates=(
    src
    app
    api
    cmd
    internal
    server
    backend
    frontend
    services
    packages
    lib
    web
  )
  local path results=()
  for path in "${candidates[@]}"; do
    if [[ -d "$target/$path" ]]; then
      results+=("$path")
    fi
  done

  if [[ ${#results[@]} -eq 0 ]]; then
    results+=(".")
  fi

  printf '%s\n' "${results[@]}"
}

build_state_summary() {
  local target="$1"
  local language="$2"
  local type="$3"
  local modules_csv="$4"
  local summary=()

  summary+=("Existing ${type} repository discovered at the target path")
  if [[ "$language" != "unknown" ]]; then
    summary+=("Primary language appears to be ${language}")
  fi
  if [[ -d "$target/.git" ]]; then
    summary+=("Git metadata is already present")
  fi
  if [[ -d "$target/tests" || -d "$target/test" || -d "$target/__tests__" ]]; then
    summary+=("Test directories already exist")
  fi
  if [[ -d "$target/docs" ]]; then
    summary+=("Repository already contains project documentation")
  fi
  summary+=("Detected active code areas: ${modules_csv}")
  summary+=("Historical work before adoption is treated as context, not reconstructed task history")

  local joined="" item
  for item in "${summary[@]}"; do
    if [[ -n "$joined" ]]; then
      joined+="; "
    fi
    joined+="$item"
  done
  printf '%s' "$joined"
}

copy_framework_files() {
  local target="$1"
  local copy_flag="-R"
  local rel
  local conflicts=()

  mkdir -p "$target/.claude" "$target/tools" "$target/docs/usage" "$target/docs/context"

  if [[ $FORCE -eq 0 ]]; then
    while IFS= read -r rel; do
      [[ -z "$rel" ]] && continue
      if [[ -e "$target/$rel" ]]; then
        conflicts+=("$target/$rel")
      fi
    done < <(managed_relpaths)

    if [[ ${#conflicts[@]} -gt 0 ]]; then
      echo "Refusing to overwrite existing ClaudeDevKit-managed paths:" >&2
      printf '%s\n' "${conflicts[@]}" | sed 's/^/  - /' >&2
      echo "Re-run with --force if this repository should be re-adopted." >&2
      exit 1
    fi
  else
    copy_flag="-Rf"
  fi

  cp $copy_flag "$FRAMEWORK_ROOT/tools/." "$target/tools/"
  cp $copy_flag "$FRAMEWORK_ROOT/.claude/." "$target/.claude/"
  if [[ -f "$FRAMEWORK_ROOT/docs/usage/CLAUDE_COMMAND_EXAMPLES.md" ]]; then
    cp $copy_flag "$FRAMEWORK_ROOT/docs/usage/CLAUDE_COMMAND_EXAMPLES.md" "$target/docs/usage/"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET_DIR="${2:-}"
      shift 2
      ;;
    --goal-title)
      GOAL_TITLE="${2:-}"
      shift 2
      ;;
    --goal-objective)
      GOAL_OBJECTIVE="${2:-}"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
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

if [[ -z "$TARGET_DIR" ]]; then
  echo "Missing required option: --target <project-path>" >&2
  exit 1
fi

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "Target directory not found: $TARGET_DIR" >&2
  exit 1
fi

TARGET_DIR="$(abs_path "$TARGET_DIR")"
if [[ "$TARGET_DIR" == "$FRAMEWORK_ROOT" ]]; then
  echo "Target directory is the current ClaudeDevKit repository. Use /proj-init here instead." >&2
  exit 1
fi

copy_framework_files "$TARGET_DIR"

PROJECT_NAME="$(basename "$TARGET_DIR")"
PRIMARY_LANGUAGE="$(detect_primary_language "$TARGET_DIR")"
PROJECT_TYPE="$(detect_project_type "$TARGET_DIR")"
mapfile -t MODULE_PATHS < <(collect_module_paths "$TARGET_DIR")
MODULES_CSV="$(printf '%s, ' "${MODULE_PATHS[@]}")"
MODULES_CSV="${MODULES_CSV%, }"
PROJECT_DESCRIPTION="$(build_state_summary "$TARGET_DIR" "$PRIMARY_LANGUAGE" "$PROJECT_TYPE" "$MODULES_CSV")"

if [[ -z "$GOAL_TITLE" ]]; then
  GOAL_TITLE="Take over current in-flight work in ${PROJECT_NAME}"
fi

if [[ -z "$GOAL_OBJECTIVE" ]]; then
  GOAL_OBJECTIVE="Adopt the live repository into ClaudeDevKit, capture the current execution context, and define the next delivery slice without reconstructing all historical work."
fi

BRIEF_PATH="$TARGET_DIR/docs/context/ADOPT_BRIEF.md"
{
  echo "# ClaudeDevKit Adopt Brief"
  echo
  echo "## Project"
  echo "- Name: ${PROJECT_NAME}"
  echo "- Type: ${PROJECT_TYPE}"
  echo "- Description: ${PROJECT_DESCRIPTION}"
  echo "- Primary language: ${PRIMARY_LANGUAGE}"
  echo
  echo "## Roadmap"
  echo "- Phase 1: Adopt the existing repository into ClaudeDevKit"
  echo "- Phase 2: Execute the current in-flight delivery slice"
  echo "- Phase 3: Tighten checks and cleanup"
  echo
  echo "## Current Goal"
  echo "- Title: ${GOAL_TITLE}"
  echo "- Objective: ${GOAL_OBJECTIVE}"
  echo "- Acceptance:"
  echo "  - Governance workspace is installed in the existing repository"
  echo "  - Current project state is summarized from the live codebase"
  echo "  - A current goal and task board exist for work from today onward"
  echo "- In scope:"
  echo "  - governance workspace bootstrap"
  echo "  - current project snapshot"
  echo "  - next executable slice"
  echo "- Out of scope:"
  echo "  - reconstructing full historical task history"
  echo "  - auto-closing past milestones without review"
  echo
  echo "## Modules"
  printf '%s\n' "${MODULE_PATHS[@]}" | sed 's#^#- #' 
} > "$BRIEF_PATH"

"$TARGET_DIR/tools/proj_init.sh" \
  --mode adopt \
  --source "$BRIEF_PATH" \
  --project-name "$PROJECT_NAME" \
  --project-type "$PROJECT_TYPE" \
  --project-description "$PROJECT_DESCRIPTION" \
  --primary-language "$PRIMARY_LANGUAGE" \
  --goal-title "$GOAL_TITLE" \
  --goal-objective "$GOAL_OBJECTIVE"

echo "Adopted project: $TARGET_DIR"
echo "Brief: $BRIEF_PATH"
