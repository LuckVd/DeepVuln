#!/usr/bin/env bash
set -euo pipefail

FILE="${1:-docs/goals/CURRENT_GOAL.yaml}"

if [[ ! -f "$FILE" ]]; then
  echo "Missing goal file: $FILE"
  exit 1
fi

for key in "objective:" "acceptance_criteria:" "in_scope:" "out_of_scope:" "linked_phase:" "task_board:" "decision_points:" "work_type:" "required_sync_docs:"; do
  if ! grep -q "$key" "$FILE"; then
    echo "Goal check failed: missing $key"
    exit 1
  fi
done

if grep -q "still need" "$FILE"; then
  echo "Goal check failed: unresolved placeholder content remains"
  exit 1
fi

echo "Goal check passed"
