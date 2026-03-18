#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/tools/lib/structure_sync.sh"

STATUS_FILE="${1:-}"

if [[ -z "$STATUS_FILE" || ! -f "$STATUS_FILE" ]]; then
  echo "Usage: tools/check_structure_sync.sh <git-status-file>"
  exit 1
fi

check_sync_rules "$STATUS_FILE"
