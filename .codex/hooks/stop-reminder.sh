#!/bin/bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || git rev-parse --show-toplevel 2>/dev/null || pwd)

exec env AI_HOOK_PROTOCOL=codex AI_HOOK_REPO_ROOT="$REPO_ROOT" \
    bash "$REPO_ROOT/scripts/ai-hooks/stop-nudge.sh"
