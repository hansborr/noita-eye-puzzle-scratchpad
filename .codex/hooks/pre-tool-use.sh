#!/bin/bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || git rev-parse --show-toplevel 2>/dev/null || pwd)

run_shared_hook() {
    local hook="$1"
    local payload="$2"
    local output status

    set +e
    output=$(
        printf '%s' "$payload" \
            | env AI_HOOK_PROTOCOL=codex AI_HOOK_REPO_ROOT="$REPO_ROOT" bash "$REPO_ROOT/scripts/ai-hooks/$hook" 2>/dev/null
    )
    status=$?
    set -e

    if [ "$status" -ne 0 ]; then
        return 0
    fi
    if [ -z "$output" ]; then
        return 0
    fi
    if command -v jq >/dev/null 2>&1 &&
        printf '%s' "$output" | jq -e '.continue == true' >/dev/null 2>&1; then
        return 0
    fi
    if ! command -v jq >/dev/null 2>&1 && [ "$output" = '{"continue":true}' ]; then
        return 0
    fi
    if command -v jq >/dev/null 2>&1 &&
        printf '%s' "$output" | jq -e 'type == "object"' >/dev/null 2>&1; then
        printf '%s\n' "$output"
        exit 0
    fi
}

payload=$(cat 2>/dev/null || true)
[ -n "$payload" ] || {
    printf '{"continue":true}\n'
    exit 0
}

run_shared_hook commit-bypass-guard.sh "$payload"
run_shared_hook cargo-run-quiet.sh "$payload"

printf '{"continue":true}\n'
