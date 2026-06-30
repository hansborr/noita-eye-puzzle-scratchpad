#!/bin/bash

# Shared helpers for Claude Code hook bodies. Hook callers should treat a
# non-zero helper result as fail-open and emit ai_emit_continue.

ai_have_jq() {
    command -v jq >/dev/null 2>&1
}

ai_repo_root() {
    local from="${1:-$PWD}"

    if [ -n "${AI_HOOK_REPO_ROOT:-}" ]; then
        printf '%s\n' "$AI_HOOK_REPO_ROOT"
        return 0
    fi

    if [ -n "${CLAUDE_PROJECT_DIR:-}" ]; then
        git -C "$CLAUDE_PROJECT_DIR" rev-parse --show-toplevel 2>/dev/null \
            || printf '%s\n' "$CLAUDE_PROJECT_DIR"
        return 0
    fi

    git -C "$from" rev-parse --show-toplevel 2>/dev/null \
        || git rev-parse --show-toplevel 2>/dev/null \
        || pwd
}

ai_emit_continue() {
    printf '{"continue":true}\n'
    exit 0
}

ai_emit_block() {
    ai_emit_deny "$1"
}

ai_emit_deny() {
    local reason="$1"
    local event="${AI_HOOK_EVENT_NAME:-PreToolUse}"

    ai_have_jq || ai_emit_continue
    jq -n --arg event "$event" --arg reason "$reason" \
        '{hookSpecificOutput:{hookEventName:$event,permissionDecision:"deny",permissionDecisionReason:$reason}}' \
        || ai_emit_continue
    exit 0
}

ai_emit_context() {
    local event text

    if [ "$#" -eq 1 ]; then
        event="${AI_HOOK_EVENT_NAME:-PreToolUse}"
        text="$1"
    else
        event="$1"
        text="$2"
    fi

    ai_have_jq || ai_emit_continue
    jq -n --arg event "$event" --arg text "$text" \
        '{hookSpecificOutput:{hookEventName:$event,additionalContext:$text}}' \
        || ai_emit_continue
    exit 0
}

ai_emit_additional_context() {
    ai_emit_context "$@"
}

ai_claude_updated_command() {
    local command="$1"
    local payload="${AI_HOOK_PAYLOAD:-}"

    ai_have_jq || ai_emit_continue
    if [ -n "$payload" ] \
        && printf '%s' "$payload" | jq -e '.tool_input | type == "object"' >/dev/null 2>&1; then
        printf '%s' "$payload" | jq -c --arg command "$command" '{
            hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "allow",
                updatedInput: (.tool_input + {command: $command})
            }
        }' || ai_emit_continue
    else
        jq -n --arg command "$command" '{
            hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "allow",
                updatedInput: {command: $command}
            }
        }' || ai_emit_continue
    fi
    exit 0
}

ai_claude_result_command() {
    local message="$1"
    local prefix="$2"
    local result_file quoted_file

    result_file=$(mktemp "$prefix.XXXXXX") || ai_emit_continue
    if ! printf '%s\n' "$message" > "$result_file"; then
        rm -f -- "$result_file"
        ai_emit_continue
    fi

    printf -v quoted_file '%q' "$result_file"
    ai_claude_updated_command "cat $quoted_file; rm -f $quoted_file"
}

ai_json_escape() {
    local value="$1"

    ai_have_jq || return 1
    jq -Rn --arg value "$value" '$value'
}

ai_read_payload() {
    AI_HOOK_PAYLOAD=""
    AI_HOOK_EVENT_NAME=""

    ai_have_jq || return 1
    AI_HOOK_PAYLOAD=$(cat 2>/dev/null || true)
    [ -n "$AI_HOOK_PAYLOAD" ] || return 1

    printf '%s' "$AI_HOOK_PAYLOAD" | jq -e 'type == "object"' >/dev/null 2>&1 \
        || return 1

    AI_HOOK_EVENT_NAME=$(
        printf '%s' "$AI_HOOK_PAYLOAD" \
            | jq -r '.hook_event_name? // .hookEventName? // empty | strings' 2>/dev/null \
            || true
    )
    [ -n "$AI_HOOK_EVENT_NAME" ] || AI_HOOK_EVENT_NAME="${1:-PreToolUse}"
}

ai_payload_tool_name() {
    local payload="$1"

    printf '%s' "$payload" | jq -er '.tool_name? // empty | strings' 2>/dev/null
}

ai_payload_command() {
    local payload="$1"

    printf '%s' "$payload" | jq -er '.tool_input.command | strings' 2>/dev/null
}

ai_payload_background() {
    local payload="$1"

    printf '%s' "$payload" | jq -r '.tool_input.run_in_background? // false' 2>/dev/null
}

ai_payload_file_path() {
    local payload="$1"

    printf '%s' "$payload" | jq -er '.tool_input.file_path | strings' 2>/dev/null
}

ai_payload_session_id() {
    local payload="$1"

    printf '%s' "$payload" \
        | jq -er '.session_id? // .sessionId? // empty | strings' 2>/dev/null
}

ai_now() {
    printf '%s\n' "${AI_FAKE_NOW:-$(date +%s)}"
}

ai_is_integer() {
    [[ "${1:-}" =~ ^-?[0-9]+$ ]]
}

ai_state_root() {
    printf '%s\n' "${AI_HOOKS_STATE_DIR:-${TMPDIR:-/tmp}/noita-ai-hooks}"
}

ai_hash_text() {
    sha256sum 2>/dev/null | awk '{print $1}'
}
