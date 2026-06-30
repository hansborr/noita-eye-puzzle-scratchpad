#!/bin/bash

# PostToolUse Edit|Write hook: run rustfmt on the edited Rust file only.
# Advisory-only and fail-open: no block decisions, no exit 2, and no formatting
# outside this repository. clippy --fix is intentionally skipped because it can
# be slow and can mutate broader compiler state than a single-file save format.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ai-hooks/common.sh
. "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(realpath -m -- "$(ai_repo_root "$SCRIPT_DIR")" 2>/dev/null || ai_repo_root "$SCRIPT_DIR")
AI_TIDY_ON_EDIT_MAX_OUTPUT_LINES="${AI_TIDY_ON_EDIT_MAX_OUTPUT_LINES:-30}"

ai_tidy_on_edit_state_dir() {
    printf '%s\n' "${AI_TIDY_ON_EDIT_STATE_DIR:-$(ai_state_root)/tidy-on-edit}"
}

ai_tidy_positive_integer_or_default() {
    local value="$1"
    local default="$2"

    if ai_is_integer "$value" && [ "$value" -gt 0 ]; then
        printf '%s\n' "$value"
    else
        printf '%s\n' "$default"
    fi
}

ai_tidy_tool_succeeded() {
    local payload="$1"
    local success

    success=$(
        printf '%s' "$payload" \
            | jq -r '(.tool_response? // .tool_output? // {}) as $response
                | if ($response | type) == "object" and ($response | has("success")) then
                    $response.success
                else
                    true
                end' 2>/dev/null
    ) || return 1
    [ "$success" = "true" ]
}

ai_tidy_absolute_path() {
    local path="$1"

    case "$path" in
        /*) realpath -m -- "$path" ;;
        *) realpath -m -- "$REPO_ROOT/$path" ;;
    esac
}

ai_tidy_relative_path() {
    local absolute_path="$1"

    if [ "$absolute_path" = "$REPO_ROOT" ]; then
        printf '.\n'
    else
        printf '%s\n' "${absolute_path#"$REPO_ROOT"/}"
    fi
}

ai_tidy_resolve_rust_file() {
    local requested_path="$1"
    local absolute_path real_path

    case "$requested_path" in
        *.rs) ;;
        *) return 1 ;;
    esac

    absolute_path=$(ai_tidy_absolute_path "$requested_path") || return 1
    case "$absolute_path" in
        "$REPO_ROOT"/*) ;;
        *) return 1 ;;
    esac

    [ -f "$absolute_path" ] || return 1
    real_path=$(realpath -- "$absolute_path" 2>/dev/null) || return 1
    case "$real_path" in
        "$REPO_ROOT"/*) ;;
        *) return 1 ;;
    esac

    printf '%s\n' "$absolute_path"
}

ai_tidy_file_hash() {
    local absolute_path="$1"

    git -C "$REPO_ROOT" hash-object --no-filters -- "$absolute_path" 2>/dev/null
}

ai_tidy_state_file() {
    local relative_path="$1"
    local session material fingerprint state_dir

    session=$(ai_payload_session_id "$AI_HOOK_PAYLOAD" 2>/dev/null || printf 'no-session')
    [ -n "$session" ] || session="no-session"
    material="$REPO_ROOT:$session:$relative_path"
    fingerprint=$(printf '%s' "$material" | ai_hash_text) || return 1
    state_dir=$(ai_tidy_on_edit_state_dir) || return 1
    printf '%s/%s\n' "$state_dir" "$fingerprint"
}

ai_tidy_seen_current_hash() {
    local state_file="$1"
    local current_hash="$2"
    local key value

    [ -f "$state_file" ] || return 1
    while IFS='=' read -r key value; do
        case "$key" in
            LAST_HASH)
                [ "$value" = "$current_hash" ] && return 0
                return 1
                ;;
            *)
                return 1
                ;;
        esac
    done < "$state_file"

    return 1
}

ai_tidy_write_hash() {
    local state_file="$1"
    local current_hash="$2"
    local dir base tmp

    dir=$(dirname -- "$state_file")
    base=$(basename -- "$state_file")
    mkdir -p -- "$dir" || return 1
    tmp=$(mktemp "$dir/.${base}.tmp.XXXXXX") || return 1
    if ! printf 'LAST_HASH=%s\n' "$current_hash" > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    mv -f -- "$tmp" "$state_file" || {
        rm -f -- "$tmp"
        return 1
    }
}

ai_tidy_bounded_tail() {
    local text="$1"
    local max_lines
    local line_count

    max_lines=$(ai_tidy_positive_integer_or_default "$AI_TIDY_ON_EDIT_MAX_OUTPUT_LINES" 30)
    line_count=$(printf '%s\n' "$text" | wc -l | tr -d ' ')
    if [ "$line_count" -gt "$max_lines" ]; then
        printf '... truncated (%s lines total; last %s lines) ...\n' "$line_count" "$max_lines"
        printf '%s\n' "$text" | tail -n "$max_lines"
    else
        printf '%s' "$text"
    fi
}

main() {
    local tool_name requested_path absolute_path relative_path state_file before_hash after_hash
    local rustfmt_output rustfmt_status message

    ai_read_payload PostToolUse || ai_emit_continue
    tool_name=$(ai_payload_tool_name "$AI_HOOK_PAYLOAD" 2>/dev/null || printf '')
    case "$tool_name" in
        Edit | Write) ;;
        *) ai_emit_continue ;;
    esac

    ai_tidy_tool_succeeded "$AI_HOOK_PAYLOAD" || ai_emit_continue
    requested_path=$(ai_payload_file_path "$AI_HOOK_PAYLOAD") || ai_emit_continue
    absolute_path=$(ai_tidy_resolve_rust_file "$requested_path") || ai_emit_continue
    relative_path=$(ai_tidy_relative_path "$absolute_path")
    before_hash=$(ai_tidy_file_hash "$absolute_path") || ai_emit_continue
    [ -n "$before_hash" ] || ai_emit_continue
    state_file=$(ai_tidy_state_file "$relative_path") || ai_emit_continue
    ai_tidy_seen_current_hash "$state_file" "$before_hash" && ai_emit_continue

    command -v rustfmt >/dev/null 2>&1 || ai_emit_continue
    cd "$REPO_ROOT" || ai_emit_continue

    rustfmt_output=$(rustfmt "$absolute_path" 2>&1)
    rustfmt_status=$?
    after_hash=$(ai_tidy_file_hash "$absolute_path") || ai_emit_continue
    [ -n "$after_hash" ] || ai_emit_continue
    ai_tidy_write_hash "$state_file" "$after_hash" || true

    if [ "$rustfmt_status" -ne 0 ]; then
        message=$(printf 'tidy-on-edit: %s rustfmt ERROR (non-blocking)' "$relative_path")
        if [ -n "$rustfmt_output" ]; then
            message="${message}"$'\n'"--- rustfmt output ---"$'\n'"$(ai_tidy_bounded_tail "$rustfmt_output")"
        fi
        ai_emit_additional_context "PostToolUse" "$message"
    fi

    if [ "$before_hash" != "$after_hash" ]; then
        ai_emit_additional_context "PostToolUse" "tidy-on-edit: $relative_path rustfmt applied"
    fi

    ai_emit_continue
}

main "$@"
