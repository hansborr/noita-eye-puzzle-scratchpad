#!/bin/bash

# PreToolUse Bash hook: run narrow cargo verification commands inside the hook
# and rewrite the Bash tool call to a bounded summary. This keeps cargo logs out
# of the live Claude context without hiding failures.
#
# Wrapped commands: cargo test, cargo clippy, cargo build, cargo check, and
# cargo fmt --check. Compound commands, cargo run/watch/install, background
# calls, and any command containing a `--` program-argument separator are left
# unchanged.
#
# Disable with truthy NOITA_QUIET_OFF values (1, true, yes, on) in the hook
# environment, as an inline command prefix (`NOITA_QUIET_OFF=1 cargo check` or
# `env NOITA_QUIET_OFF=true cargo test`), or by creating .noita-quiet-off at the
# repo root. The hook is fail-open: malformed payloads, missing helper tools,
# parser uncertainty, or cache/fingerprint errors all emit continue so the
# original command runs unchanged.

set -u -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ai-hooks/common.sh
. "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(ai_repo_root "$SCRIPT_DIR")
AI_CARGO_SEPARATOR_TOKEN="__NOITA_AI_CARGO_SEPARATOR__"
AI_CARGO_QUIET_TTL="${AI_CARGO_QUIET_TTL:-3600}"
AI_CARGO_QUIET_TIMEOUT="${AI_CARGO_QUIET_TIMEOUT:-1200}"
AI_CARGO_QUIET_TAIL_LINES="${AI_CARGO_QUIET_TAIL_LINES:-40}"
AI_CARGO_QUIET_OFF_MARKER="${AI_CARGO_QUIET_OFF_MARKER:-$REPO_ROOT/.noita-quiet-off}"
AI_CARGO_CHILD_PID=""
AI_CARGO_ACTIVE_LABEL=""
AI_CARGO_ACTIVE_LOG=""
AI_CARGO_ACTIVE_START=0

ai_cargo_positive_integer_or_default() {
    local value="$1"
    local default="$2"

    if ai_is_integer "$value" && [ "$value" -gt 0 ]; then
        printf '%s\n' "$value"
    else
        printf '%s\n' "$default"
    fi
}

ai_cargo_is_truthy() {
    case "${1,,}" in
        1 | true | yes | on)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

ai_cargo_quiet_off() {
    ai_cargo_is_truthy "${NOITA_QUIET_OFF:-0}" || [ -f "$AI_CARGO_QUIET_OFF_MARKER" ]
}

ai_cargo_nonnegative_integer_or_default() {
    local value="$1"
    local default="$2"

    if ai_is_integer "$value" && [ "$value" -ge 0 ]; then
        printf '%s\n' "$value"
    else
        printf '%s\n' "$default"
    fi
}

ai_cargo_mark_command_separators() {
    local input="$1"
    local output=""
    local quote=""
    local char next
    local i

    for ((i = 0; i < ${#input}; i += 1)); do
        char="${input:i:1}"
        if [ -n "$quote" ]; then
            output+="$char"
            if [ "$quote" = '"' ] && [ "$char" = "\\" ]; then
                i=$((i + 1))
                if [ "$i" -lt "${#input}" ]; then
                    output+="${input:i:1}"
                fi
                continue
            fi
            if [ "$char" = "$quote" ]; then
                quote=""
            fi
            continue
        fi

        case "$char" in
            "'" | '"')
                quote="$char"
                output+="$char"
                ;;
            \\)
                output+="$char"
                i=$((i + 1))
                if [ "$i" -lt "${#input}" ]; then
                    output+="${input:i:1}"
                fi
                ;;
            ";" | $'\n')
                output+=" $AI_CARGO_SEPARATOR_TOKEN "
                ;;
            "&" | "|")
                next="${input:i + 1:1}"
                if [ "$next" = "$char" ]; then
                    i=$((i + 1))
                fi
                output+=" $AI_CARGO_SEPARATOR_TOKEN "
                ;;
            *)
                output+="$char"
                ;;
        esac
    done

    [ -z "$quote" ] || return 1
    printf '%s\n' "$output"
}

ai_cargo_tokenize_command() {
    local command="$1"
    local marked

    command -v xargs >/dev/null 2>&1 || return 1
    marked=$(ai_cargo_mark_command_separators "$command") || return 1
    [[ "$marked" =~ [^[:space:]] ]] || return 1
    printf '%s\n' "$marked" | xargs -n1 printf '%s\n' 2>/dev/null
}

ai_cargo_is_env_assignment() {
    [[ "${1:-}" =~ ^[A-Za-z_][A-Za-z0-9_]*=.*$ ]]
}

ai_cargo_inline_quiet_off() {
    local command="$1"
    local token_output token value
    local -a tokens=()
    local idx=0
    local saw_quiet=0
    local quiet_value=""

    token_output=$(ai_cargo_tokenize_command "$command") || return 1
    mapfile -t tokens <<< "$token_output"
    [ "${#tokens[@]}" -gt 0 ] || return 1

    if [ "${tokens[$idx]}" = "env" ]; then
        idx=$((idx + 1))
    fi
    while [ "$idx" -lt "${#tokens[@]}" ] && ai_cargo_is_env_assignment "${tokens[$idx]}"; do
        token="${tokens[$idx]}"
        if [[ "$token" == NOITA_QUIET_OFF=* ]]; then
            value="${token#NOITA_QUIET_OFF=}"
            saw_quiet=1
            quiet_value="$value"
        fi
        idx=$((idx + 1))
    done

    [ "$saw_quiet" -eq 1 ] || return 1
    ai_cargo_is_truthy "$quiet_value"
}

ai_cargo_has_unsafe_shell_syntax() {
    local backtick dollar_paren

    backtick='`'
    dollar_paren="\$("
    case "$1" in
        *"$backtick"* | *"$dollar_paren"* | *'<'* | *'>'*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

ai_cargo_command_label() {
    local command="$1"
    local token_output token subcommand
    local -a tokens=()
    local idx=0
    local saw_fmt_check=0

    ai_cargo_has_unsafe_shell_syntax "$command" && return 1
    token_output=$(ai_cargo_tokenize_command "$command") || return 2
    mapfile -t tokens <<< "$token_output"
    [ "${#tokens[@]}" -gt 0 ] || return 1

    for token in "${tokens[@]}"; do
        [ "$token" = "$AI_CARGO_SEPARATOR_TOKEN" ] && return 1
    done

    if [ "${tokens[$idx]}" = "env" ]; then
        idx=$((idx + 1))
    fi
    while [ "$idx" -lt "${#tokens[@]}" ] && ai_cargo_is_env_assignment "${tokens[$idx]}"; do
        idx=$((idx + 1))
    done

    [ "$idx" -lt "${#tokens[@]}" ] || return 1
    [ "${tokens[$idx]}" = "cargo" ] || return 1
    idx=$((idx + 1))
    [ "$idx" -lt "${#tokens[@]}" ] || return 1

    subcommand="${tokens[$idx]}"
    case "$subcommand" in
        test | clippy | build | check | fmt)
            ;;
        *)
            return 1
            ;;
    esac
    idx=$((idx + 1))

    while [ "$idx" -lt "${#tokens[@]}" ]; do
        token="${tokens[$idx]}"
        case "$token" in
            -- | --fix | --allow-dirty | --allow-staged)
                return 1
                ;;
            --check)
                [ "$subcommand" = "fmt" ] && saw_fmt_check=1
                ;;
        esac
        idx=$((idx + 1))
    done

    if [ "$subcommand" = "fmt" ] && [ "$saw_fmt_check" -ne 1 ]; then
        return 1
    fi

    if [ "$subcommand" = "fmt" ]; then
        printf 'cargo fmt --check\n'
    else
        printf 'cargo %s\n' "$subcommand"
    fi
}

ai_cargo_untracked_file_hashes() {
    local path hash

    while IFS= read -r -d '' path; do
        hash=$(git -C "$REPO_ROOT" hash-object --no-filters -- "$REPO_ROOT/$path" 2>/dev/null) \
            || return 1
        printf '%s  %s\n' "$hash" "$path"
    done < <(git -C "$REPO_ROOT" ls-files --others --exclude-standard -z 2>/dev/null)
}

ai_cargo_worktree_fingerprint() {
    {
        printf 'RUSTC_VERSION\n'
        rustc -vV 2>/dev/null || printf 'rustc unavailable\n'
        printf '\nRELEVANT_ENV\n'
        env | LC_ALL=C sort | awk -F= '
            /^(RUSTFLAGS|RUSTDOCFLAGS|RUSTC|RUSTUP_TOOLCHAIN|CARGO|CARGO_[A-Za-z0-9_]*|CARGO_TARGET_[A-Za-z0-9_]*|CARGO_BUILD_[A-Za-z0-9_]*|CARGO_PROFILE_[A-Za-z0-9_]*|CARGO_INCREMENTAL)=/ {
                print
            }
        '
        printf '\nWORKTREE\n'
        printf 'HEAD\n'
        git -C "$REPO_ROOT" rev-parse --verify HEAD 2>/dev/null || printf 'NO_HEAD\n'
        printf '\nINDEX_DIFF\n'
        git -C "$REPO_ROOT" diff --cached --no-ext-diff --binary -- . 2>/dev/null || exit 1
        printf '\nWORKTREE_DIFF\n'
        git -C "$REPO_ROOT" diff --no-ext-diff --binary -- . 2>/dev/null || exit 1
        printf '\nUNTRACKED_FILE_HASHES\n'
        ai_cargo_untracked_file_hashes | LC_ALL=C sort || exit 1
    } | sha256sum | awk '{print $1}'
}

ai_cargo_state_dir() {
    printf '%s\n' "${AI_CARGO_QUIET_STATE_DIR:-$(ai_state_root)/cargo-run-quiet}"
}

ai_cargo_marker_name() {
    local command="$1"
    local key

    key=$(printf '%s' "$command" | ai_hash_text) || return 1
    [ -n "$key" ] || return 1
    printf 'last.%s\n' "$key"
}

ai_cargo_read_marker() {
    local marker="$1"
    local saw_ts=0 saw_fp=0 saw_elapsed=0

    AI_CARGO_MARKER_TS=0
    AI_CARGO_MARKER_FP=""
    AI_CARGO_MARKER_ELAPSED=0

    [ -f "$marker" ] || return 1
    while IFS='=' read -r key value; do
        case "$key" in
            LAST_TS) AI_CARGO_MARKER_TS="$value"; saw_ts=1 ;;
            LAST_FP) AI_CARGO_MARKER_FP="$value"; saw_fp=1 ;;
            LAST_ELAPSED) AI_CARGO_MARKER_ELAPSED="$value"; saw_elapsed=1 ;;
            *) return 1 ;;
        esac
    done < "$marker"

    [ "$saw_ts" -eq 1 ] || return 1
    [ "$saw_fp" -eq 1 ] || return 1
    [ "$saw_elapsed" -eq 1 ] || return 1
    ai_is_integer "$AI_CARGO_MARKER_TS" || return 1
    ai_is_integer "$AI_CARGO_MARKER_ELAPSED" || return 1
    [[ "$AI_CARGO_MARKER_FP" =~ ^[0-9a-f]{64}$ ]] || return 1
}

ai_cargo_write_marker() {
    local marker="$1"
    local fingerprint="$2"
    local elapsed="$3"
    local dir base tmp

    dir=$(dirname -- "$marker")
    base=$(basename -- "$marker")
    mkdir -p -- "$dir" || return 1
    tmp=$(mktemp "$dir/.${base}.tmp.XXXXXX") || return 1
    if ! {
        printf 'LAST_TS=%s\n' "$(date +%s)"
        printf 'LAST_FP=%s\n' "$fingerprint"
        printf 'LAST_ELAPSED=%s\n' "$elapsed"
    } > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    mv -f -- "$tmp" "$marker" || {
        rm -f -- "$tmp"
        return 1
    }
}

ai_cargo_tail_log() {
    local log="$1"
    local lines="$2"

    tail -n "$lines" "$log" 2>/dev/null || true
}

ai_cargo_failure_summary() {
    local label="$1"
    local log="$2"
    local exit_status="$3"
    local elapsed="$4"
    local lines="$5"

    printf '%s failed (exit %s, %ss). Full log: %s\n\n--- last %s lines ---\n%s\n' \
        "$label" "$exit_status" "$elapsed" "$log" "$lines" "$(ai_cargo_tail_log "$log" "$lines")"
}

ai_cargo_timeout_summary() {
    local label="$1"
    local log="$2"
    local elapsed="$3"
    local lines="$4"

    printf '%s timed out or was interrupted after %ss. Full log: %s\n\n--- last %s lines ---\n%s\n' \
        "$label" "$elapsed" "$log" "$lines" "$(ai_cargo_tail_log "$log" "$lines")"
}

ai_cargo_emit_result_command() {
    local message="$1"
    local exit_status="$2"
    local state_dir result_file quoted_file command

    if [ "$(ai_hook_protocol)" = "codex" ]; then
        if [ "$exit_status" -eq 0 ]; then
            ai_emit_block "$message"
        fi
        ai_emit_block "$message"
    fi

    state_dir=$(ai_cargo_state_dir) || ai_emit_continue
    mkdir -p -- "$state_dir" || ai_emit_continue
    result_file=$(mktemp "$state_dir/result.XXXXXX") || ai_emit_continue
    if ! printf '%s\n' "$message" > "$result_file"; then
        rm -f -- "$result_file"
        ai_emit_continue
    fi

    printf -v quoted_file '%q' "$result_file"
    if [ "$exit_status" -eq 0 ]; then
        command="cat $quoted_file; rm -f $quoted_file"
    else
        command="cat $quoted_file; status=$exit_status; rm -f $quoted_file; exit \"\$status\""
    fi
    ai_claude_updated_command "$command"
}

ai_cargo_payload_timeout_millis() {
    local payload="$1"
    local value

    value=$(
        printf '%s' "$payload" \
            | jq -er '.tool_input.timeout? // empty
                | if type == "number" then tostring
                  elif type == "string" then .
                  else empty
                  end' 2>/dev/null
    ) || return 1
    ai_is_integer "$value" || return 1
    [ "$value" -gt 0 ] || return 1
    printf '%s\n' "$value"
}

ai_cargo_effective_timeout_seconds() {
    local quiet_seconds="$1"
    local quiet_millis effective_millis caller_millis seconds millis

    quiet_millis=$((quiet_seconds * 1000))
    effective_millis="$quiet_millis"
    if caller_millis=$(ai_cargo_payload_timeout_millis "$AI_HOOK_PAYLOAD" 2>/dev/null); then
        if [ "$caller_millis" -lt "$effective_millis" ]; then
            effective_millis="$caller_millis"
        fi
    fi

    seconds=$((effective_millis / 1000))
    millis=$((effective_millis % 1000))
    if [ "$millis" -eq 0 ]; then
        printf '%s\n' "$seconds"
    else
        printf '%s.%03d\n' "$seconds" "$millis"
    fi
}

# shellcheck disable=SC2317
ai_cargo_on_signal() {
    local elapsed summary

    if [ -n "$AI_CARGO_CHILD_PID" ]; then
        kill -TERM "$AI_CARGO_CHILD_PID" 2>/dev/null || true
        wait "$AI_CARGO_CHILD_PID" 2>/dev/null || true
    fi

    elapsed=$(( $(date +%s) - AI_CARGO_ACTIVE_START ))
    summary=$(ai_cargo_timeout_summary \
        "$AI_CARGO_ACTIVE_LABEL" \
        "$AI_CARGO_ACTIVE_LOG" \
        "$elapsed" \
        "$(ai_cargo_positive_integer_or_default "$AI_CARGO_QUIET_TAIL_LINES" 40)")
    ai_cargo_emit_result_command "$summary" 124
}

ai_cargo_run_command() {
    local command="$1"
    local log="$2"
    local timeout_seconds="$3"
    local exit_status

    command -v timeout >/dev/null 2>&1 || return 125
    trap ai_cargo_on_signal INT TERM
    timeout --kill-after=10s "${timeout_seconds}s" bash -c "$command" > "$log" 2>&1 &
    AI_CARGO_CHILD_PID=$!
    wait "$AI_CARGO_CHILD_PID"
    exit_status=$?
    AI_CARGO_CHILD_PID=""
    trap - INT TERM
    return "$exit_status"
}

main() {
    local command background label state_dir marker_name marker fingerprint now age ttl
    local key log start elapsed timeout_seconds tail_lines exit_status summary message

    ai_read_payload PreToolUse || ai_emit_continue
    command=$(ai_payload_command "$AI_HOOK_PAYLOAD") || ai_emit_continue
    [ -n "$command" ] || ai_emit_continue
    background=$(ai_payload_background "$AI_HOOK_PAYLOAD" 2>/dev/null || printf 'false')
    [ "$background" = "true" ] && ai_emit_continue
    ai_cargo_quiet_off && ai_emit_continue
    ai_cargo_inline_quiet_off "$command" && ai_emit_continue

    label=$(ai_cargo_command_label "$command") || ai_emit_continue
    command -v git >/dev/null 2>&1 || ai_emit_continue
    command -v sha256sum >/dev/null 2>&1 || ai_emit_continue
    command -v awk >/dev/null 2>&1 || ai_emit_continue
    command -v tail >/dev/null 2>&1 || ai_emit_continue
    command -v mktemp >/dev/null 2>&1 || ai_emit_continue
    command -v timeout >/dev/null 2>&1 || ai_emit_continue

    cd "$REPO_ROOT" || ai_emit_continue
    state_dir=$(ai_cargo_state_dir) || ai_emit_continue
    mkdir -p -- "$state_dir" || ai_emit_continue
    marker_name=$(ai_cargo_marker_name "$command") || ai_emit_continue
    marker="$state_dir/$marker_name"
    key="${marker_name#last.}"
    log="$state_dir/$key.log"

    fingerprint=$(ai_cargo_worktree_fingerprint) || ai_emit_continue
    [ -n "$fingerprint" ] || ai_emit_continue
    ttl=$(ai_cargo_nonnegative_integer_or_default "$AI_CARGO_QUIET_TTL" 3600)
    now=$(date +%s)

    if ai_cargo_read_marker "$marker"; then
        age=$((now - AI_CARGO_MARKER_TS))
        if [ "$age" -ge 0 ] \
            && [ "$age" -lt "$ttl" ] \
            && [ "$AI_CARGO_MARKER_FP" = "$fingerprint" ]; then
            message="$label OK (cached; previous ${AI_CARGO_MARKER_ELAPSED}s, ${age}s ago, unchanged worktree/env)"
            ai_cargo_emit_result_command "$message" 0
        fi
    fi

    timeout_seconds=$(ai_cargo_effective_timeout_seconds \
        "$(ai_cargo_positive_integer_or_default "$AI_CARGO_QUIET_TIMEOUT" 1200)") || ai_emit_continue
    tail_lines=$(ai_cargo_positive_integer_or_default "$AI_CARGO_QUIET_TAIL_LINES" 40)
    start=$(date +%s)
    AI_CARGO_ACTIVE_LABEL="$label"
    AI_CARGO_ACTIVE_LOG="$log"
    AI_CARGO_ACTIVE_START="$start"
    ai_cargo_run_command "$command" "$log" "$timeout_seconds"
    exit_status=$?
    elapsed=$(( $(date +%s) - start ))

    if [ "$exit_status" -eq 0 ]; then
        ai_cargo_write_marker "$marker" "$fingerprint" "$elapsed" || ai_emit_continue
        message="$label OK (${elapsed}s)"
        ai_cargo_emit_result_command "$message" 0
    fi

    if [ "$exit_status" -eq 124 ] || [ "$exit_status" -eq 125 ]; then
        summary=$(ai_cargo_timeout_summary "$label" "$log" "$elapsed" "$tail_lines")
    else
        summary=$(ai_cargo_failure_summary "$label" "$log" "$exit_status" "$elapsed" "$tail_lines")
    fi
    ai_cargo_emit_result_command "$summary" "$exit_status"
}

main "$@"
