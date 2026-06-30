#!/bin/bash

# PreToolUse Bash hook: block only confident, argv-level git commit bypasses.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ai-hooks/common.sh
. "$SCRIPT_DIR/common.sh"

AI_COMMIT_BYPASS_REASON="Git commit hook bypasses are not allowed. Stay on the feature branch, make a normal git commit, and let the pre-commit hook plus CI/make verify be the gate. Do not use --no-verify, -n, or --amend."

ai_strip_quoted_substrings() {
    local input="$1"
    local output=""
    local quote=""
    local char
    local i

    for ((i = 0; i < ${#input}; i += 1)); do
        char="${input:i:1}"
        if [ -n "$quote" ]; then
            if [ "$quote" = '"' ] && [ "$char" = "\\" ]; then
                i=$((i + 1))
                continue
            fi
            if [ "$char" = "$quote" ]; then
                quote=""
                output+=" "
            fi
            continue
        fi

        case "$char" in
            "'" | '"')
                quote="$char"
                output+=" "
                ;;
            \\)
                output+=" "
                i=$((i + 1))
                ;;
            *)
                output+="$char"
                ;;
        esac
    done

    [ -z "$quote" ] || return 1
    printf '%s\n' "$output"
}

ai_is_env_assignment() {
    [[ "${1:-}" =~ ^[A-Za-z_][A-Za-z0-9_]*=.*$ ]]
}

ai_commit_arg_takes_value() {
    case "$1" in
        -m | --message | -F | --file | -C | --reuse-message | -c | --reedit-message | \
            --author | --date | --fixup | --squash | --template | --pathspec-from-file | \
            --cleanup)
            return 0
            ;;
        --message=* | --file=* | --reuse-message=* | --reedit-message=* | --author=* | \
            --date=* | --fixup=* | --squash=* | --template=* | --pathspec-from-file=* | \
            --cleanup=*)
            return 2
            ;;
        *)
            return 1
            ;;
    esac
}

ai_segment_has_commit_bypass() {
    local segment="$1"
    local tokens=()
    local idx=0
    local len
    local token

    read -r -a tokens <<< "$segment"
    len="${#tokens[@]}"
    [ "$len" -gt 0 ] || return 1

    if [ "${tokens[$idx]}" = "env" ]; then
        idx=$((idx + 1))
    fi

    while [ "$idx" -lt "$len" ] && ai_is_env_assignment "${tokens[$idx]}"; do
        idx=$((idx + 1))
    done

    [ "$idx" -lt "$len" ] && [ "${tokens[$idx]}" = "git" ] || return 1
    idx=$((idx + 1))

    while [ "$idx" -lt "$len" ]; do
        token="${tokens[$idx]}"
        case "$token" in
            -c | -C | --git-dir | --work-tree | --namespace | --exec-path | --config-env | --super-prefix)
                idx=$((idx + 2))
                [ "$idx" -le "$len" ] || return 1
                ;;
            --git-dir=* | --work-tree=* | --namespace=* | --exec-path=* | --config-env=* | --super-prefix=*)
                idx=$((idx + 1))
                ;;
            -*)
                idx=$((idx + 1))
                ;;
            *)
                break
                ;;
        esac
    done

    [ "$idx" -lt "$len" ] && [ "${tokens[$idx]}" = "commit" ] || return 1
    idx=$((idx + 1))

    while [ "$idx" -lt "$len" ]; do
        token="${tokens[$idx]}"
        case "$token" in
            --)
                return 1
                ;;
            --no-verify | -n | --amend)
                return 0
                ;;
        esac

        ai_commit_arg_takes_value "$token"
        case "$?" in
            0)
                idx=$((idx + 2))
                [ "$idx" -le "$len" ] || return 1
                ;;
            2)
                idx=$((idx + 1))
                ;;
            *)
                idx=$((idx + 1))
                ;;
        esac
    done

    return 1
}

ai_command_has_commit_bypass() {
    local command="$1"
    local stripped segment

    stripped=$(ai_strip_quoted_substrings "$command") || return 1
    while IFS= read -r segment; do
        ai_segment_has_commit_bypass "$segment" && return 0
    done < <(printf '%s\n' "$stripped" | tr ';&|' '\n')

    return 1
}

main() {
    local command

    ai_read_payload PreToolUse || ai_emit_continue
    command=$(ai_payload_command "$AI_HOOK_PAYLOAD") || ai_emit_continue
    [ -n "$command" ] || ai_emit_continue

    if ai_command_has_commit_bypass "$command"; then
        ai_emit_block "$AI_COMMIT_BYPASS_REASON"
    fi

    ai_emit_continue
}

main "$@"
