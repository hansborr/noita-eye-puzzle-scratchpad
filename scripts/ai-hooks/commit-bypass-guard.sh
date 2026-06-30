#!/bin/bash

# PreToolUse Bash hook: block only confident, argv-level git commit bypasses.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ai-hooks/common.sh
. "$SCRIPT_DIR/common.sh"

AI_COMMIT_BYPASS_REASON="Git commit hook bypasses are not allowed. Stay on the feature branch, make a normal git commit, and let the pre-commit hook plus CI/make verify be the gate. Do not use --no-verify, -n, or --amend."
AI_COMMAND_SEPARATOR_TOKEN="__NOITA_AI_HOOK_COMMAND_SEPARATOR__"

ai_mark_command_separators() {
    local input="$1"
    local output=""
    local quote=""
    local char
    local next
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
                output+=" $AI_COMMAND_SEPARATOR_TOKEN "
                ;;
            "&" | "|")
                next="${input:i + 1:1}"
                if [ "$next" = "$char" ]; then
                    i=$((i + 1))
                fi
                output+=" $AI_COMMAND_SEPARATOR_TOKEN "
                ;;
            *)
                output+="$char"
                ;;
        esac
    done

    [ -z "$quote" ] || return 1
    printf '%s\n' "$output"
}

ai_tokenize_command() {
    local command="$1"
    local marked
    local tokens

    command -v xargs >/dev/null 2>&1 || return 1
    marked=$(ai_mark_command_separators "$command") || return 1
    [[ "$marked" =~ [^[:space:]] ]] || return 0
    tokens=$(printf '%s\n' "$marked" | xargs -n1 printf '%s\n' 2>/dev/null) || return 1
    printf '%s\n' "$tokens"
}

ai_is_command_separator() {
    [ "${1:-}" = "$AI_COMMAND_SEPARATOR_TOKEN" ]
}

ai_is_env_assignment() {
    [[ "${1:-}" =~ ^[A-Za-z_][A-Za-z0-9_]*=.*$ ]]
}

ai_is_git_hooks_path_config() {
    local config="${1:-}"
    local key="${config%%=*}"

    [ "$config" != "$key" ] || return 1
    [ "${key,,}" = "core.hookspath" ]
}

ai_commit_arg_value_mode() {
    case "$1" in
        -m | --message | -F | --file | -C | --reuse-message | -c | --reedit-message | \
            --reedit | --author | --date | --fixup | --squash | --template | \
            --pathspec-from-file | --cleanup)
            return 0
            ;;
        --message=* | --file=* | --reuse-message=* | --reedit-message=* | --author=* | \
            --reedit=* | --date=* | --fixup=* | --squash=* | --gpg-sign=* | -S?* | \
            --template=* | --pathspec-from-file=* | --cleanup=*)
            return 2
            ;;
        --gpg-sign | -S)
            return 3
            ;;
        *)
            return 1
            ;;
    esac
}

ai_commit_args_have_bypass() {
    local -n commit_tokens="$1"
    local idx=0
    local len
    local token

    idx="$2"
    len="${#commit_tokens[@]}"
    while [ "$idx" -lt "$len" ]; do
        token="${commit_tokens[$idx]}"
        ai_is_command_separator "$token" && return 1
        case "$token" in
            --)
                return 1
                ;;
            --no-verify | --amend)
                return 0
                ;;
        esac

        ai_commit_arg_value_mode "$token"
        case "$?" in
            0)
                idx=$((idx + 1))
                [ "$idx" -lt "$len" ] || return 2
                ai_is_command_separator "${commit_tokens[$idx]}" && return 2
                idx=$((idx + 1))
                continue
                ;;
            2)
                idx=$((idx + 1))
                continue
                ;;
            3)
                idx=$((idx + 1))
                if [ "$idx" -lt "$len" ] \
                    && ! ai_is_command_separator "${commit_tokens[$idx]}" \
                    && [[ "${commit_tokens[$idx]}" != -* ]]; then
                    idx=$((idx + 1))
                fi
                continue
                ;;
        esac

        if [[ "$token" =~ ^-[A-Za-z]+$ && "$token" == *n* ]]; then
            return 0
        fi

        idx=$((idx + 1))
    done

    return 1
}

ai_tokens_segment_has_commit_bypass() {
    local tokens_name="$1"
    local -n segment_tokens="$tokens_name"
    local idx="$2"
    local len
    local token
    local config_value

    len="${#segment_tokens[@]}"
    [ "$idx" -lt "$len" ] || return 1

    if [ "${segment_tokens[$idx]}" = "env" ]; then
        idx=$((idx + 1))
    fi

    while [ "$idx" -lt "$len" ] && ai_is_env_assignment "${segment_tokens[$idx]}"; do
        idx=$((idx + 1))
    done

    [ "$idx" -lt "$len" ] && [ "${segment_tokens[$idx]}" = "git" ] || return 1
    idx=$((idx + 1))

    while [ "$idx" -lt "$len" ]; do
        token="${segment_tokens[$idx]}"
        ai_is_command_separator "$token" && return 1

        case "$token" in
            commit)
                idx=$((idx + 1))
                ai_commit_args_have_bypass "$tokens_name" "$idx"
                return "$?"
                ;;
            -c | --config)
                idx=$((idx + 1))
                [ "$idx" -lt "$len" ] || return 2
                ai_is_command_separator "${segment_tokens[$idx]}" && return 2
                ai_is_git_hooks_path_config "${segment_tokens[$idx]}" && return 0
                idx=$((idx + 1))
                ;;
            --config=*)
                config_value="${token#--config=}"
                ai_is_git_hooks_path_config "$config_value" && return 0
                idx=$((idx + 1))
                ;;
            -C | --git-dir | --work-tree | --namespace | --exec-path | --config-env | --super-prefix)
                idx=$((idx + 1))
                [ "$idx" -lt "$len" ] || return 2
                ai_is_command_separator "${segment_tokens[$idx]}" && return 2
                idx=$((idx + 1))
                ;;
            --git-dir=* | --work-tree=* | --namespace=* | --exec-path=* | --config-env=* | \
                --super-prefix=*)
                idx=$((idx + 1))
                ;;
            -p | --paginate | -P | --no-pager | --bare | --no-replace-objects | \
                --literal-pathspecs | --glob-pathspecs | --noglob-pathspecs | \
                --icase-pathspecs | --no-optional-locks)
                idx=$((idx + 1))
                ;;
            --)
                idx=$((idx + 1))
                ;;
            -*)
                return 2
                ;;
            *)
                return 1
                ;;
        esac
    done

    return 1
}

ai_command_has_commit_bypass() {
    local command="$1"
    local token_output
    local tokens=()
    local idx=0
    local len
    local status

    token_output=$(ai_tokenize_command "$command") || return 1
    if [ -n "$token_output" ]; then
        mapfile -t tokens <<< "$token_output"
    fi
    len="${#tokens[@]}"

    while [ "$idx" -lt "$len" ]; do
        while [ "$idx" -lt "$len" ] && ai_is_command_separator "${tokens[$idx]}"; do
            idx=$((idx + 1))
        done

        ai_tokens_segment_has_commit_bypass tokens "$idx"
        status="$?"
        case "$status" in
            0)
                return 0
                ;;
            2)
                return 1
                ;;
        esac

        while [ "$idx" -lt "$len" ] && ! ai_is_command_separator "${tokens[$idx]}"; do
            idx=$((idx + 1))
        done
    done

    return 1
}

main() {
    local command

    ai_read_payload PreToolUse || ai_emit_continue
    command=$(ai_payload_command "$AI_HOOK_PAYLOAD") || ai_emit_continue
    [ -n "$command" ] || ai_emit_continue

    if ai_command_has_commit_bypass "$command"; then
        ai_emit_deny "$AI_COMMIT_BYPASS_REASON"
    fi

    ai_emit_continue
}

main "$@"
