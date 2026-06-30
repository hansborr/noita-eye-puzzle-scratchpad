#!/bin/bash

# PreToolUse Edit|Write hook: non-blocking, throttled advisories for guardrails.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ai-hooks/common.sh
. "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(ai_repo_root "$SCRIPT_DIR")

ai_protected_files_ttl() {
    local value="${AI_PROTECTED_FILES_TTL:-1800}"

    if ai_is_integer "$value" && [ "$value" -ge 0 ]; then
        printf '%s\n' "$value"
    else
        printf '1800\n'
    fi
}

ai_repo_relative_path() {
    local path="$1"
    local root_real path_real

    root_real=$(realpath -m -- "$REPO_ROOT" 2>/dev/null || printf '%s\n' "$REPO_ROOT")
    case "$path" in
        /*) path_real=$(realpath -m -- "$path" 2>/dev/null || printf '%s\n' "$path") ;;
        *) path_real=$(realpath -m -- "$REPO_ROOT/$path" 2>/dev/null || printf '%s\n' "$REPO_ROOT/$path") ;;
    esac

    case "$path_real" in
        "$root_real"/*) printf '%s\n' "${path_real#"$root_real"/}" ;;
        "$root_real") printf '.\n' ;;
        *) printf '%s\n' "$path" ;;
    esac
}

ai_protected_file_entry() {
    local rel="$1"
    local key advisory

    case "$rel" in
        Cargo.toml | Cargo.lock)
            key="dependency-surface"
            advisory="dependency surface: justify the crate; keep cargo-deny + cargo-machete green; lockfile changes must be deliberate"
            ;;
        deny.toml | clippy.toml | rustfmt.toml | rust-toolchain.toml)
            key="policy-floor"
            advisory="lint/supply-chain/toolchain policy: changing this moves the guardrail floor"
            ;;
        .claude/* | .codex/* | .githooks/* | scripts/check-*.sh | scripts/ai-hooks/*)
            key="guardrails"
            advisory="you are editing the guardrails themselves; cover changes with scripts/tests and shellcheck"
            ;;
        src/data/corpus.rs)
            key="verified-corpus"
            advisory="Experiment-0-verified corpus: any change must stay byte-for-byte cross-checked (see AGENTS.md golden rules)"
            ;;
        research/data/*)
            key="embedded-fixture"
            advisory="embedded fixture (include_str!): keep tests/goldens in sync"
            ;;
        *)
            return 1
            ;;
    esac

    printf '%s\t%s\n' "$key" "$advisory"
}

ai_protected_state_file() {
    local advisory_key="$1"
    local state_dir material fp session

    state_dir="${AI_PROTECTED_FILES_STATE_DIR:-$(ai_state_root)/protected-files}"
    session=$(ai_payload_session_id "$AI_HOOK_PAYLOAD" 2>/dev/null || printf 'no-session')
    [ -n "$session" ] || session="no-session"
    material="$REPO_ROOT:$session:$advisory_key"
    fp=$(printf '%s' "$material" | ai_hash_text)
    [ -n "$fp" ] || return 1

    printf '%s/%s\n' "$state_dir" "$fp"
}

ai_protected_should_emit() {
    local advisory_key="$1"
    local file dir base tmp now ttl last_ts=""

    file=$(ai_protected_state_file "$advisory_key") || return 1
    dir=$(dirname -- "$file")
    base=$(basename -- "$file")
    mkdir -p -- "$dir" || return 1

    now=$(ai_now)
    ttl=$(ai_protected_files_ttl)

    if [ -f "$file" ]; then
        while IFS='=' read -r key value; do
            case "$key" in
                LAST_TS) last_ts="$value" ;;
                *) last_ts="" ;;
            esac
        done < "$file"
        if ai_is_integer "$last_ts" && [ "$((now - last_ts))" -ge 0 ] && [ "$((now - last_ts))" -lt "$ttl" ]; then
            return 1
        fi
    fi

    tmp=$(mktemp "$dir/.${base}.tmp.XXXXXX") || return 1
    if ! printf 'LAST_TS=%s\n' "$now" > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    mv -f -- "$tmp" "$file" || {
        rm -f -- "$tmp"
        return 1
    }
}

main() {
    local path abs rel entry advisory_key advisory combined
    local -A seen=()

    ai_read_payload PreToolUse || ai_emit_continue
    combined=""

    while IFS= read -r path; do
        [ -n "$path" ] || continue
        abs=$(ai_payload_absolute_path "$AI_HOOK_PAYLOAD" "$path" "$REPO_ROOT") || continue
        rel=$(ai_repo_relative_path "$abs")
        [ -z "${seen[$rel]+x}" ] || continue
        seen[$rel]=1

        entry=$(ai_protected_file_entry "$rel") || continue
        advisory_key="${entry%%$'\t'*}"
        advisory="${entry#*$'\t'}"

        if ai_protected_should_emit "$advisory_key"; then
            if [ -n "$combined" ]; then
                combined="${combined}"$'\n'"protected-files: $advisory"
            else
                combined="protected-files: $advisory"
            fi
        fi
    done < <(ai_payload_file_paths "$AI_HOOK_PAYLOAD")

    [ -n "$combined" ] && ai_emit_context "PreToolUse" "$combined"

    ai_emit_continue
}

main "$@"
