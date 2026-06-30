#!/bin/bash

# Stop hook: non-blocking reminder to commit dirty work before ending a session.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ai-hooks/common.sh
. "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(ai_repo_root "$SCRIPT_DIR")
AI_STOP_KILL_SWITCH=".no-stop-uncommitted"

ai_stop_repo_key() {
    local root_real material fp session

    root_real=$(realpath -m -- "$REPO_ROOT" 2>/dev/null || printf '%s\n' "$REPO_ROOT")
    session=$(ai_payload_session_id "$AI_HOOK_PAYLOAD" 2>/dev/null || printf 'no-session')
    [ -n "$session" ] || session="no-session"
    material="$root_real:$session"
    fp=$(printf '%s' "$material" | ai_hash_text)
    [ -n "$fp" ] || return 1
    printf '%s\n' "$fp"
}

ai_stop_marker_path() {
    local state_dir repo_key

    state_dir="${AI_STOP_NUDGE_STATE_DIR:-$(ai_state_root)/stop}"
    repo_key=$(ai_stop_repo_key) || return 1
    printf '%s/last.%s\n' "$state_dir" "$repo_key"
}

ai_stop_has_uncommitted_changes() {
    [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal 2>/dev/null)" ]
}

ai_stop_worktree_fingerprint() {
    {
        git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf 'none\n'
        git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=normal 2>/dev/null || true
        git -C "$REPO_ROOT" diff --binary HEAD -- 2>/dev/null \
            || git -C "$REPO_ROOT" diff --binary -- 2>/dev/null \
            || true
        git -C "$REPO_ROOT" diff --binary --cached HEAD -- 2>/dev/null \
            || git -C "$REPO_ROOT" diff --binary --cached -- 2>/dev/null \
            || true
        (
            cd "$REPO_ROOT" || exit 0
            while IFS= read -r -d '' path; do
                printf 'untracked %s\n' "$path"
                sha256sum -- "$path" 2>/dev/null || true
            done < <(git ls-files --others --exclude-standard -z 2>/dev/null)
        )
    } | ai_hash_text
}

ai_stop_current_branch() {
    local branch

    branch=$(git -C "$REPO_ROOT" branch --show-current 2>/dev/null || true)
    [ -n "$branch" ] || branch="detached HEAD"
    printf '%s\n' "$branch"
}

ai_stop_read_marker_matches() {
    local marker="$1"
    local fp="$2"
    local branch="$3"
    local last_fp="" last_branch=""

    [ -f "$marker" ] || return 1
    while IFS='=' read -r key value; do
        case "$key" in
            LAST_FP) last_fp="$value" ;;
            LAST_BRANCH) last_branch="$value" ;;
            LAST_TS) ;;
            *) return 1 ;;
        esac
    done < "$marker"

    [ "$last_fp" = "$fp" ] && [ "$last_branch" = "$branch" ]
}

ai_stop_write_marker() {
    local marker="$1"
    local fp="$2"
    local branch="$3"
    local dir base tmp

    dir=$(dirname -- "$marker")
    base=$(basename -- "$marker")
    mkdir -p -- "$dir" || return 1
    tmp=$(mktemp "$dir/.${base}.tmp.XXXXXX") || return 1

    if ! {
        printf 'LAST_TS=%s\n' "$(date +%s)"
        printf 'LAST_FP=%s\n' "$fp"
        printf 'LAST_BRANCH=%s\n' "$branch"
    } > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi

    mv -f -- "$tmp" "$marker" || {
        rm -f -- "$tmp"
        return 1
    }
}

ai_stop_message() {
    local branch="$1"

    case "$branch" in
        main | master)
            printf "stop-nudge: you're on %s with uncommitted work - branch first, then commit before stopping. Disable with: touch %s/%s" \
                "$branch" "$REPO_ROOT" "$AI_STOP_KILL_SWITCH"
            ;;
        *)
            printf "stop-nudge: uncommitted changes - commit the work before stopping (branch: %s). Disable with: touch %s/%s" \
                "$branch" "$REPO_ROOT" "$AI_STOP_KILL_SWITCH"
            ;;
    esac
}

main() {
    local marker fp branch

    ai_read_payload Stop || ai_emit_continue

    git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0
    [ -f "$REPO_ROOT/$AI_STOP_KILL_SWITCH" ] && exit 0
    ai_stop_has_uncommitted_changes || exit 0

    fp=$(ai_stop_worktree_fingerprint)
    [ -n "$fp" ] || exit 0
    branch=$(ai_stop_current_branch)
    marker=$(ai_stop_marker_path) || marker=""

    if [ -n "$marker" ] && ai_stop_read_marker_matches "$marker" "$fp" "$branch"; then
        exit 0
    fi

    if [ -n "$marker" ]; then
        ai_stop_write_marker "$marker" "$fp" "$branch" || true
    fi
    ai_emit_context "Stop" "$(ai_stop_message "$branch")"
}

main "$@"
