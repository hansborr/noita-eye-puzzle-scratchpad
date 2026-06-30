#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
hooks_dir="$repo_root/scripts/ai-hooks"
tmp_root="$(mktemp -d)"
state_dir="$tmp_root/state"

cleanup() {
    rm -rf -- "$tmp_root"
}
trap cleanup EXIT

fail() {
    local name="$1"
    local detail="${2:-}"

    printf 'not ok - %s\n' "$name" >&2
    [ -z "$detail" ] || printf '%s\n' "$detail" >&2
    exit 1
}

pass() {
    printf 'ok - %s\n' "$1"
}

command -v jq >/dev/null 2>&1 || fail "jq is required for ai hook tests"

run_hook() {
    local hook="$1"
    local payload="$2"
    shift 2

    set +e
    RUN_OUTPUT=$(
        printf '%s' "$payload" \
            | env AI_HOOKS_STATE_DIR="$state_dir" "$@" bash "$hook" 2>&1
    )
    RUN_STATUS=$?
    set -e
}

assert_status_zero() {
    local name="$1"

    [ "$RUN_STATUS" -eq 0 ] || fail "$name" "exit status: $RUN_STATUS"$'\n'"$RUN_OUTPUT"
}

assert_not_exit_two() {
    local name="$1"

    [ "$RUN_STATUS" -ne 2 ] || fail "$name" "Stop hook exited 2"
}

assert_jq() {
    local name="$1"
    local filter="$2"

    printf '%s' "$RUN_OUTPUT" | jq -e "$filter" >/dev/null 2>&1 \
        || fail "$name" "output did not match jq filter: $filter"$'\n'"$RUN_OUTPUT"
}

assert_empty_output() {
    local name="$1"

    [ -z "$RUN_OUTPUT" ] || fail "$name" "expected empty output, got:"$'\n'"$RUN_OUTPUT"
}

command_payload() {
    local command="$1"

    jq -n --arg command "$command" '{
        hook_event_name: "PreToolUse",
        session_id: "commit-tests",
        tool_input: {command: $command}
    }'
}

file_payload() {
    local path="$1"
    local session="$2"

    jq -n --arg path "$path" --arg session "$session" '{
        hook_event_name: "PreToolUse",
        session_id: $session,
        tool_input: {file_path: $path}
    }'
}

stop_payload() {
    local session="$1"

    jq -n --arg session "$session" '{
        hook_event_name: "Stop",
        session_id: $session
    }'
}

expect_commit_block() {
    local name="$1"
    local command="$2"

    run_hook "$hooks_dir/commit-bypass-guard.sh" "$(command_payload "$command")"
    assert_status_zero "$name"
    assert_jq "$name" \
        '.hookSpecificOutput.hookEventName == "PreToolUse" and .hookSpecificOutput.permissionDecision == "deny" and (.hookSpecificOutput.permissionDecisionReason | contains("pre-commit hook"))'
    pass "$name"
}

expect_commit_allow() {
    local name="$1"
    local command="$2"

    run_hook "$hooks_dir/commit-bypass-guard.sh" "$(command_payload "$command")"
    assert_status_zero "$name"
    assert_jq "$name" '.continue == true'
    pass "$name"
}

expect_file_context() {
    local name="$1"
    local path="$2"
    local needle="$3"
    local session="$4"

    run_hook "$hooks_dir/protected-files-advisory.sh" "$(file_payload "$path" "$session")" \
        AI_HOOK_REPO_ROOT="$repo_root"
    assert_status_zero "$name"
    assert_jq "$name" \
        ".hookSpecificOutput.hookEventName == \"PreToolUse\" and (.hookSpecificOutput.additionalContext | contains(\"$needle\")) and (.decision? // \"\") != \"block\""
    pass "$name"
}

expect_file_allow() {
    local name="$1"
    local path="$2"

    run_hook "$hooks_dir/protected-files-advisory.sh" "$(file_payload "$path" "normal-file")" \
        AI_HOOK_REPO_ROOT="$repo_root"
    assert_status_zero "$name"
    assert_jq "$name" '.continue == true'
    pass "$name"
}

expect_fail_open() {
    local name="$1"
    local hook="$2"
    local payload="$3"

    run_hook "$hook" "$payload"
    assert_status_zero "$name"
    assert_jq "$name" '.continue == true'
    pass "$name"
}

git_hermetic() {
    local repo="$1"
    shift

    git \
        -C "$repo" \
        -c commit.gpgsign=false \
        -c core.hooksPath= \
        -c user.name=t \
        -c user.email=t@e \
        "$@"
}

new_repo() {
    local branch="$1"
    local name="${branch//\//-}"
    local repo

    repo="$(mktemp -d "$tmp_root/repo-$name.XXXXXX")"
    git_hermetic "$repo" init -q -b "$branch"
    printf 'base\n' > "$repo/README.md"
    git_hermetic "$repo" add README.md
    git_hermetic "$repo" commit -q -m "initial commit"
    printf '%s\n' "$repo"
}

expect_stop_context() {
    local name="$1"
    local repo="$2"
    local session="$3"
    local needle="$4"

    run_hook "$hooks_dir/stop-nudge.sh" "$(stop_payload "$session")" \
        AI_HOOK_REPO_ROOT="$repo"
    assert_not_exit_two "$name"
    assert_status_zero "$name"
    assert_jq "$name" \
        ".hookSpecificOutput.hookEventName == \"Stop\" and (.hookSpecificOutput.additionalContext | contains(\"$needle\"))"
    pass "$name"
}

expect_stop_silent() {
    local name="$1"
    local repo="$2"
    local session="$3"

    run_hook "$hooks_dir/stop-nudge.sh" "$(stop_payload "$session")" \
        AI_HOOK_REPO_ROOT="$repo"
    assert_not_exit_two "$name"
    assert_status_zero "$name"
    assert_empty_output "$name"
    pass "$name"
}

expect_commit_block "blocks git commit --no-verify" "git commit --no-verify"
expect_commit_block "blocks git commit flag after message" "git commit -m x --no-verify"
expect_commit_block "blocks env-prefixed amend" "HUSKY=0 git commit --amend"
expect_commit_block "blocks git commit --amend" "git commit --amend"

expect_commit_allow "allows quoted no-verify mention" 'git commit -m "explain --no-verify behavior"'
expect_commit_allow "allows quoted short flag mention" 'git commit -m "fix -n flag"'
expect_commit_allow "allows normal commit" 'git commit -m "msg"'
expect_commit_allow "allows non-git command" 'printf "%s\n" "git commit --no-verify"'

expect_file_context "advises on Cargo.toml" "Cargo.toml" "dependency surface" "cargo-file"
expect_file_context "advises on verified corpus" "src/data/corpus.rs" "Experiment-0-verified corpus" "corpus-file"
expect_file_allow "allows normal source file" "src/lib.rs"

clean_repo="$(new_repo feature/clean-stop)"
expect_stop_silent "stop hook silent on clean repo" "$clean_repo" "clean-stop"

dirty_repo="$(new_repo feature/dirty-stop)"
printf 'dirty\n' >> "$dirty_repo/README.md"
expect_stop_context "stop hook advises on dirty feature branch" "$dirty_repo" "dirty-stop" "uncommitted changes"
expect_stop_silent "stop hook throttles same dirty changes" "$dirty_repo" "dirty-stop"

main_repo="$(new_repo main)"
printf 'dirty\n' >> "$main_repo/README.md"
expect_stop_context "stop hook advises to branch on main" "$main_repo" "main-stop" "branch first"

kill_repo="$(new_repo feature/kill-stop)"
printf 'dirty\n' >> "$kill_repo/README.md"
touch "$kill_repo/.no-stop-uncommitted"
expect_stop_silent "stop hook respects kill switch" "$kill_repo" "kill-stop"

expect_fail_open "commit hook fails open on malformed stdin" "$hooks_dir/commit-bypass-guard.sh" "{"
expect_fail_open "commit hook fails open on empty stdin" "$hooks_dir/commit-bypass-guard.sh" ""
expect_fail_open "protected-files hook fails open on malformed stdin" "$hooks_dir/protected-files-advisory.sh" "{"
expect_fail_open "protected-files hook fails open on empty stdin" "$hooks_dir/protected-files-advisory.sh" ""
expect_fail_open "stop hook fails open on malformed stdin" "$hooks_dir/stop-nudge.sh" "{"
expect_fail_open "stop hook fails open on empty stdin" "$hooks_dir/stop-nudge.sh" ""
