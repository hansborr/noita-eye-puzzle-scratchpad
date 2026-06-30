#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
hook="$repo_root/scripts/ai-hooks/cargo-run-quiet.sh"
tmp_root="$(mktemp -d)"
cargo_repo="$tmp_root/repo"
fake_bin="$tmp_root/bin"
state_dir="$tmp_root/state"
cargo_log="$tmp_root/cargo.log"
timeout_log="$tmp_root/timeout.log"

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

command -v jq >/dev/null 2>&1 || fail "jq is required for cargo hook tests"

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

setup_repo() {
    mkdir -p "$cargo_repo/src" "$fake_bin" "$state_dir"
    git_hermetic "$cargo_repo" init -q -b main
    printf '[package]\nname = "stub"\nversion = "0.1.0"\nedition = "2024"\n' > "$cargo_repo/Cargo.toml"
    printf 'pub fn answer() -> u8 { 42 }\n' > "$cargo_repo/src/lib.rs"
    git_hermetic "$cargo_repo" add Cargo.toml src/lib.rs
    git_hermetic "$cargo_repo" commit -q -m "initial commit"

    cat > "$fake_bin/cargo" <<'SH'
#!/bin/bash
set -u

printf '%s\n' "$*" >> "$STUB_CARGO_LOG"
if [ "${STUB_CARGO_METACHARS:-0}" = "1" ]; then
    printf '%s\n' '$(touch SENTINEL_A)'
    printf '%s\n' '`touch SENTINEL_B`'
    printf '%s\n' '; touch SENTINEL_C' >&2
    printf '%s\n' 'stray " quote' >&2
fi
i=1
while [ "$i" -le "${STUB_CARGO_LINES:-1}" ]; do
    printf 'cargo line %02d\n' "$i"
    i=$((i + 1))
done
exit "${STUB_CARGO_STATUS:-0}"
SH
    chmod +x "$fake_bin/cargo"

    cat > "$fake_bin/timeout" <<'SH'
#!/bin/bash
set -u

[ -z "${STUB_TIMEOUT_LOG:-}" ] || printf '%s\n' "$*" >> "$STUB_TIMEOUT_LOG"
if [[ "${1:-}" == --kill-after=* ]]; then
    shift
fi
[ "$#" -gt 0 ] || exit 125
shift
exec "$@"
SH
    chmod +x "$fake_bin/timeout"
}

command_payload() {
    local command="$1"
    local timeout_ms="${2:-}"

    if [ -n "$timeout_ms" ]; then
        jq -n --arg command "$command" --argjson timeout "$timeout_ms" '{
            hook_event_name: "PreToolUse",
            tool_name: "Bash",
            tool_input: {command: $command, timeout: $timeout}
        }'
    else
        jq -n --arg command "$command" '{
            hook_event_name: "PreToolUse",
            tool_name: "Bash",
            tool_input: {command: $command}
        }'
    fi
}

run_cargo_hook() {
    local payload="$1"
    shift

    set +e
    RUN_OUTPUT=$(
        printf '%s' "$payload" \
            | env \
                AI_HOOK_REPO_ROOT="$cargo_repo" \
                AI_CARGO_QUIET_STATE_DIR="$state_dir" \
                PATH="$fake_bin:$PATH" \
                STUB_CARGO_LOG="$cargo_log" \
                STUB_TIMEOUT_LOG="$timeout_log" \
                "$@" \
                bash "$hook" 2>&1
    )
    RUN_STATUS=$?
    set -e
}

assert_status_zero() {
    local name="$1"

    [ "$RUN_STATUS" -eq 0 ] || fail "$name" "exit status: $RUN_STATUS"$'\n'"$RUN_OUTPUT"
}

assert_no_block() {
    local name="$1"

    [ "$RUN_STATUS" -ne 2 ] || fail "$name" "hook exited 2"
    printf '%s' "$RUN_OUTPUT" \
        | jq -e '(.decision? // "") != "block" and (.hookSpecificOutput.permissionDecision? // "") != "deny"' \
            >/dev/null 2>&1 \
        || fail "$name" "hook emitted a blocking decision:"$'\n'"$RUN_OUTPUT"
}

assert_continue() {
    local name="$1"

    assert_status_zero "$name"
    assert_no_block "$name"
    printf '%s' "$RUN_OUTPUT" | jq -e '.continue == true' >/dev/null 2>&1 \
        || fail "$name" "expected continue output:"$'\n'"$RUN_OUTPUT"
    pass "$name"
}

assert_rewrite() {
    local name="$1"

    assert_status_zero "$name"
    assert_no_block "$name"
    printf '%s' "$RUN_OUTPUT" \
        | jq -e '.hookSpecificOutput.hookEventName == "PreToolUse"
            and .hookSpecificOutput.permissionDecision == "allow"
            and (.hookSpecificOutput.updatedInput.command | type == "string")' \
            >/dev/null 2>&1 \
        || fail "$name" "expected updatedInput rewrite:"$'\n'"$RUN_OUTPUT"
}

rewritten_command() {
    printf '%s' "$RUN_OUTPUT" | jq -r '.hookSpecificOutput.updatedInput.command // empty'
}

run_rewritten() {
    local command="$1"

    set +e
    REPLAY_OUTPUT=$(cd "$tmp_root" && bash -c "$command" 2>&1)
    REPLAY_STATUS=$?
    set -e
}

assert_contains() {
    local name="$1"
    local haystack="$2"
    local needle="$3"

    [[ "$haystack" == *"$needle"* ]] || fail "$name" "missing [$needle] in:"$'\n'"$haystack"
}

assert_not_contains() {
    local name="$1"
    local haystack="$2"
    local needle="$3"

    [[ "$haystack" != *"$needle"* ]] || fail "$name" "unexpected [$needle] in:"$'\n'"$haystack"
}

assert_cargo_invocations() {
    local name="$1"
    local expected="$2"
    local actual=0

    if [ -f "$cargo_log" ]; then
        actual=$(wc -l < "$cargo_log" | tr -d ' ')
    fi
    [ "$actual" = "$expected" ] || fail "$name" "expected $expected cargo invocation(s), got $actual"
}

assert_no_sentinels() {
    local name="$1"
    local sentinel

    for sentinel in SENTINEL_A SENTINEL_B SENTINEL_C; do
        [ ! -e "$tmp_root/$sentinel" ] \
            || fail "$name" "unexpected sentinel was created: $tmp_root/$sentinel"
    done
}

setup_repo

run_cargo_hook "$(command_payload "cargo test")" NOITA_QUIET_OFF=1
assert_continue "cargo quiet off switch continues unchanged"
assert_cargo_invocations "off switch does not run cargo" 0

run_cargo_hook "$(command_payload "NOITA_QUIET_OFF=1 cargo check")"
assert_continue "inline quiet off assignment continues unchanged"
assert_cargo_invocations "inline assignment does not run cargo" 0

run_cargo_hook "$(command_payload "env NOITA_QUIET_OFF=1 cargo test")"
assert_continue "env quiet off assignment continues unchanged"
assert_cargo_invocations "env assignment does not run cargo" 0

run_cargo_hook "$(command_payload "echo cargo test")"
assert_continue "non-cargo command continues unchanged"

run_cargo_hook "$(command_payload "cargo run")"
assert_continue "cargo run continues unchanged"

run_cargo_hook "$(command_payload "cargo check && cargo test")"
assert_continue "compound cargo command continues unchanged"

run_cargo_hook "$(command_payload "cargo test -- --nocapture")"
assert_continue "cargo program-arg separator continues unchanged"

run_cargo_hook "{"
assert_continue "cargo hook fails open on malformed stdin"

run_cargo_hook "$(command_payload "cargo check")" STUB_CARGO_STATUS=0 STUB_CARGO_LINES=3
assert_rewrite "cargo check success rewrites command"
run_rewritten "$(rewritten_command)"
[ "$REPLAY_STATUS" -eq 0 ] || fail "cargo check replay exits zero" "$REPLAY_OUTPUT"
assert_contains "cargo check replay summary" "$REPLAY_OUTPUT" "cargo check OK ("
assert_cargo_invocations "cargo check ran once" 1
pass "cargo check success replay summary"

run_cargo_hook "$(command_payload "cargo check")" STUB_CARGO_STATUS=99 STUB_CARGO_LINES=3
assert_rewrite "cargo check cached success rewrites command"
run_rewritten "$(rewritten_command)"
[ "$REPLAY_STATUS" -eq 0 ] || fail "cargo check cached replay exits zero" "$REPLAY_OUTPUT"
assert_contains "cargo check cached replay summary" "$REPLAY_OUTPUT" "cargo check OK (cached"
assert_cargo_invocations "cargo check cached path does not rerun cargo" 1
pass "cargo check cached success replay summary"

mkdir -p "$cargo_repo/tests/golden"
printf 'first\n' > "$cargo_repo/tests/golden/x.stdout"
run_cargo_hook "$(command_payload "cargo check")" STUB_CARGO_STATUS=0 STUB_CARGO_LINES=2
assert_rewrite "untracked non-source file busts cargo check cache"
run_rewritten "$(rewritten_command)"
[ "$REPLAY_STATUS" -eq 0 ] || fail "untracked non-source replay exits zero" "$REPLAY_OUTPUT"
assert_contains "untracked non-source replay summary" "$REPLAY_OUTPUT" "cargo check OK ("
assert_not_contains "untracked non-source replay is not cached" "$REPLAY_OUTPUT" "cached"
assert_cargo_invocations "untracked non-source file reruns cargo" 2
pass "untracked non-source file busts cache"

printf 'second\n' > "$cargo_repo/tests/golden/x.stdout"
run_cargo_hook "$(command_payload "cargo check")" STUB_CARGO_STATUS=0 STUB_CARGO_LINES=2
assert_rewrite "untracked non-source modification busts cargo check cache"
run_rewritten "$(rewritten_command)"
[ "$REPLAY_STATUS" -eq 0 ] || fail "untracked non-source modification exits zero" "$REPLAY_OUTPUT"
assert_contains "untracked non-source modification summary" "$REPLAY_OUTPUT" "cargo check OK ("
assert_not_contains "untracked non-source modification is not cached" "$REPLAY_OUTPUT" "cached"
assert_cargo_invocations "untracked non-source modification reruns cargo" 3
pass "untracked non-source modification busts cache"

: > "$timeout_log"
run_cargo_hook "$(command_payload "cargo clippy" 2500)" STUB_CARGO_STATUS=0
assert_rewrite "caller timeout cargo clippy rewrites command"
assert_contains "caller timeout clamps cargo pre-run" "$(tail -n 1 "$timeout_log")" "--kill-after=10s 2.500s bash -c cargo clippy"
run_rewritten "$(rewritten_command)"
[ "$REPLAY_STATUS" -eq 0 ] || fail "caller timeout replay exits zero" "$REPLAY_OUTPUT"
assert_contains "caller timeout replay summary" "$REPLAY_OUTPUT" "cargo clippy OK ("
assert_cargo_invocations "caller timeout cargo clippy ran" 4
pass "caller timeout clamps cargo pre-run"

run_cargo_hook "$(command_payload "cargo test")" STUB_CARGO_STATUS=0 STUB_CARGO_METACHARS=1
assert_rewrite "cargo metachar success rewrites command"
run_rewritten "$(rewritten_command)"
[ "$REPLAY_STATUS" -eq 0 ] || fail "cargo metachar success replay exits zero" "$REPLAY_OUTPUT"
assert_no_sentinels "cargo metachar success replay is injection-safe"
assert_contains "cargo metachar success replay summary" "$REPLAY_OUTPUT" "cargo test OK ("
assert_cargo_invocations "cargo metachar success ran" 5
pass "cargo metachar success replay is injection-safe"

run_cargo_hook "$(command_payload "cargo fmt --check")" STUB_CARGO_STATUS=13 STUB_CARGO_METACHARS=1
assert_rewrite "cargo metachar failure rewrites command"
run_rewritten "$(rewritten_command)"
[ "$REPLAY_STATUS" -eq 13 ] || fail "cargo metachar failure replay preserves exit" "$REPLAY_OUTPUT"
assert_no_sentinels "cargo metachar failure replay is injection-safe"
assert_contains "cargo metachar failure prints dollar paren verbatim" "$REPLAY_OUTPUT" "\$(touch SENTINEL_A)"
assert_contains "cargo metachar failure prints backticks verbatim" "$REPLAY_OUTPUT" "\`touch SENTINEL_B\`"
assert_contains "cargo metachar failure prints semicolon verbatim" "$REPLAY_OUTPUT" '; touch SENTINEL_C'
assert_contains "cargo metachar failure prints quote verbatim" "$REPLAY_OUTPUT" 'stray " quote'
assert_cargo_invocations "cargo metachar failure ran" 6
pass "cargo metachar failure replay is injection-safe"

run_cargo_hook "$(command_payload "cargo build")" STUB_CARGO_STATUS=7 STUB_CARGO_LINES=50
assert_rewrite "cargo build failure rewrites command"
run_rewritten "$(rewritten_command)"
[ "$REPLAY_STATUS" -eq 7 ] || fail "cargo build replay preserves failure exit" "$REPLAY_OUTPUT"
assert_contains "cargo build failure tail includes final line" "$REPLAY_OUTPUT" "cargo line 50"
assert_not_contains "cargo build failure tail omits early line" "$REPLAY_OUTPUT" "cargo line 01"
assert_contains "cargo build failure summary" "$REPLAY_OUTPUT" "cargo build failed (exit 7"
pass "cargo build failure replay tail"
