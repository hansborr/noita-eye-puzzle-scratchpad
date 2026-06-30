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
i=1
while [ "$i" -le "${STUB_CARGO_LINES:-1}" ]; do
    printf 'cargo line %02d\n' "$i"
    i=$((i + 1))
done
exit "${STUB_CARGO_STATUS:-0}"
SH
    chmod +x "$fake_bin/cargo"
}

command_payload() {
    local command="$1"

    jq -n --arg command "$command" '{
        hook_event_name: "PreToolUse",
        tool_name: "Bash",
        tool_input: {command: $command}
    }'
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
    REPLAY_OUTPUT=$(bash -c "$command" 2>&1)
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

setup_repo

run_cargo_hook "$(command_payload "cargo test")" NOITA_QUIET_OFF=1
assert_continue "cargo quiet off switch continues unchanged"
assert_cargo_invocations "off switch does not run cargo" 0

run_cargo_hook "$(command_payload "echo cargo test")"
assert_continue "non-cargo command continues unchanged"

run_cargo_hook "$(command_payload "cargo run")"
assert_continue "cargo run continues unchanged"

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

run_cargo_hook "$(command_payload "cargo build")" STUB_CARGO_STATUS=7 STUB_CARGO_LINES=50
assert_rewrite "cargo build failure rewrites command"
run_rewritten "$(rewritten_command)"
[ "$REPLAY_STATUS" -eq 7 ] || fail "cargo build replay preserves failure exit" "$REPLAY_OUTPUT"
assert_contains "cargo build failure tail includes final line" "$REPLAY_OUTPUT" "cargo line 50"
assert_not_contains "cargo build failure tail omits early line" "$REPLAY_OUTPUT" "cargo line 01"
assert_contains "cargo build failure summary" "$REPLAY_OUTPUT" "cargo build failed (exit 7"
pass "cargo build failure replay tail"
