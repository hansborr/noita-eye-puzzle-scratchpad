#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
hook="$repo_root/scripts/ai-hooks/tidy-on-edit.sh"
tmp_root="$(mktemp -d)"
tidy_repo="$tmp_root/repo"
fake_bin="$tmp_root/bin"
state_dir="$tmp_root/state"
rustfmt_log="$tmp_root/rustfmt.log"

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

command -v jq >/dev/null 2>&1 || fail "jq is required for tidy hook tests"

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
    mkdir -p "$tidy_repo/src" "$fake_bin" "$state_dir"
    git_hermetic "$tidy_repo" init -q -b main
    printf 'pub fn answer()->u8{42}\n' > "$tidy_repo/src/lib.rs"
    printf 'text\n' > "$tidy_repo/README.md"
    git_hermetic "$tidy_repo" add src/lib.rs README.md
    git_hermetic "$tidy_repo" commit -q -m "initial commit"

    cat > "$fake_bin/rustfmt" <<'SH'
#!/bin/bash
set -u

file="$1"
printf '%s\n' "$file" >> "$RUSTFMT_LOG"
if [ "${STUB_RUSTFMT_SLEEP:-0}" -gt 0 ]; then
    sleep "$STUB_RUSTFMT_SLEEP"
fi
if [ "${STUB_RUSTFMT_STATUS:-0}" -ne 0 ]; then
    printf 'rustfmt stub error\n' >&2
    exit "$STUB_RUSTFMT_STATUS"
fi
if [ "${STUB_RUSTFMT_MODE:-modify}" = "modify" ]; then
    printf '\n// rustfmt stub\n' >> "$file"
fi
exit 0
SH
    chmod +x "$fake_bin/rustfmt"
}

edit_payload() {
    local file="$1"
    local tool="${2:-Edit}"
    local session="${3:-tidy-tests}"

    jq -n --arg file "$file" --arg tool "$tool" --arg session "$session" '{
        hook_event_name: "PostToolUse",
        session_id: $session,
        tool_name: $tool,
        tool_input: {file_path: $file},
        tool_response: {success: true}
    }'
}

run_tidy_hook() {
    local payload="$1"
    shift

    set +e
    RUN_OUTPUT=$(
        printf '%s' "$payload" \
            | env \
                AI_HOOK_REPO_ROOT="$tidy_repo" \
                AI_TIDY_ON_EDIT_STATE_DIR="$state_dir" \
                PATH="$fake_bin:$PATH" \
                RUSTFMT_LOG="$rustfmt_log" \
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

assert_context_contains() {
    local name="$1"
    local needle="$2"

    assert_status_zero "$name"
    assert_no_block "$name"
    printf '%s' "$RUN_OUTPUT" \
        | jq -e --arg needle "$needle" \
            '.hookSpecificOutput.hookEventName == "PostToolUse"
                and (.hookSpecificOutput.additionalContext | contains($needle))' \
            >/dev/null 2>&1 \
        || fail "$name" "missing context [$needle] in:"$'\n'"$RUN_OUTPUT"
    pass "$name"
}

assert_rustfmt_invocations() {
    local name="$1"
    local expected="$2"
    local actual=0

    if [ -f "$rustfmt_log" ]; then
        actual=$(wc -l < "$rustfmt_log" | tr -d ' ')
    fi
    [ "$actual" = "$expected" ] || fail "$name" "expected $expected rustfmt invocation(s), got $actual"
}

setup_repo

run_tidy_hook "$(edit_payload "src/lib.rs")" STUB_RUSTFMT_MODE=modify
assert_context_contains "tidy hook formats edited Rust file" "tidy-on-edit: src/lib.rs rustfmt applied"
assert_rustfmt_invocations "rustfmt ran once for Rust file" 1

run_tidy_hook "$(edit_payload "src/lib.rs")" STUB_RUSTFMT_MODE=modify
assert_continue "tidy hook skips unchanged Rust file hash"
assert_rustfmt_invocations "rustfmt did not rerun for unchanged hash" 1

run_tidy_hook "$(edit_payload "README.md" "Write")"
assert_continue "tidy hook ignores non-Rust file"
assert_rustfmt_invocations "rustfmt did not run for non-Rust file" 1

outside_file="$tmp_root/outside.rs"
printf 'fn outside(){}\n' > "$outside_file"
run_tidy_hook "$(edit_payload "$outside_file")"
assert_continue "tidy hook ignores Rust file outside repo"
assert_rustfmt_invocations "rustfmt did not run outside repo" 1

printf 'fn bad(){\n' > "$tidy_repo/src/bad.rs"
run_tidy_hook "$(edit_payload "src/bad.rs" "Edit" "tidy-error")" STUB_RUSTFMT_STATUS=2 STUB_RUSTFMT_MODE=none
assert_context_contains "tidy hook reports rustfmt errors without blocking" "tidy-on-edit: src/bad.rs rustfmt ERROR (non-blocking)"
assert_rustfmt_invocations "rustfmt ran for error case" 2

printf 'fn slow(){}\n' > "$tidy_repo/src/slow.rs"
run_tidy_hook "$(edit_payload "src/slow.rs" "Edit" "tidy-timeout")" \
    AI_TIDY_ON_EDIT_TIMEOUT=1 \
    STUB_RUSTFMT_SLEEP=2 \
    STUB_RUSTFMT_MODE=none
assert_context_contains "tidy hook reports rustfmt timeout without blocking" "tidy-on-edit: src/slow.rs rustfmt TIMEOUT after 1s (non-blocking)"
assert_rustfmt_invocations "rustfmt ran for timeout case" 3

run_tidy_hook "{"
assert_continue "tidy hook fails open on malformed stdin"
assert_rustfmt_invocations "rustfmt did not run for malformed stdin" 3
