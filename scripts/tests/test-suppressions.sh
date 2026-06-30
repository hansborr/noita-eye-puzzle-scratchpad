#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
check="$repo_root/scripts/check-suppressions.sh"
tmp_root="$(mktemp -d)"

cleanup() {
    rm -rf -- "$tmp_root"
}
trap cleanup EXIT

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
    local name="$1"
    local repo

    repo="$(mktemp -d "$tmp_root/repo-$name.XXXXXX")"
    git_hermetic "$repo" init -q -b main
    mkdir -p -- "$repo/scripts" "$repo/src"
    : > "$repo/scripts/suppression-register.txt"
    printf '%s\n' "$repo"
}

stage_src() {
    local repo="$1"

    git_hermetic "$repo" add src/lib.rs
}

run_check() {
    local repo="$1"
    shift

    (
        cd "$repo"
        "$check" "$@"
    )
}

expect_success_contains() {
    local name="$1"
    local repo="$2"
    local needle="$3"
    local output
    shift 3

    if ! output="$(run_check "$repo" "$@" 2>&1)"; then
        printf 'not ok - %s\n%s\n' "$name" "$output" >&2
        exit 1
    fi
    if [[ "$output" != *"$needle"* ]]; then
        printf 'not ok - %s\nexpected output to contain: %s\nactual output:\n%s\n' \
            "$name" "$needle" "$output" >&2
        exit 1
    fi
    printf 'ok - %s\n' "$name"
}

expect_failure_contains() {
    local name="$1"
    local repo="$2"
    local needle="$3"
    local output
    shift 3

    if output="$(run_check "$repo" "$@" 2>&1)"; then
        printf 'not ok - %s\nexpected failure containing: %s\nactual output:\n%s\n' \
            "$name" "$needle" "$output" >&2
        exit 1
    fi
    if [[ "$output" != *"$needle"* ]]; then
        printf 'not ok - %s\nexpected output to contain: %s\nactual output:\n%s\n' \
            "$name" "$needle" "$output" >&2
        exit 1
    fi
    printf 'ok - %s\n' "$name"
}

unregistered_repo="$(new_repo unregistered)"
cat > "$unregistered_repo/src/lib.rs" <<'RS'
#![allow(clippy::unwrap_used, reason = "positive control")]
pub fn demo() {}
RS
stage_src "$unregistered_repo"
expect_failure_contains \
    "unregistered safety-silencing allow fails" \
    "$unregistered_repo" \
    "unregistered safety suppression"

registered_repo="$(new_repo registered)"
cat > "$registered_repo/src/lib.rs" <<'RS'
#![allow(clippy::unwrap_used, reason = "positive control")]
pub fn demo() {}
RS
printf 'src/lib.rs:1:clippy::unwrap_used # positive control\n' > \
    "$registered_repo/scripts/suppression-register.txt"
stage_src "$registered_repo"
expect_success_contains \
    "registered safety-silencing allow passes" \
    "$registered_repo" \
    "suppressions: OK"

stale_repo="$(new_repo stale)"
cat > "$stale_repo/src/lib.rs" <<'RS'
pub fn demo() {}
RS
printf 'src/lib.rs:1:clippy::unwrap_used # stale positive control\n' > \
    "$stale_repo/scripts/suppression-register.txt"
stage_src "$stale_repo"
expect_failure_contains \
    "stale suppression register entry fails" \
    "$stale_repo" \
    "stale register entry"

summary_repo="$(new_repo summary)"
cat > "$summary_repo/src/lib.rs" <<'RS'
#[allow(clippy::too_many_lines, reason = "summary positive control")]
pub fn demo() {}
RS
stage_src "$summary_repo"
expect_success_contains \
    "summary lists suppression entries" \
    "$summary_repo" \
    "src/lib.rs:1 allow clippy::too_many_lines" \
    --summary
