#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
check="$repo_root/scripts/check-blob-size.sh"
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
    mkdir -p -- "$repo/scripts"
    : > "$repo/scripts/blob-size-allowlist.txt"
    printf '%s\n' "$repo"
}

stage_blob() {
    local repo="$1"
    local path="$2"
    local bytes="$3"

    mkdir -p -- "$repo/$(dirname -- "$path")"
    head -c "$bytes" /dev/zero > "$repo/$path"
    git_hermetic "$repo" add -- "$path"
}

run_check() {
    local repo="$1"

    (
        cd "$repo"
        "$check"
    )
}

expect_success_contains() {
    local name="$1"
    local repo="$2"
    local needle="$3"
    local output

    if ! output="$(run_check "$repo" 2>&1)"; then
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

    if output="$(run_check "$repo" 2>&1)"; then
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

blocked_repo="$(new_repo blocked)"
stage_blob "$blocked_repo" big.bin 2097153
expect_failure_contains \
    "staged blob over block threshold fails" \
    "$blocked_repo" \
    "exceeding block threshold"

allowlisted_repo="$(new_repo allowlisted)"
printf 'big.bin # intentional test fixture\n' > "$allowlisted_repo/scripts/blob-size-allowlist.txt"
git_hermetic "$allowlisted_repo" add scripts/blob-size-allowlist.txt
stage_blob "$allowlisted_repo" big.bin 2097153
expect_success_contains \
    "allowlisted large staged blob passes" \
    "$allowlisted_repo" \
    "blob-size: OK"

warn_repo="$(new_repo warn)"
stage_blob "$warn_repo" medium.bin 524288
expect_success_contains \
    "staged blob at warning threshold warns but passes" \
    "$warn_repo" \
    "blob-size: warning:"

reasonless_repo="$(new_repo reasonless)"
printf 'big.bin #\n' > "$reasonless_repo/scripts/blob-size-allowlist.txt"
expect_failure_contains \
    "reasonless allowlist entry fails" \
    "$reasonless_repo" \
    "entry needs a non-empty reason"

stale_repo="$(new_repo stale)"
printf 'missing.bin # stale test fixture\n' > "$stale_repo/scripts/blob-size-allowlist.txt"
expect_failure_contains \
    "stale allowlist entry fails" \
    "$stale_repo" \
    "stale allowlist entry"
