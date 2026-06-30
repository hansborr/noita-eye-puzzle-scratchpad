#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
check="$repo_root/scripts/check-file-size.sh"
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
    : > "$repo/scripts/file-size-allowlist.txt"
    printf '%s\n' "$repo"
}

write_lines() {
    local path="$1"
    local count="$2"
    local i

    : > "$path"
    for (( i = 0; i < count; i++ )); do
        printf '// line %d\n' "$i" >> "$path"
    done
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

summary_repo="$(new_repo summary)"
write_lines "$summary_repo/src/lib.rs" 650
printf 'src/lib.rs 650 # summary fixture pin\n' > \
    "$summary_repo/scripts/file-size-allowlist.txt"
git_hermetic "$summary_repo" add src/lib.rs scripts/file-size-allowlist.txt
expect_success_contains \
    "file-size summary lists pins" \
    "$summary_repo" \
    $'src/lib.rs\t650\t650\t0' \
    --summary

debt_repo="$(new_repo debt-log)"
printf '// small file\n' > "$debt_repo/src/lib.rs"
git_hermetic "$debt_repo" add src/lib.rs
expect_success_contains \
    "file-size log-debt appends JSONL" \
    "$debt_repo" \
    "logged debt for src/lib.rs" \
    --log-debt src/lib.rs - 700 "smoke-test debt entry"
expect_success_contains \
    "file-size validates debt JSONL" \
    "$debt_repo" \
    "file-size: OK"
