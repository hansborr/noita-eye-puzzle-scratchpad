#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
hook="$repo_root/.githooks/pre-commit"
tmp_root="$(mktemp -d)"

cleanup() {
    rm -rf -- "$tmp_root"
}
trap cleanup EXIT

new_repo() {
    local branch="$1"
    local name="${branch//\//-}"
    local repo

    repo="$tmp_root/repo-$name"
    mkdir -p -- "$repo"
    git -C "$repo" init -q -b "$branch"
    printf '%s\n' "$repo"
}

run_hook() {
    local repo="$1"
    shift

    (
        cd "$repo"
        env PRECOMMIT_GUARDS_ONLY=1 "$@" "$hook"
    )
}

expect_success() {
    local name="$1"
    local repo="$2"
    local output
    shift 2

    if ! output="$(run_hook "$repo" "$@" 2>&1)"; then
        printf 'not ok - %s\n%s\n' "$name" "$output" >&2
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

    if output="$(run_hook "$repo" "$@" 2>&1)"; then
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

main_repo="$(new_repo main)"
expect_failure_contains \
    "protected branch rejects main" \
    "$main_repo" \
    "refusing to commit directly on main"
expect_success \
    "protected branch override allows main" \
    "$main_repo" \
    ALLOW_COMMIT_ON_MAIN=1

feature_repo="$(new_repo feature/precommit-guards)"
expect_success \
    "protected branch allows feature branch" \
    "$feature_repo"

clean_repo="$(new_repo feature/clean-worktree)"
mkdir -p -- "$clean_repo/src"
printf 'pub fn clean() {}\n' > "$clean_repo/src/lib.rs"
git -C "$clean_repo" add src/lib.rs
expect_success \
    "dirty guard allows clean source-relevant index" \
    "$clean_repo"

unstaged_repo="$(new_repo feature/unstaged-source)"
mkdir -p -- "$unstaged_repo/src"
printf 'pub fn before() {}\n' > "$unstaged_repo/src/lib.rs"
git -C "$unstaged_repo" add src/lib.rs
printf 'pub fn after() {}\n' >> "$unstaged_repo/src/lib.rs"
expect_failure_contains \
    "dirty guard rejects unstaged source-relevant changes" \
    "$unstaged_repo" \
    "unstaged source-relevant paths:"
expect_success \
    "dirty guard override allows unstaged source-relevant changes" \
    "$unstaged_repo" \
    ALLOW_DIRTY_COMMIT=1

untracked_repo="$(new_repo feature/untracked-source)"
mkdir -p -- "$untracked_repo/src"
printf 'pub fn spaced() {}\n' > "$untracked_repo/src/file with space.rs"
expect_failure_contains \
    "dirty guard rejects untracked source-relevant paths" \
    "$untracked_repo" \
    "file with space.rs"
expect_success \
    "dirty guard override allows untracked source-relevant paths" \
    "$untracked_repo" \
    ALLOW_DIRTY_COMMIT=1

unrelated_repo="$(new_repo feature/unrelated-untracked)"
printf 'scratch\n' > "$unrelated_repo/notes.txt"
expect_success \
    "dirty guard ignores unrelated untracked paths" \
    "$unrelated_repo"
