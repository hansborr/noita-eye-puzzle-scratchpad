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
    git_hermetic "$repo" init -q -b feature/fast-commit
    mkdir -p -- "$repo/src"
    printf 'pub fn staged() {}\n' > "$repo/src/lib.rs"
    git_hermetic "$repo" add src/lib.rs
    printf '%s\n' "$repo"
}

run_plan() {
    local repo="$1"
    shift

    (
        cd "$repo"
        env PRECOMMIT_PLAN_ONLY=1 "$@" "$hook"
    )
}

enable_default_marker() {
    local repo="$1"

    (
        cd "$repo"
        touch "$(git rev-parse --git-dir)/noita-fast-commit"
    )
}

plan_has() {
    local output="$1"
    local slot="$2"

    grep -Fxq "pre-commit: plan: $slot" <<< "$output"
}

expect_plan_has() {
    local name="$1"
    local output="$2"
    local slot="$3"

    if ! plan_has "$output" "$slot"; then
        printf 'not ok - %s\nmissing plan slot: %s\nactual output:\n%s\n' \
            "$name" "$slot" "$output" >&2
        exit 1
    fi
}

expect_plan_lacks() {
    local name="$1"
    local output="$2"
    local slot="$3"

    if plan_has "$output" "$slot"; then
        printf 'not ok - %s\nunexpected plan slot: %s\nactual output:\n%s\n' \
            "$name" "$slot" "$output" >&2
        exit 1
    fi
}

expect_fast_plan() {
    local name="$1"
    local output="$2"

    for slot in blob-size suppressions rustfmt clippy file-size cargo-deny; do
        expect_plan_has "$name" "$output" "$slot"
    done
    expect_plan_lacks "$name" "$output" tests
    expect_plan_lacks "$name" "$output" rustdoc
    printf 'ok - %s\n' "$name"
}

default_repo="$(new_repo default-plan)"
default_output="$(run_plan "$default_repo" 2>&1)"
expect_plan_has "default plan includes tests" "$default_output" tests
expect_plan_has "default plan includes rustdoc" "$default_output" rustdoc
expect_plan_has "default plan keeps clippy" "$default_output" clippy
expect_plan_has "default plan keeps blob-size" "$default_output" blob-size
printf 'ok - default plan includes slow Rust slots\n'

marker_repo="$(new_repo marker-plan)"
enable_default_marker "$marker_repo"
marker_output="$(run_plan "$marker_repo" 2>&1)"
expect_fast_plan "default marker skips only slow Rust slots" "$marker_output"

override_repo="$(new_repo override-plan)"
override_marker="$tmp_root/override/noita-fast-commit"
mkdir -p -- "$(dirname -- "$override_marker")"
touch "$override_marker"
override_output="$(run_plan "$override_repo" NOITA_FAST_COMMIT_MARKER="$override_marker" 2>&1)"
expect_fast_plan "env marker override skips slow Rust slots" "$override_output"
