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

run_check_without_json_tools() {
    local repo="$1"
    local bin_dir="$tmp_root/no-json-tools-bin"
    local command_name command_path
    shift

    mkdir -p -- "$bin_dir"
    for command_name in bash git sort tr wc; do
        command_path="$(command -v "$command_name")"
        ln -sf -- "$command_path" "$bin_dir/$command_name"
    done

    (
        cd "$repo"
        PATH="$bin_dir" "$check" "$@"
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

grew_repo="$(new_repo grew-past-pin)"
write_lines "$grew_repo/src/lib.rs" 651
printf 'src/lib.rs 650 # growth fixture pin\n' > \
    "$grew_repo/scripts/file-size-allowlist.txt"
git_hermetic "$grew_repo" add src/lib.rs scripts/file-size-allowlist.txt
expect_failure_contains \
    "pinned file over its pin fails" \
    "$grew_repo" \
    "grew to 651 lines"

shrank_repo="$(new_repo shrank-below-slack)"
write_lines "$shrank_repo/src/lib.rs" 649
printf 'src/lib.rs 700 # shrink fixture pin\n' > \
    "$shrank_repo/scripts/file-size-allowlist.txt"
git_hermetic "$shrank_repo" add src/lib.rs scripts/file-size-allowlist.txt
expect_failure_contains \
    "pinned file below slack fails" \
    "$shrank_repo" \
    "shrank to 649 lines"

redundant_repo="$(new_repo redundant-pin)"
write_lines "$redundant_repo/src/lib.rs" 600
printf 'src/lib.rs 650 # redundant fixture pin\n' > \
    "$redundant_repo/scripts/file-size-allowlist.txt"
git_hermetic "$redundant_repo" add src/lib.rs scripts/file-size-allowlist.txt
expect_failure_contains \
    "redundant pin under default cap fails" \
    "$redundant_repo" \
    "delete its line"

unpinned_repo="$(new_repo unpinned-over-cap)"
write_lines "$unpinned_repo/src/lib.rs" 601
git_hermetic "$unpinned_repo" add src/lib.rs
expect_failure_contains \
    "unpinned file over default cap fails" \
    "$unpinned_repo" \
    "cap 600"

stale_repo="$(new_repo stale-pin)"
printf 'src/missing.rs 650 # stale fixture pin\n' > \
    "$stale_repo/scripts/file-size-allowlist.txt"
expect_failure_contains \
    "stale file-size pin fails" \
    "$stale_repo" \
    "stale allowlist entry"

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

summary_violation_repo="$(new_repo summary-violation)"
write_lines "$summary_violation_repo/src/lib.rs" 651
printf 'src/lib.rs 650 # summary violation fixture pin\n' > \
    "$summary_violation_repo/scripts/file-size-allowlist.txt"
git_hermetic "$summary_violation_repo" add src/lib.rs scripts/file-size-allowlist.txt
expect_success_contains \
    "file-size summary is report-only" \
    "$summary_violation_repo" \
    $'src/lib.rs\t650\t651\t-1' \
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

corrupt_debt_repo="$(new_repo corrupt-debt-log)"
printf '// small file\n' > "$corrupt_debt_repo/src/lib.rs"
printf 'not-json\n' > "$corrupt_debt_repo/scripts/file-size-debt-log.jsonl"
git_hermetic "$corrupt_debt_repo" add src/lib.rs
expect_failure_contains \
    "corrupt debt JSONL fails" \
    "$corrupt_debt_repo" \
    "invalid"

missing_key_debt_repo="$(new_repo missing-key-debt-log)"
printf '// small file\n' > "$missing_key_debt_repo/src/lib.rs"
printf '{}\n' > "$missing_key_debt_repo/scripts/file-size-debt-log.jsonl"
git_hermetic "$missing_key_debt_repo" add src/lib.rs
if output="$(run_check_without_json_tools "$missing_key_debt_repo" 2>&1)"; then
    printf 'not ok - fallback rejects empty debt JSON object\nexpected failure\nactual output:\n%s\n' \
        "$output" >&2
    exit 1
fi
if [[ "$output" != *"missing mandatory debt-log key"* ]]; then
    printf 'not ok - fallback rejects empty debt JSON object\nactual output:\n%s\n' \
        "$output" >&2
    exit 1
fi
printf 'ok - fallback rejects empty debt JSON object\n'

garbage_object_debt_repo="$(new_repo garbage-object-debt-log)"
printf '// small file\n' > "$garbage_object_debt_repo/src/lib.rs"
printf '{garbage}\n' > "$garbage_object_debt_repo/scripts/file-size-debt-log.jsonl"
git_hermetic "$garbage_object_debt_repo" add src/lib.rs
if output="$(run_check_without_json_tools "$garbage_object_debt_repo" 2>&1)"; then
    printf 'not ok - fallback rejects garbage debt JSON object\nexpected failure\nactual output:\n%s\n' \
        "$output" >&2
    exit 1
fi
if [[ "$output" != *"missing mandatory debt-log key"* ]]; then
    printf 'not ok - fallback rejects garbage debt JSON object\nactual output:\n%s\n' \
        "$output" >&2
    exit 1
fi
printf 'ok - fallback rejects garbage debt JSON object\n'

log_arg_repo="$(new_repo log-debt-args)"
expect_failure_contains \
    "log-debt rejects missing reason" \
    "$log_arg_repo" \
    "usage:" \
    --log-debt src/lib.rs - 700
expect_failure_contains \
    "log-debt rejects invalid new cap" \
    "$log_arg_repo" \
    "new cap must be an integer" \
    --log-debt src/lib.rs - nope "bad cap fixture"
