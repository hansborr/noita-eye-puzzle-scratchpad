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

test_rs_repo="$(new_repo test-rust-file)"
mkdir -p "$test_rs_repo/tests"
cat > "$test_rs_repo/src/lib.rs" <<'RS'
pub fn demo() {}
RS
cat > "$test_rs_repo/tests/allow_integration.rs" <<'RS'
#![allow(clippy::unwrap_used, reason = "positive control")]
#[test]
fn demo() {}
RS
stage_src "$test_rs_repo"
git_hermetic "$test_rs_repo" add tests/allow_integration.rs
expect_failure_contains \
    "unregistered safety allow in tests fails" \
    "$test_rs_repo" \
    "tests/allow_integration.rs"

cfg_attr_repo="$(new_repo cfg-attr)"
cat > "$cfg_attr_repo/src/lib.rs" <<'RS'
#[cfg_attr(not(test), allow(clippy::indexing_slicing, reason = "positive control"))]
pub fn demo() {}
RS
stage_src "$cfg_attr_repo"
expect_failure_contains \
    "cfg_attr-wrapped safety allow fails" \
    "$cfg_attr_repo" \
    "clippy::indexing_slicing"

doc_comment_repo="$(new_repo doc-comment)"
cat > "$doc_comment_repo/src/lib.rs" <<'RS'
/// see #[allow(clippy::unwrap_used)] in the suppression policy
/* and ignore #[expect(clippy::panic)] inside block comments */
pub fn demo() {}
RS
stage_src "$doc_comment_repo"
expect_success_contains \
    "doc and block comment allow prose is ignored" \
    "$doc_comment_repo" \
    "0 safety-gated"

string_repo="$(new_repo string-literal)"
cat > "$string_repo/src/lib.rs" <<'RS'
pub const NORMAL: &str = "#[allow(clippy::panic)]";
pub const RAW: &str = r#"#[expect(clippy::unwrap_used)]"#;
RS
stage_src "$string_repo"
expect_success_contains \
    "string literal allow prose is ignored" \
    "$string_repo" \
    "0 safety-gated"

broad_repo="$(new_repo broad-group)"
cat > "$broad_repo/src/lib.rs" <<'RS'
#[allow(warnings, reason = "positive control")]
pub fn demo() {}
RS
stage_src "$broad_repo"
expect_failure_contains \
    "broad lint group allow fails" \
    "$broad_repo" \
    "canonical warnings"

non_safety_repo="$(new_repo non-safety)"
cat > "$non_safety_repo/src/lib.rs" <<'RS'
#[allow(clippy::too_many_lines, reason = "positive control")]
pub fn demo() {}
RS
stage_src "$non_safety_repo"
expect_success_contains \
    "non-safety allow passes" \
    "$non_safety_repo" \
    "0 safety-gated"

let_underscore_repo="$(new_repo let-underscore)"
cat > "$let_underscore_repo/src/lib.rs" <<'RS'
#[allow(let_underscore_must_use, reason = "positive control")]
pub fn demo() {}
RS
stage_src "$let_underscore_repo"
expect_failure_contains \
    "let_underscore_must_use allow fails" \
    "$let_underscore_repo" \
    "clippy::let_underscore_must_use"

map_err_repo="$(new_repo map-err)"
cat > "$map_err_repo/src/lib.rs" <<'RS'
#[allow(clippy::map_err_ignore, reason = "positive control")]
pub fn demo() {}
RS
stage_src "$map_err_repo"
expect_failure_contains \
    "map_err_ignore allow fails" \
    "$map_err_repo" \
    "clippy::map_err_ignore"

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

reasonless_repo="$(new_repo reasonless-register)"
cat > "$reasonless_repo/src/lib.rs" <<'RS'
#![allow(clippy::unwrap_used, reason = "positive control")]
pub fn demo() {}
RS
printf 'src/lib.rs:1:clippy::unwrap_used #\n' > \
    "$reasonless_repo/scripts/suppression-register.txt"
stage_src "$reasonless_repo"
expect_failure_contains \
    "reasonless suppression register entry fails" \
    "$reasonless_repo" \
    "entry needs a non-empty reason"

malformed_repo="$(new_repo malformed-register)"
cat > "$malformed_repo/src/lib.rs" <<'RS'
#![allow(clippy::unwrap_used, reason = "positive control")]
pub fn demo() {}
RS
printf 'src/lib.rs:1 clippy::unwrap_used # malformed positive control\n' > \
    "$malformed_repo/scripts/suppression-register.txt"
stage_src "$malformed_repo"
expect_failure_contains \
    "malformed suppression register entry fails" \
    "$malformed_repo" \
    "malformed"

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
