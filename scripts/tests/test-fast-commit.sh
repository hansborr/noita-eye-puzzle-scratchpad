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

commit_index() {
    local repo="$1"
    local message="$2"

    git_hermetic "$repo" commit -q -m "$message"
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

install_stub_toolchain() {
    local bin_dir="$1"

    mkdir -p -- "$bin_dir"
    cat > "$bin_dir/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

: "${NOITA_STUB_LOG:?}"
printf 'cargo' >> "$NOITA_STUB_LOG"
for arg in "$@"; do
    printf '\t%s' "$arg" >> "$NOITA_STUB_LOG"
done
printf '\n' >> "$NOITA_STUB_LOG"
exit 0
SH
    cat > "$bin_dir/cargo-deny" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

: "${NOITA_STUB_LOG:?}"
printf 'cargo-deny' >> "$NOITA_STUB_LOG"
for arg in "$@"; do
    printf '\t%s' "$arg" >> "$NOITA_STUB_LOG"
done
printf '\n' >> "$NOITA_STUB_LOG"
exit 0
SH
    chmod +x "$bin_dir/cargo" "$bin_dir/cargo-deny"
}

install_execution_stubs() {
    local repo="$1"
    local script

    mkdir -p -- "$repo/scripts"
    for script in check-blob-size.sh check-suppressions.sh check-file-size.sh; do
        cat > "$repo/scripts/$script" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
exit 0
SH
        chmod +x "$repo/scripts/$script"
    done
    git_hermetic "$repo" add scripts
    commit_index "$repo" "add hook stubs"
}

new_execution_repo() {
    local name="$1"
    local repo

    repo="$(mktemp -d "$tmp_root/repo-exec-$name.XXXXXX")"
    git_hermetic "$repo" init -q -b feature/fast-commit-exec
    install_execution_stubs "$repo"
    mkdir -p -- "$repo/src"
    printf 'pub fn staged() {}\n' > "$repo/src/lib.rs"
    git_hermetic "$repo" add src/lib.rs
    printf '%s\n' "$repo"
}

new_docs_execution_repo() {
    local name="$1"
    local repo

    repo="$(mktemp -d "$tmp_root/repo-exec-$name.XXXXXX")"
    git_hermetic "$repo" init -q -b feature/fast-commit-exec
    install_execution_stubs "$repo"
    printf 'docs\n' > "$repo/README.md"
    git_hermetic "$repo" add README.md
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

run_real_commit() {
    local repo="$1"
    local log_file="$2"
    local message="$3"
    shift 3

    env PATH="$stub_bin:$PATH" NOITA_STUB_LOG="$log_file" "$@" \
        git \
        -C "$repo" \
        -c core.hooksPath="$repo_root/.githooks" \
        -c commit.gpgsign=false \
        -c user.name=t \
        -c user.email=t@e \
        commit -q -m "$message"
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

expect_plan_failure_status_contains() {
    local name="$1"
    local repo="$2"
    local want_status="$3"
    local needle="$4"
    local output
    local status
    shift 4

    if output="$(run_plan "$repo" "$@" 2>&1)"; then
        status=0
    else
        status=$?
    fi
    if (( status != want_status )); then
        printf 'not ok - %s\nexpected status: %s\nactual status: %s\nactual output:\n%s\n' \
            "$name" "$want_status" "$status" "$output" >&2
        exit 1
    fi
    if [[ "$output" != *"$needle"* ]]; then
        printf 'not ok - %s\nexpected output to contain: %s\nactual output:\n%s\n' \
            "$name" "$needle" "$output" >&2
        exit 1
    fi
    printf 'ok - %s\n' "$name"
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

expect_log_has() {
    local name="$1"
    local log_file="$2"
    local pattern="$3"

    if [[ ! -f "$log_file" ]] || ! grep -Fq "$pattern" "$log_file"; then
        printf 'not ok - %s\nmissing command pattern: %s\nactual log:\n' \
            "$name" "$pattern" >&2
        if [[ -f "$log_file" ]]; then
            cat "$log_file" >&2
        fi
        exit 1
    fi
}

expect_log_lacks() {
    local name="$1"
    local log_file="$2"
    local pattern="$3"

    if [[ -f "$log_file" ]] && grep -Fq "$pattern" "$log_file"; then
        printf 'not ok - %s\nunexpected command pattern: %s\nactual log:\n' \
            "$name" "$pattern" >&2
        cat "$log_file" >&2
        exit 1
    fi
}

expect_deny_logged() {
    local name="$1"
    local log_file="$2"

    if [[ -f "$log_file" ]] &&
        { grep -Fq $'cargo\tdeny\tcheck' "$log_file" ||
            grep -Fq $'cargo-deny\tcheck' "$log_file"; }; then
        return 0
    fi

    printf 'not ok - %s\nmissing cargo-deny invocation\nactual log:\n' "$name" >&2
    if [[ -f "$log_file" ]]; then
        cat "$log_file" >&2
    fi
    exit 1
}

expect_notice_once() {
    local name="$1"
    local output="$2"
    local count

    count="$(grep -Fc "FAST-COMMIT MODE ENABLED" <<< "$output" || true)"
    if [[ "$count" != "1" ]]; then
        printf 'not ok - %s\nexpected one fast-commit notice, saw: %s\nactual output:\n%s\n' \
            "$name" "$count" "$output" >&2
        exit 1
    fi
}

expect_commit_success() {
    local name="$1"
    local repo="$2"
    local log_file="$3"
    local message="$4"
    local output
    shift 4

    if ! output="$(run_real_commit "$repo" "$log_file" "$message" "$@" 2>&1)"; then
        printf 'not ok - %s\ncommit failed\n%s\n' "$name" "$output" >&2
        exit 1
    fi
    printf '%s\n' "$output"
}

stub_bin="$tmp_root/bin"
install_stub_toolchain "$stub_bin"

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

relative_marker_repo="$(new_repo relative-marker)"
expect_plan_failure_status_contains \
    "relative env marker is rejected" \
    "$relative_marker_repo" \
    2 \
    "NOITA_FAST_COMMIT_MARKER must be an absolute path" \
    NOITA_FAST_COMMIT_MARKER=relative-marker

empty_marker_repo="$(new_repo empty-marker)"
enable_default_marker "$empty_marker_repo"
empty_marker_output="$(run_plan "$empty_marker_repo" NOITA_FAST_COMMIT_MARKER= 2>&1)"
expect_fast_plan "empty env marker falls back to default marker" "$empty_marker_output"

fast_exec_repo="$(new_execution_repo fast-marker)"
enable_default_marker "$fast_exec_repo"
fast_exec_log="$tmp_root/fast-exec-cargo.log"
fast_exec_output="$(expect_commit_success \
    "fast-commit execution commit succeeds" \
    "$fast_exec_repo" \
    "$fast_exec_log" \
    "exercise fast commit")"
expect_log_has "fast-commit execution runs rustfmt" "$fast_exec_log" $'cargo\tfmt\t--check'
expect_log_has "fast-commit execution runs clippy" "$fast_exec_log" $'cargo\tclippy\t--all-targets'
expect_log_lacks "fast-commit execution skips tests" "$fast_exec_log" $'cargo\ttest'
expect_log_lacks "fast-commit execution skips rustdoc" "$fast_exec_log" $'cargo\tdoc'
expect_deny_logged "fast-commit execution keeps supply-chain check" "$fast_exec_log"
expect_notice_once "fast-commit execution prints notice once" "$fast_exec_output"
printf 'ok - fast-commit execution skips only slow Rust slots\n'

docs_exec_repo="$(new_docs_execution_repo docs-marker)"
enable_default_marker "$docs_exec_repo"
docs_exec_log="$tmp_root/docs-exec-cargo.log"
docs_exec_output="$(expect_commit_success \
    "docs-only fast-commit execution commit succeeds" \
    "$docs_exec_repo" \
    "$docs_exec_log" \
    "exercise docs fast commit")"
expect_notice_once "docs-only fast-commit execution prints notice once" "$docs_exec_output"
expect_log_lacks "docs-only fast-commit execution does not run cargo" "$docs_exec_log" "cargo"
printf 'ok - fast-commit notice does not depend on Rust gate\n'

default_exec_repo="$(new_execution_repo default-exec)"
default_exec_log="$tmp_root/default-exec-cargo.log"
default_exec_output="$(expect_commit_success \
    "default execution commit succeeds" \
    "$default_exec_repo" \
    "$default_exec_log" \
    "exercise default commit")"
expect_log_has "default execution runs tests" "$default_exec_log" $'cargo\ttest\t--locked'
expect_log_has "default execution runs rustdoc" "$default_exec_log" $'cargo\tdoc\t--no-deps'
expect_deny_logged "default execution keeps supply-chain check" "$default_exec_log"
if [[ "$default_exec_output" == *"FAST-COMMIT MODE ENABLED"* ]]; then
    printf 'not ok - default execution does not print fast-commit notice\nactual output:\n%s\n' \
        "$default_exec_output" >&2
    exit 1
fi
printf 'ok - default execution runs slow Rust slots\n'
