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
    local branch="$1"
    local name="${branch//\//-}"
    local repo

    repo="$(mktemp -d "$tmp_root/repo-$name.XXXXXX")"
    git_hermetic "$repo" init -q -b "$branch"
    printf '%s\n' "$repo"
}

commit_index() {
    local repo="$1"
    local message="$2"

    git_hermetic "$repo" commit -q -m "$message"
}

run_hook() {
    local repo="$1"
    shift

    (
        cd "$repo"
        env PRECOMMIT_GUARDS_ONLY=1 "$@" "$hook"
    )
}

run_full_hook() {
    local repo="$1"
    shift

    (
        cd "$repo"
        "$@" "$hook"
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

expect_full_hook_success() {
    local name="$1"
    local repo="$2"
    local output
    shift 2

    if ! output="$(run_full_hook "$repo" "$@" 2>&1)"; then
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

install_stub_guards() {
    local repo="$1"

    mkdir -p -- "$repo/scripts"
    cat > "$repo/scripts/check-blob-size.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p hook-runs
printf 'blob\n' >> hook-runs/blob-size
SH
    cat > "$repo/scripts/check-suppressions.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p hook-runs
printf 'suppressions\n' >> hook-runs/suppressions
SH
    chmod +x "$repo/scripts/check-blob-size.sh" "$repo/scripts/check-suppressions.sh"
    git -C "$repo" add scripts/check-blob-size.sh scripts/check-suppressions.sh
    commit_index "$repo" "add stub guards"
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

master_repo="$(new_repo master)"
expect_failure_contains \
    "protected branch rejects master" \
    "$master_repo" \
    "refusing to commit directly on master"

detached_repo="$(new_repo main)"
printf 'base\n' > "$detached_repo/README.md"
git -C "$detached_repo" add README.md
commit_index "$detached_repo" "initial commit"
detached_sha="$(git -C "$detached_repo" rev-parse HEAD)"
git -C "$detached_repo" checkout -q "$detached_sha"
expect_success \
    "protected branch allows detached HEAD" \
    "$detached_repo"

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

root_toml_untracked_repo="$(new_repo feature/root-toml-untracked)"
printf '[advisories]\n' > "$root_toml_untracked_repo/deny.toml"
expect_failure_contains \
    "dirty guard rejects untracked root toml" \
    "$root_toml_untracked_repo" \
    "deny.toml"

root_toml_unstaged_repo="$(new_repo feature/root-toml-unstaged)"
printf '[advisories]\n' > "$root_toml_unstaged_repo/deny.toml"
git -C "$root_toml_unstaged_repo" add deny.toml
commit_index "$root_toml_unstaged_repo" "add deny config"
printf 'ignore = []\n' >> "$root_toml_unstaged_repo/deny.toml"
expect_failure_contains \
    "dirty guard rejects unstaged root toml" \
    "$root_toml_unstaged_repo" \
    "deny.toml"

nested_toml_repo="$(new_repo feature/nested-toml)"
mkdir -p -- "$nested_toml_repo/docs"
printf '[notes]\n' > "$nested_toml_repo/docs/foo.toml"
expect_success \
    "dirty guard ignores nested non-cargo toml" \
    "$nested_toml_repo"

fixture_repo="$(new_repo feature/embedded-fixture)"
mkdir -p -- "$fixture_repo/research/data/lang"
printf 'word\n' > "$fixture_repo/research/data/lang/english.txt"
expect_failure_contains \
    "dirty guard rejects untracked embedded fixture" \
    "$fixture_repo" \
    "research/data/lang/english.txt"

unrelated_repo="$(new_repo feature/unrelated-untracked)"
printf 'scratch\n' > "$unrelated_repo/notes.txt"
expect_success \
    "dirty guard ignores unrelated untracked paths" \
    "$unrelated_repo"

docs_only_repo="$(new_repo feature/docs-only-wiring)"
install_stub_guards "$docs_only_repo"
printf 'docs\n' > "$docs_only_repo/README.md"
git -C "$docs_only_repo" add README.md
expect_full_hook_success \
    "pre-commit skips suppressions for docs-only commits" \
    "$docs_only_repo"
if [[ ! -f "$docs_only_repo/hook-runs/blob-size" ]]; then
    printf 'not ok - pre-commit skips suppressions for docs-only commits\nblob-size did not run\n' >&2
    exit 1
fi
if [[ -f "$docs_only_repo/hook-runs/suppressions" ]]; then
    printf 'not ok - pre-commit skips suppressions for docs-only commits\nsuppressions unexpectedly ran\n' >&2
    exit 1
fi

register_repo="$(new_repo feature/register-wiring)"
install_stub_guards "$register_repo"
: > "$register_repo/scripts/suppression-register.txt"
git -C "$register_repo" add scripts/suppression-register.txt
expect_full_hook_success \
    "pre-commit runs suppressions for register changes" \
    "$register_repo"
if [[ ! -f "$register_repo/hook-runs/suppressions" ]]; then
    printf 'not ok - pre-commit runs suppressions for register changes\nsuppressions did not run\n' >&2
    exit 1
fi

renamed_rs_repo="$(new_repo feature/renamed-rs-suppressions)"
install_stub_guards "$renamed_rs_repo"
mkdir -p -- "$renamed_rs_repo/src"
printf 'pub fn old_path() {}\n' > "$renamed_rs_repo/src/old.rs"
git -C "$renamed_rs_repo" add src/old.rs
commit_index "$renamed_rs_repo" "add rust source"
git -C "$renamed_rs_repo" mv src/old.rs notes.txt
expect_full_hook_success \
    "pre-commit runs suppressions for Rust files renamed away" \
    "$renamed_rs_repo"
if [[ ! -f "$renamed_rs_repo/hook-runs/suppressions" ]]; then
    printf 'not ok - pre-commit runs suppressions for Rust files renamed away\nsuppressions did not run\n' >&2
    exit 1
fi
