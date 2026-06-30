#!/usr/bin/env bash
# Staged blob-size guard. Checks index blobs, not working-tree bytes, so the
# gate measures exactly what the commit would add or modify.
set -euo pipefail

warn_bytes="${BLOB_WARN_BYTES:-524288}"
block_bytes="${BLOB_BLOCK_BYTES:-2097152}"
allowlist="scripts/blob-size-allowlist.txt"

cd "$(git rev-parse --show-toplevel)" || exit 1

declare -A allowlisted

ltrim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    printf '%s' "$value"
}

rtrim() {
    local value="$1"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

trim() {
    local value="$1"
    value="$(ltrim "$value")"
    rtrim "$value"
}

human_bytes() {
    local bytes="$1"

    if (( bytes >= 1048576 )); then
        awk -v bytes="$bytes" 'BEGIN { printf "%.1f MiB", bytes / 1048576 }'
    elif (( bytes >= 1024 )); then
        awk -v bytes="$bytes" 'BEGIN { printf "%.1f KiB", bytes / 1024 }'
    else
        printf '%d bytes' "$bytes"
    fi
}

if ! [[ "$warn_bytes" =~ ^[0-9]+$ && "$block_bytes" =~ ^[0-9]+$ ]]; then
    printf 'blob-size: BLOB_WARN_BYTES and BLOB_BLOCK_BYTES must be integer byte counts\n' >&2
    exit 1
fi
if (( warn_bytes <= 0 || block_bytes <= warn_bytes )); then
    printf 'blob-size: require 0 < BLOB_WARN_BYTES < BLOB_BLOCK_BYTES\n' >&2
    exit 1
fi

if [[ -f "$allowlist" ]]; then
    lineno=0
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        lineno=$((lineno + 1))
        line="$(ltrim "$raw")"
        if [[ -z "$line" || "${line:0:1}" == "#" ]]; then
            continue
        fi
        if [[ "$line" != *"#"* ]]; then
            printf 'blob-size: %s:%d: entry needs a "# reason": %s\n' \
                "$allowlist" "$lineno" "$line" >&2
            exit 1
        fi

        path="$(trim "${line%%#*}")"
        reason="$(ltrim "${line#*#}")"
        if [[ -z "$path" || "$path" == *[[:space:]]* ]]; then
            printf 'blob-size: %s:%d: malformed (want "<path> # reason"): %s\n' \
                "$allowlist" "$lineno" "$line" >&2
            exit 1
        fi
        if [[ -z "$reason" ]]; then
            printf 'blob-size: %s:%d: entry needs a non-empty reason: %s\n' \
                "$allowlist" "$lineno" "$line" >&2
            exit 1
        fi
        allowlisted["$path"]=1
    done < "$allowlist"
fi

stale=0
for path in "${!allowlisted[@]}"; do
    if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
        printf 'blob-size: stale allowlist entry for missing tracked path: %s\n' "$path" >&2
        stale=$((stale + 1))
    fi
done

checked=0
warnings=0
blocks=0
while IFS= read -r -d '' path; do
    if [[ -n "${allowlisted[$path]+x}" ]]; then
        continue
    fi

    index_entry="$(git ls-files -s -- "$path")"
    mode="${index_entry%% *}"
    if [[ "$mode" == "160000" ]]; then
        printf 'blob-size: skipping staged gitlink: %s\n' "$path" >&2
        continue
    fi

    if ! size="$(git cat-file -s ":$path" 2>/dev/null)"; then
        printf 'blob-size: skipping staged non-blob path: %s\n' "$path" >&2
        continue
    fi

    checked=$((checked + 1))
    if (( size >= block_bytes )); then
        printf 'blob-size: %s is %s (%d bytes), exceeding block threshold %s; add to %s as "%s # reason" only if intentional\n' \
            "$path" "$(human_bytes "$size")" "$size" "$(human_bytes "$block_bytes")" "$allowlist" "$path" >&2
        blocks=$((blocks + 1))
    elif (( size >= warn_bytes )); then
        printf 'blob-size: warning: %s is %s (%d bytes), at or above warning threshold %s; consider splitting/compressing or allowlisting with a reason\n' \
            "$path" "$(human_bytes "$size")" "$size" "$(human_bytes "$warn_bytes")" >&2
        warnings=$((warnings + 1))
    fi
done < <(git diff --cached --no-renames --name-only -z --diff-filter=ACM)

if (( blocks > 0 || stale > 0 )); then
    printf 'blob-size: %d blocked blob(s), %d warning(s), %d stale allowlist entry(s). See %s\n' \
        "$blocks" "$warnings" "$stale" "$allowlist" >&2
    exit 1
fi

printf 'blob-size: OK (%d staged blob(s) checked; %d warning(s); warn %s, block %s)\n' \
    "$checked" "$warnings" "$(human_bytes "$warn_bytes")" "$(human_bytes "$block_bytes")"
