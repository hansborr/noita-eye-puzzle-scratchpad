#!/usr/bin/env bash
# Rust file-size ratchet. Fails when a tracked *.rs file exceeds its line budget:
#   - the default MAX_RS_LINES (600) for any file, or
#   - a per-file pin in scripts/file-size-allowlist.txt for the existing oversized
#     modules the refactor campaign is shrinking (docs/refactor/06,07a,07b).
# Pins ratchet DOWN only (see docs/refactor/09-file-size-ratchet.md):
#   over the pin -> fail (no growth); far under the pin -> fail (lower it);
#   under MAX_RS_LINES -> fail (delete the now-redundant pin).
set -euo pipefail

max_default="${MAX_RS_LINES:-600}"
slack="${FILE_SIZE_SLACK:-50}"
allowlist="scripts/file-size-allowlist.txt"

cd "$(git rev-parse --show-toplevel)" || exit 1

declare -A cap          # path -> pinned max lines
declare -A pin_seen     # path -> 1 once matched to a tracked file

if [[ -f "$allowlist" ]]; then
    lineno=0
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        lineno=$((lineno + 1))
        line="${raw#"${raw%%[![:space:]]*}"}"          # ltrim
        if [[ -z "$line" || "${line:0:1}" == "#" ]]; then
            continue
        fi
        if [[ "$line" != *"#"* ]]; then
            printf 'file-size: %s:%d: entry needs a "# reason": %s\n' \
                "$allowlist" "$lineno" "$line" >&2
            exit 1
        fi
        path="${line%%[[:space:]]*}"
        rest="${line#"$path"}"
        rest="${rest#"${rest%%[![:space:]]*}"}"         # ltrim
        num="${rest%%[[:space:]#]*}"
        if [[ -z "$path" || ! "$num" =~ ^[0-9]+$ ]]; then
            printf 'file-size: %s:%d: malformed (want "<path> <max> # reason"): %s\n' \
                "$allowlist" "$lineno" "$line" >&2
            exit 1
        fi
        cap["$path"]="$num"
    done < "$allowlist"
fi

violations=0
stale=0

while IFS= read -r -d '' f; do
    lines="$(wc -l < "$f")"
    lines="${lines//[[:space:]]/}"
    if [[ -n "${cap[$f]+x}" ]]; then
        pin_seen["$f"]=1
        limit="${cap[$f]}"
        if (( lines <= max_default )); then
            printf 'file-size: %s is %d lines (<= %d) — delete its line from %s\n' \
                "$f" "$lines" "$max_default" "$allowlist" >&2
            violations=$((violations + 1))
        elif (( lines > limit )); then
            printf 'file-size: %s grew to %d lines (pin %d) — pins may not grow\n' \
                "$f" "$lines" "$limit" >&2
            violations=$((violations + 1))
        elif (( lines < limit - slack )); then
            printf 'file-size: %s shrank to %d lines (pin %d) — lower its pin\n' \
                "$f" "$lines" "$limit" >&2
            violations=$((violations + 1))
        fi
    elif (( lines > max_default )); then
        printf 'file-size: %s is %d lines (cap %d) — split it or add a justified pin\n' \
            "$f" "$lines" "$max_default" >&2
        violations=$((violations + 1))
    fi
done < <(git ls-files -z -- '*.rs')

for p in "${!cap[@]}"; do
    if [[ -z "${pin_seen[$p]+x}" ]]; then
        printf 'file-size: stale allowlist entry for missing file: %s\n' "$p" >&2
        stale=$((stale + 1))
    fi
done

if (( violations > 0 || stale > 0 )); then
    printf 'file-size: %d over/under-budget, %d stale pin(s). See docs/refactor/09-file-size-ratchet.md\n' \
        "$violations" "$stale" >&2
    exit 1
fi

printf 'file-size: OK (%s Rust files within budget; default cap %d)\n' \
    "$(git ls-files -- '*.rs' | wc -l | tr -d '[:space:]')" "$max_default"
