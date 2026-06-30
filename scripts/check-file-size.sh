#!/usr/bin/env bash
# Rust file-size ratchet. Fails when a tracked *.rs file exceeds its line budget:
#   - the default MAX_RS_LINES (600) for any file, or
#   - a per-file pin in scripts/file-size-allowlist.txt for the existing oversized
#     modules being shrunk (each pin names how it will shrink).
# Pins ratchet DOWN only:
#   over the pin -> fail (no growth); far under the pin -> fail (lower it);
#   under MAX_RS_LINES -> fail (delete the now-redundant pin).
# Debt log:
#   scripts/file-size-debt-log.jsonl is append-only JSONL for justified new
#   pins or raised pins above the default cap. Use:
#   ./scripts/check-file-size.sh --log-debt <path> <old|-> <new> <reason>
set -euo pipefail

max_default="${MAX_RS_LINES:-600}"
slack="${FILE_SIZE_SLACK:-50}"
allowlist="scripts/file-size-allowlist.txt"
debt_log="scripts/file-size-debt-log.jsonl"
mode="check"

usage() {
    cat >&2 <<EOF
usage:
  $0
  $0 --summary
  $0 --log-debt <path> <old|-> <new> <reason>
EOF
}

cd "$(git rev-parse --show-toplevel)" || exit 1

declare -A cap          # path -> pinned max lines
declare -A pin_seen     # path -> 1 once matched to a tracked file
declare -A actual_lines  # path -> actual tracked line count

require_python3() {
    if ! command -v python3 >/dev/null 2>&1; then
        printf 'file-size: python3 is required to validate %s\n' "$debt_log" >&2
        exit 1
    fi
}

validate_debt_log() {
    if [[ ! -f "$debt_log" ]]; then
        return 0
    fi

    require_python3
    python3 - "$debt_log" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    for line_no, line in enumerate(handle, 1):
        if not line.strip():
            print(f"file-size: {path}:{line_no}: blank JSONL line", file=sys.stderr)
            sys.exit(1)
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            print(f"file-size: {path}:{line_no}: invalid JSON: {error}", file=sys.stderr)
            sys.exit(1)
        if not isinstance(entry, dict):
            print(f"file-size: {path}:{line_no}: entry must be a JSON object", file=sys.stderr)
            sys.exit(1)
        required = {"path", "old_cap", "new_cap", "reason"}
        missing = sorted(required.difference(entry))
        if missing:
            joined = ", ".join(missing)
            print(f"file-size: {path}:{line_no}: missing key(s): {joined}", file=sys.stderr)
            sys.exit(1)
        if not isinstance(entry["path"], str) or not entry["path"]:
            print(f"file-size: {path}:{line_no}: path must be a non-empty string", file=sys.stderr)
            sys.exit(1)
        if entry["old_cap"] is not None and not isinstance(entry["old_cap"], int):
            print(f"file-size: {path}:{line_no}: old_cap must be an integer or null", file=sys.stderr)
            sys.exit(1)
        if not isinstance(entry["new_cap"], int):
            print(f"file-size: {path}:{line_no}: new_cap must be an integer", file=sys.stderr)
            sys.exit(1)
        if not isinstance(entry["reason"], str) or not entry["reason"]:
            print(f"file-size: {path}:{line_no}: reason must be a non-empty string", file=sys.stderr)
            sys.exit(1)
PY
}

log_debt() {
    local path="$1"
    local old_cap="$2"
    local new_cap="$3"
    local reason="$4"

    validate_debt_log
    if [[ -z "$path" ]]; then
        printf 'file-size: --log-debt path must be non-empty\n' >&2
        exit 1
    fi
    if [[ "$old_cap" != "-" && ! "$old_cap" =~ ^[0-9]+$ ]]; then
        printf 'file-size: --log-debt old cap must be an integer or "-"\n' >&2
        exit 1
    fi
    if ! [[ "$new_cap" =~ ^[0-9]+$ ]]; then
        printf 'file-size: --log-debt new cap must be an integer\n' >&2
        exit 1
    fi
    if [[ -z "$reason" ]]; then
        printf 'file-size: --log-debt reason must be non-empty\n' >&2
        exit 1
    fi

    require_python3
    python3 - "$debt_log" "$path" "$old_cap" "$new_cap" "$reason" <<'PY'
import json
import sys

log_path, path, old_cap, new_cap, reason = sys.argv[1:]
entry = {
    "path": path,
    "old_cap": None if old_cap == "-" else int(old_cap),
    "new_cap": int(new_cap),
    "reason": reason,
}
with open(log_path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(entry, ensure_ascii=True, separators=(",", ":")) + "\n")
PY
    validate_debt_log
    printf 'file-size: logged debt for %s (%s -> %s)\n' "$path" "$old_cap" "$new_cap"
}

print_summary() {
    printf 'file-size: summary (default cap %d, slack %d)\n' "$max_default" "$slack"
    if (( ${#cap[@]} == 0 )); then
        printf 'file-size: no per-file pins\n'
        return 0
    fi

    printf 'path\tpin\tactual\theadroom\n'
    while IFS= read -r p; do
        if [[ -n "${actual_lines[$p]+x}" ]]; then
            printf '%s\t%d\t%d\t%d\n' \
                "$p" "${cap[$p]}" "${actual_lines[$p]}" "$((cap[$p] - actual_lines[$p]))"
        else
            printf '%s\t%d\tmissing\tn/a\n' "$p" "${cap[$p]}"
        fi
    done < <(printf '%s\n' "${!cap[@]}" | sort)
}

case "${1:-}" in
    "")
        ;;
    --summary)
        if (( $# != 1 )); then
            usage
            exit 2
        fi
        mode="summary"
        ;;
    --log-debt)
        if (( $# < 5 )); then
            usage
            exit 2
        fi
        log_path="$2"
        log_old="$3"
        log_new="$4"
        shift 4
        log_reason="$*"
        log_debt "$log_path" "$log_old" "$log_new" "$log_reason"
        exit 0
        ;;
    *)
        usage
        exit 2
        ;;
esac

validate_debt_log

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
        actual_lines["$f"]="$lines"
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

if [[ "$mode" == "summary" ]]; then
    print_summary
fi

if (( violations > 0 || stale > 0 )); then
    printf 'file-size: %d over/under-budget, %d stale pin(s). See scripts/file-size-allowlist.txt\n' \
        "$violations" "$stale" >&2
    exit 1
fi

printf 'file-size: OK (%s Rust files within budget; default cap %d)\n' \
    "$(git ls-files -- '*.rs' | wc -l | tr -d '[:space:]')" "$max_default"
