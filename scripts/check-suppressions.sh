#!/usr/bin/env bash
# Rust allow/expect inventory and safety-suppression register.
#
# The scan is a fast src/ text pass (<1s on the current tree), so pre-commit
# runs it on every commit. Clippy already enforces reasons for all allows; this
# gate covers the part clippy cannot audit: safety/correctness lints hidden by
# an allow/expect.
set -euo pipefail

register="scripts/suppression-register.txt"
mode="gate"

if (( $# > 1 )); then
    printf 'usage: %s [--summary]\n' "$0" >&2
    exit 2
fi
if (( $# == 1 )); then
    case "$1" in
        --summary)
            mode="summary"
            ;;
        *)
            printf 'usage: %s [--summary]\n' "$0" >&2
            exit 2
            ;;
    esac
fi

cd "$(git rev-parse --show-toplevel)" || exit 1

tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

inventory="$tmp_dir/inventory.tsv"
safety_inventory="$tmp_dir/safety.tsv"
: > "$inventory"
: > "$safety_inventory"

declare -A registered
declare -A current_safety

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

canonical_safety_lint() {
    local lint="$1"

    case "$lint" in
        clippy::unwrap_used | unwrap_used)
            printf 'clippy::unwrap_used'
            ;;
        clippy::get_unwrap | get_unwrap)
            printf 'clippy::get_unwrap'
            ;;
        clippy::panic | panic)
            printf 'clippy::panic'
            ;;
        clippy::panic_in_result_fn | panic_in_result_fn)
            printf 'clippy::panic_in_result_fn'
            ;;
        clippy::indexing_slicing | indexing_slicing)
            printf 'clippy::indexing_slicing'
            ;;
        clippy::string_slice | string_slice)
            printf 'clippy::string_slice'
            ;;
        clippy::unused_result_ok | unused_result_ok)
            printf 'clippy::unused_result_ok'
            ;;
        clippy::todo | todo)
            printf 'clippy::todo'
            ;;
        clippy::unimplemented | unimplemented)
            printf 'clippy::unimplemented'
            ;;
        clippy::dbg_macro | dbg_macro)
            printf 'clippy::dbg_macro'
            ;;
        unsafe_code | clippy::unsafe_code | rustc::unsafe_code)
            printf 'unsafe_code'
            ;;
        unused_results | clippy::unused_results | rustc::unused_results)
            printf 'unused_results'
            ;;
        *)
            return 1
            ;;
    esac
}

collect_inventory() {
    local src_files=()

    while IFS= read -r -d '' path; do
        src_files+=("$path")
    done < <(git ls-files -z -- 'src/*.rs')

    if (( ${#src_files[@]} == 0 )); then
        return 0
    fi

    perl - "${src_files[@]}" <<'PERL'
use strict;
use warnings;

sub trim {
    my ($value) = @_;
    $value =~ s/^\s+//;
    $value =~ s/\s+$//;
    return $value;
}

for my $file (@ARGV) {
    open my $fh, '<', $file or die "suppressions: cannot read $file: $!\n";
    local $/;
    my $text = <$fh>;
    close $fh or die "suppressions: cannot close $file: $!\n";

    while ($text =~ /#\s*!?\s*\[\s*(allow|expect)\s*\(/g) {
        my $kind = $1;
        my $start = $-[0];
        my $inner_start = pos($text);
        my $i = $inner_start;
        my $depth = 1;
        my $in_string = 0;
        my $escape = 0;

        while ($i < length $text) {
            my $char = substr($text, $i, 1);
            if ($in_string) {
                if ($escape) {
                    $escape = 0;
                } elsif ($char eq "\\") {
                    $escape = 1;
                } elsif ($char eq '"') {
                    $in_string = 0;
                }
                $i++;
                next;
            }

            if ($char eq '"') {
                $in_string = 1;
            } elsif ($char eq '(') {
                $depth++;
            } elsif ($char eq ')') {
                $depth--;
                last if $depth == 0;
            }
            $i++;
        }

        my $prefix = substr($text, 0, $start);
        my $line = 1 + ($prefix =~ tr/\n//);
        if ($depth != 0) {
            die "suppressions: $file:$line: malformed allow/expect attribute\n";
        }

        my $inner = substr($text, $inner_start, $i - $inner_start);
        pos($text) = $i + 1;

        my $reason = "";
        if ($inner =~ /\breason\s*=\s*"((?:\\.|[^"\\])*)"/s) {
            $reason = $1;
            $reason =~ s/\\n/ /g;
            $reason =~ s/\\"/"/g;
            $reason =~ s/\\\\/\\/g;
        }
        $reason =~ s/[\t\r\n]+/ /g;
        $reason = trim($reason);

        my $lint_part = $inner;
        $lint_part =~ s/\breason\s*=\s*"(?:\\.|[^"\\])*"\s*,?//gs;
        $lint_part =~ s{//[^\n]*}{}g;
        $lint_part =~ s{/\*.*?\*/}{}gs;

        for my $lint (split /,/, $lint_part) {
            $lint = trim($lint);
            next if $lint eq "";
            next if $lint =~ /=/;
            $lint =~ s/\s+//g;
            print join("\t", $file, $line, $kind, $lint, $reason), "\n";
        }
    }
}
PERL
}

print_summary() {
    local total
    total="$(wc -l < "$inventory" | tr -d '[:space:]')"
    printf 'suppressions: summary (%d lint entry(s))\n' "$total"

    if (( total == 0 )); then
        return 0
    fi

    printf 'suppressions: counts by lint\n'
    cut -f4 "$inventory" | sort | uniq -c | while read -r count lint; do
        printf '  %s %s\n' "$lint" "$count"
    done

    printf 'suppressions: inventory\n'
    sort -t "$(printf '\t')" -k1,1 -k2,2n -k4,4 "$inventory" |
        while IFS=$'\t' read -r path line kind lint reason; do
            printf '  %s:%s %s %s # %s\n' "$path" "$line" "$kind" "$lint" "$reason"
        done
}

parse_register() {
    if [[ ! -f "$register" ]]; then
        return 0
    fi

    local lineno=0
    local raw line before_hash reason entry path line_no lint canonical key
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        lineno=$((lineno + 1))
        line="$(ltrim "$raw")"
        if [[ -z "$line" || "${line:0:1}" == "#" ]]; then
            continue
        fi
        if [[ "$line" != *"#"* ]]; then
            printf 'suppressions: %s:%d: entry needs a "# reason": %s\n' \
                "$register" "$lineno" "$line" >&2
            exit 1
        fi

        before_hash="$(trim "${line%%#*}")"
        reason="$(ltrim "${line#*#}")"
        if [[ -z "$reason" ]]; then
            printf 'suppressions: %s:%d: entry needs a non-empty reason: %s\n' \
                "$register" "$lineno" "$line" >&2
            exit 1
        fi
        if [[ ! "$before_hash" =~ ^([^:]+):([0-9]+):([^[:space:]#]+)$ ]]; then
            printf 'suppressions: %s:%d: malformed (want "<path>:<line>:<lint> # reason"): %s\n' \
                "$register" "$lineno" "$line" >&2
            exit 1
        fi

        path="${BASH_REMATCH[1]}"
        line_no="${BASH_REMATCH[2]}"
        lint="${BASH_REMATCH[3]}"
        if ! canonical="$(canonical_safety_lint "$lint")"; then
            printf 'suppressions: %s:%d: registered lint is not safety-gated: %s\n' \
                "$register" "$lineno" "$lint" >&2
            exit 1
        fi
        entry="$path:$line_no:$canonical"
        key="$entry"
        registered["$key"]=1
    done < "$register"
}

collect_inventory > "$inventory"

while IFS=$'\t' read -r path line kind lint reason; do
    if canonical="$(canonical_safety_lint "$lint")"; then
        key="$path:$line:$canonical"
        current_safety["$key"]=1
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$path" "$line" "$kind" "$lint" "$canonical" "$reason" >> "$safety_inventory"
    fi
done < "$inventory"

if [[ "$mode" == "summary" ]]; then
    print_summary
    exit 0
fi

parse_register

violations=0
while IFS=$'\t' read -r path line kind lint canonical reason; do
    key="$path:$line:$canonical"
    if [[ -z "${registered[$key]+x}" ]]; then
        printf 'suppressions: unregistered safety suppression: %s:%s %s %s (canonical %s) # %s\n' \
            "$path" "$line" "$kind" "$lint" "$canonical" "$reason" >&2
        printf 'suppressions: register as: %s:%s:%s # reason\n' \
            "$path" "$line" "$canonical" >&2
        violations=$((violations + 1))
    fi
done < "$safety_inventory"

for key in "${!registered[@]}"; do
    if [[ -z "${current_safety[$key]+x}" ]]; then
        printf 'suppressions: stale register entry: %s\n' "$key" >&2
        violations=$((violations + 1))
    fi
done

if (( violations > 0 )); then
    printf 'suppressions: %d register violation(s). See %s\n' "$violations" "$register" >&2
    exit 1
fi

printf 'suppressions: OK (%s allow/expect lint entry(s), %s safety-gated)\n' \
    "$(wc -l < "$inventory" | tr -d '[:space:]')" \
    "$(wc -l < "$safety_inventory" | tr -d '[:space:]')"
