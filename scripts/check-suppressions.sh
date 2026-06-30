#!/usr/bin/env bash
# Rust allow/expect inventory and safety-suppression register.
#
# Clippy already enforces reasons for all allows; this gate covers the part
# clippy cannot audit: safety/correctness lints hidden by an allow/expect.
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
        clippy::let_underscore_must_use | let_underscore_must_use)
            printf 'clippy::let_underscore_must_use'
            ;;
        clippy::map_err_ignore | map_err_ignore)
            printf 'clippy::map_err_ignore'
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
        clippy::float_cmp | float_cmp)
            printf 'clippy::float_cmp'
            ;;
        clippy::lossy_float_literal | lossy_float_literal)
            printf 'clippy::lossy_float_literal'
            ;;
        unused_results | clippy::unused_results | rustc::unused_results)
            printf 'unused_results'
            ;;
        warnings)
            printf 'warnings'
            ;;
        clippy::all)
            printf 'clippy::all'
            ;;
        clippy::correctness)
            printf 'clippy::correctness'
            ;;
        clippy::perf)
            printf 'clippy::perf'
            ;;
        unused)
            printf 'unused'
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
    done < <(git ls-files -z -- '*.rs')

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

sub blank_range {
    my ($chars, $start, $end) = @_;
    for my $pos ($start .. $end - 1) {
        $chars->[$pos] = "\n" if $chars->[$pos] eq "\n";
        $chars->[$pos] = " " if $chars->[$pos] ne "\n";
    }
}

sub raw_string_hashes_at {
    my ($text, $prefix_start) = @_;
    my $pos = $prefix_start;
    $pos++ if substr($text, $pos, 1) eq "b" || substr($text, $pos, 1) eq "c";
    return () if substr($text, $pos, 1) ne "r";
    $pos++;

    my $hashes = "";
    while (substr($text, $pos, 1) eq "#") {
        $hashes .= "#";
        $pos++;
    }
    return () if substr($text, $pos, 1) ne '"';
    return ($hashes, $pos);
}

sub string_prefix_start {
    my ($text, $quote_pos) = @_;
    return $quote_pos - 2 if $quote_pos >= 2 && substr($text, $quote_pos - 2, 2) eq "br";
    return $quote_pos - 2 if $quote_pos >= 2 && substr($text, $quote_pos - 2, 2) eq "cr";
    return $quote_pos - 1
        if $quote_pos >= 1
        && (substr($text, $quote_pos - 1, 1) eq "b"
            || substr($text, $quote_pos - 1, 1) eq "c"
            || substr($text, $quote_pos - 1, 1) eq "r");
    return $quote_pos;
}

sub strip_comments_and_literals {
    my ($text) = @_;
    my @chars = split //, $text;
    my $len = length $text;
    my $i = 0;

    while ($i < $len) {
        my $two = substr($text, $i, 2);

        if ($two eq "//") {
            my $start = $i;
            $i += 2;
            $i++ while $i < $len && substr($text, $i, 1) ne "\n";
            blank_range(\@chars, $start, $i);
            next;
        }

        if ($two eq "/*") {
            my $start = $i;
            my $depth = 1;
            $i += 2;
            while ($i < $len && $depth > 0) {
                my $pair = substr($text, $i, 2);
                if ($pair eq "/*") {
                    $depth++;
                    $i += 2;
                } elsif ($pair eq "*/") {
                    $depth--;
                    $i += 2;
                } else {
                    $i++;
                }
            }
            blank_range(\@chars, $start, $i);
            next;
        }

        if (substr($text, $i, 1) =~ /[bcr]/) {
            my @raw = raw_string_hashes_at($text, $i);
            if (@raw) {
                my ($hashes, $quote_pos) = @raw;
                my $terminator = '"' . $hashes;
                my $end = index($text, $terminator, $quote_pos + 1);
                my $next = $end < 0 ? $len : $end + length($terminator);
                blank_range(\@chars, $i, $next);
                $i = $next;
                next;
            }
        }

        if (substr($text, $i, 1) eq '"') {
            my $start = $i;
            my $quote = '"';
            $start = string_prefix_start($text, $i);

            $i++;
            my $escape = 0;
            while ($i < $len) {
                my $char = substr($text, $i, 1);
                if ($escape) {
                    $escape = 0;
                } elsif ($char eq "\\") {
                    $escape = 1;
                } elsif ($char eq $quote) {
                    $i++;
                    last;
                }
                $i++;
            }
            blank_range(\@chars, $start, $i);
            next;
        }

        $i++;
    }

    return join "", @chars;
}

sub find_matching {
    my ($text, $open_pos, $open, $close) = @_;
    my $depth = 1;
    my $i = $open_pos + 1;
    while ($i < length $text) {
        my $char = substr($text, $i, 1);
        if ($char eq $open) {
            $depth++;
        } elsif ($char eq $close) {
            $depth--;
            return $i if $depth == 0;
        }
        $i++;
    }
    return undef;
}

sub emit_suppression {
    my ($file, $raw_text, $kind, $kind_pos, $inner_start, $inner_end) = @_;
    my $prefix = substr($raw_text, 0, $kind_pos);
    my $line = 1 + ($prefix =~ tr/\n//);
    my $inner = substr($raw_text, $inner_start, $inner_end - $inner_start);

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

sub scan_cfg_attr {
    my ($file, $raw_text, $clean_text, $inner_start, $inner_end) = @_;
    my $inner = substr($clean_text, $inner_start, $inner_end - $inner_start);
    while ($inner =~ /\b(allow|expect)\s*\(/g) {
        my $kind = $1;
        my $kind_pos = $inner_start + $-[1];
        my $open_pos = $inner_start + $+[0] - 1;
        my $close_pos = find_matching($clean_text, $open_pos, "(", ")");
        if (!defined $close_pos || $close_pos > $inner_end) {
            my $prefix = substr($raw_text, 0, $kind_pos);
            my $line = 1 + ($prefix =~ tr/\n//);
            die "suppressions: $file:$line: malformed cfg_attr allow/expect\n";
        }
        emit_suppression($file, $raw_text, $kind, $kind_pos, $open_pos + 1, $close_pos);
        pos($inner) = $close_pos - $inner_start + 1;
    }
}

for my $file (@ARGV) {
    open my $fh, '<', $file or die "suppressions: cannot read $file: $!\n";
    local $/;
    my $text = <$fh>;
    close $fh or die "suppressions: cannot close $file: $!\n";

    my $clean = strip_comments_and_literals($text);
    pos($clean) = 0;
    while ($clean =~ /#\s*!?\s*\[/g) {
        my $attr_start = $-[0];
        my $open_bracket = $+[0] - 1;
        my $close_bracket = find_matching($clean, $open_bracket, "[", "]");
        if (!defined $close_bracket) {
            my $prefix = substr($text, 0, $attr_start);
            my $line = 1 + ($prefix =~ tr/\n//);
            die "suppressions: $file:$line: malformed attribute\n";
        }
        my $content_start = $open_bracket + 1;
        my $content = substr($clean, $content_start, $close_bracket - $content_start);

        if ($content =~ /^\s*(allow|expect)\s*\(/) {
            my $kind = $1;
            my $kind_pos = $content_start + $-[1];
            my $open_pos = $content_start + $+[0] - 1;
            my $close_pos = find_matching($clean, $open_pos, "(", ")");
            if (!defined $close_pos || $close_pos > $close_bracket) {
                my $prefix = substr($text, 0, $kind_pos);
                my $line = 1 + ($prefix =~ tr/\n//);
                die "suppressions: $file:$line: malformed allow/expect attribute\n";
            }
            emit_suppression($file, $text, $kind, $kind_pos, $open_pos + 1, $close_pos);
        } elsif ($content =~ /^\s*cfg_attr\s*\(/) {
            my $open_pos = $content_start + $+[0] - 1;
            my $close_pos = find_matching($clean, $open_pos, "(", ")");
            if (!defined $close_pos || $close_pos > $close_bracket) {
                my $prefix = substr($text, 0, $content_start + $-[0]);
                my $line = 1 + ($prefix =~ tr/\n//);
                die "suppressions: $file:$line: malformed cfg_attr attribute\n";
            }
            scan_cfg_attr($file, $text, $clean, $open_pos + 1, $close_pos);
        }
        pos($clean) = $close_bracket + 1;
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
