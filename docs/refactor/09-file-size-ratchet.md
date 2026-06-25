# 09 — Rust file-size ratchet (god-file guardrail)

> One-line: add an enforced per-file line budget — a hard default cap plus a shrinking allowlist of the 25 current oversized modules — so no new god-file is born and briefs 06/07a/07b's cuts can't silently regrow.
> Status: not started · Depends on: — (independent; lands early) · Coordinates with: 06, 07a, 07b, 08 (it ratchets their wins) · Blocks: — · Size: S

## Goal & why it matters

The overview's smell table leads with god-files — `gak_attack.rs` 8,147 lines and
`report.rs` 5,694 lines, "31% of crate in 2 files" (`docs/refactor/00-OVERVIEW.md:92`).
Briefs **06** (dissolve `report.rs`), **07a** (split `gak_attack.rs`) and **07b**
(role-directory layout) are the *cure*. This brief is the *prevention*: nothing in
the repo today caps file size, so (a) a new experiment can land as another
1,500-line module tomorrow, and (b) after 06/07a shrink the two headline files,
nothing stops them — or any sibling — from creeping back up.

**The existing complexity guardrails are per-*function*, not per-*file*.**
`clippy.toml` sets `cognitive-complexity-threshold = 20` and
`too-many-arguments-threshold = 7` — these bound the shape of an individual
function and say nothing about how many functions a file may hold. (Clippy's
`too_many_lines` is also a *per-function* lint, default ~100 lines, and is not
enabled here anyway.) There is **no built-in Rust/clippy lint for max-lines-per-file**;
a file-level budget has to be a small script wired into the gate, which is exactly
how the comparison repo (`/workspace`) does file/blob-size policy
(`scripts/check-blob-size.sh` + a reasoned allowlist). This brief ports that
*pattern* (cap + reasoned, shrinking allowlist) to this repo's Rust source.

This is a **guardrail, not a refactor**: it changes no library/CLI behavior and
touches no `src/` file. It is deliberately tiny and should land **early** (it does
not need brief 01's golden master, since it reads only line counts), so that every
subsequent split is enforced by a one-way ratchet instead of being aspirational.

## Current state (grounded, with file:line)

**No file-size mechanism exists.** Verified across the whole gate:

- `Makefile:10` — `verify: fmt-check lint test doc-check deny` (no size step).
- `Makefile:7` — `check: verify machete spell shellcheck build` (no size step).
- `.githooks/pre-commit:18-29` — the Rust gate runs `cargo fmt --check`, `clippy
  -D warnings`, `cargo test`, `cargo doc`, `cargo deny`. No size check.
- `.github/workflows/ci.yml:14-42` — the `rust` job mirrors the above plus the
  release build; jobs `supply-chain`/`spelling`/`shell` cover deny/machete,
  codespell, shellcheck. No size check.
- `clippy.toml` — `cognitive-complexity-threshold = 20`,
  `too-many-arguments-threshold = 7`, `max-struct-bools = 3`. All per-function.

**Current oversized inventory** (tracked `*.rs`, `git ls-files -- '*.rs' | xargs
wc -l | sort -rn`, as of the `engine-spine` merge `8866814`, 2026-06-25). 25 files
exceed a 600-line budget; the top of the list:

| File | Lines | Cured/owned by |
| ---- | ----: | -------------- |
| `src/gak_attack.rs` | 8147 | 07a |
| `src/report.rs` | 5694 | 06 |
| `src/ciphers.rs` | 2910 | 02 / 07b |
| `src/perfect_isomorphism.rs` | 1749 | 05 / 07b |
| `src/conditional_structure.rs` | 1664 | 05 / 07b |
| `src/chaining_graph.rs` | 1590 | 05 / 07b |
| `src/dof_null.rs` | 1473 | 05 |
| `src/pyry_conditions.rs` | 1465 | 05 / 07b |
| `src/modular_diff.rs` | 1353 | 05 / 07b |
| `src/cipher_attack.rs` | 1342 | 04 / 07b |
| `src/orders.rs` | 1340 | 04a / 07b |
| `src/controls.rs` | 1304 | 05 / 07b |
| `src/main.rs` | 1137 | 08 |
| `src/grouping.rs` | 1129 | 07b |
| `src/honeycomb.rs` | 1085 | 07b |
| `src/perseus.rs` | 1077 | 05 |
| `src/chaining.rs` | 1036 | 07b |
| `src/agl_gak.rs` | 1011 | 07b |
| `src/tree_residual.rs` | 992 | 05 |
| `src/periodicity.rs` | 924 | 05 / 07b |
| `src/null.rs` | 832 | 05 |
| `src/orientation_homogeneity.rs` | 822 | 05 / 07b |
| `src/zero_adjacency_null.rs` | 671 | 05 |
| `src/language.rs` | 618 | 04 |
| `src/ingest.rs` | 610 | trim under 600 |

The healthy cluster sits just under the proposed budget (`src/corpus.rs` 512,
`src/pipeline_null.rs` 529, `src/transitivity.rs` 465, `src/generator.rs` 456), so
**600 cleanly separates "god-ish" from "fine"** while leaving normal modules
unpinned. No `tests/*.rs` file exceeds 600 (largest: `tests/golden_master.rs` 441).

**`scripts/` does not exist yet**, but CI already globs it: `ci.yml:76`
(`shellcheck -x .githooks/* scripts/**/*.sh`) and `Makefile:46`
(`shellcheck -x .githooks/* $(wildcard scripts/*.sh)`). A new `scripts/*.sh` is
therefore shellchecked automatically, with no wiring change.

## Target design (concrete API / types / layout)

Two committed artifacts plus three one-line wiring edits. **No new dependency**
(pure `bash` + `git` + `wc`, matching the brief-01 decision to keep the supply
chain minimal — `00-OVERVIEW.md:64` rationale).

### Semantics (the ratchet)

For each tracked `*.rs` file, `lines = wc -l`:

- **Default budget** `MAX_RS_LINES` (default **600**) applies to every file.
- A file may exceed the default **only** if it has a pin in
  `scripts/file-size-allowlist.txt`, seeded at its **exact current** count.
- Pins are **one-way**:
  - `lines > pin` → **fail** ("over cap"): pinned files may not grow.
  - `lines < pin - SLACK` (`FILE_SIZE_SLACK`, default 50) → **fail** ("lower the
    pin"): when you shrink a file you must tighten its pin in the same commit, so
    the budget tracks the file down instead of leaving slack to refill.
  - `lines <= MAX_RS_LINES` → **fail** ("delete the pin"): once a file drops under
    the default it is no longer special and its allowlist line must be removed.
- Every allowlist entry **must carry a `# reason`** (mirrors `/workspace`'s
  `.blob-size-allowlist.txt` discipline: each exception is documented, shrinking
  debt — never a silent permanent carve-out).
- A pin whose file no longer exists → **fail** ("stale entry").

Net effect: new files are hard-capped at 600; the 25 existing god-files are frozen
at today's size and can move in exactly one direction — down — until they cross 600
and their pin is deleted.

### `scripts/check-file-size.sh`

```bash
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
```

### `scripts/file-size-allowlist.txt` (seed)

```text
# Rust files over the 600-line default budget, pinned at their current size so
# they can only SHRINK. Lower the number as you remove lines; delete the line
# once the file drops to <= 600 (the ratchet enforces this). Every entry needs a
# "# reason". See docs/refactor/09-file-size-ratchet.md.
#
# <path>                            <max-lines>  # reason / retiring brief
src/gak_attack.rs                   8147  # god-file; split by brief 07a
src/report.rs                       5694  # god-file; dissolved by brief 06
src/ciphers.rs                      2910  # cipher zoo; trait + move briefs 02, 07b
src/perfect_isomorphism.rs          1749  # structural experiment; briefs 05, 07b
src/conditional_structure.rs        1664  # structural experiment; briefs 05, 07b
src/chaining_graph.rs               1590  # structural experiment; briefs 05, 07b
src/dof_null.rs                     1473  # matched-null driver; brief 05
src/pyry_conditions.rs              1465  # structural experiment; briefs 05, 07b
src/modular_diff.rs                 1353  # structural experiment; briefs 05, 07b
src/cipher_attack.rs                1342  # attack scorer; briefs 04, 07b
src/orders.rs                       1340  # reading layer; briefs 04a, 07b
src/controls.rs                     1304  # positive controls; briefs 05, 07b
src/main.rs                         1137  # CLI dispatch; brief 08
src/grouping.rs                     1129  # structural analysis; brief 07b
src/honeycomb.rs                    1085  # structural analysis; brief 07b
src/perseus.rs                      1077  # matched-null driver; brief 05
src/chaining.rs                     1036  # structural analysis; brief 07b
src/agl_gak.rs                      1011  # attack; brief 07b
src/tree_residual.rs                992   # matched-null driver; brief 05
src/periodicity.rs                  924   # structural experiment; briefs 05, 07b
src/null.rs                         832   # matched-null core; brief 05
src/orientation_homogeneity.rs      822   # structural experiment; briefs 05, 07b
src/zero_adjacency_null.rs          671   # matched-null driver; brief 05
src/language.rs                     618   # language scorer; brief 04
src/ingest.rs                       610   # new (brief 03); trim under 600 next
```

### Wiring (three edits)

**`Makefile`** — add a fast step to `verify` (runs near-instant, fails fast before
the slow `test`/`doc-check` steps) and declare the target:

```make
.PHONY: check verify fmt fmt-check lint filesize test doc-check deny machete spell shellcheck build setup run clean

## verify: the correctness gate the pre-commit hook runs
verify: fmt-check lint filesize test doc-check deny

## filesize: enforce the per-file Rust line budget (ratchet)
filesize:
	./scripts/check-file-size.sh
```

**`.githooks/pre-commit`** — add one line inside the existing Rust-staged block
(`.githooks/pre-commit:19-29`), after `rustfmt`/`clippy`:

```bash
    run "file-size" ./scripts/check-file-size.sh
```

**`.github/workflows/ci.yml`** — a dedicated job (no Rust toolchain needed; pure
checkout + bash), parallel to the others:

```yaml
  file-size:
    name: file-size ratchet
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Rust file-size ratchet
        run: ./scripts/check-file-size.sh
```

(The script is also picked up by the existing `shell` job and `make shellcheck`
because it lives under `scripts/`; no extra shellcheck wiring needed.)

### Doc edits (index the brief)

- `docs/refactor/00-OVERVIEW.md` — add brief 09 to the briefs table (`:346-357`)
  as a meta/guardrail row, add it to the "God-files" smell row (`:92`) as the
  *prevention*, and add a ground rule under "Shared ground rules": *"No new
  god-files: `scripts/check-file-size.sh` caps every `*.rs` at 600 lines; the 25
  existing oversized files are pinned in `scripts/file-size-allowlist.txt` and may
  only shrink."*
- `AGENTS.md` — add a Guardrail-map row: `File size / god-files | scripts/check-file-size.sh + scripts/file-size-allowlist.txt (ratchet)`.

## Implementation steps (ordered, each independently committable & green)

1. **Script + allowlist, no wiring.** Create `scripts/check-file-size.sh` (chmod
   +x) and `scripts/file-size-allowlist.txt` seeded exactly as above. Run
   `./scripts/check-file-size.sh` by hand — it must print `file-size: OK`. Run
   `shellcheck -x scripts/check-file-size.sh` — clean. Run `codespell` on the two
   new files. Commit. (Gate unchanged, so `make verify` still green.)
2. **Wire into `make verify`.** Add the `filesize` target + `.PHONY` entry and the
   `verify` dependency. `make verify` green. Commit.
3. **Wire into the pre-commit hook.** Add the `run "file-size" …` line in the
   Rust-staged block; `shellcheck -x .githooks/pre-commit` clean. Stage a trivial
   `.rs` no-op and confirm the hook runs the check. Commit.
4. **Wire into CI.** Add the `file-size` job. Commit.
5. **Index the brief.** Apply the `00-OVERVIEW.md` + `AGENTS.md` doc edits.
   `make check` green (codespell included). Commit.

Each step is independently green; the guardrail is only *armed* from step 2 on, and
since the seed makes the tree already-compliant, no step turns the gate red.

## Files to create / change / delete

**Create:**
- `scripts/check-file-size.sh` (executable; shellcheck-clean).
- `scripts/file-size-allowlist.txt` (25 seeded pins + header).

**Change:**
- `Makefile` — `filesize` target, `.PHONY`, `verify` dependency.
- `.githooks/pre-commit` — one `run` line in the Rust block.
- `.github/workflows/ci.yml` — one `file-size` job.
- `docs/refactor/00-OVERVIEW.md` — index brief 09 (table + smell row + ground rule).
- `AGENTS.md` — Guardrail-map row.

**Delete:** none. No `src/` change.

## Success criteria

- `./scripts/check-file-size.sh` exits 0 on the seeded tree and is run by
  `make verify`, the pre-commit hook (when `*.rs` staged), and a CI job.
- Adding a 601-line unpinned `*.rs` (or growing any pinned file by one line) makes
  the script exit non-zero with a clear message — demonstrated once, then reverted.
- Every allowlist entry has a `# reason`; a missing reason or a stale (missing-file)
  pin fails the script.
- `make verify` and `make check` green; `shellcheck` and `codespell` clean on the
  new files. No `Cargo.toml`/`deny.toml` change (no new crate).

## Verification (exactly how to prove it)

1. `make verify` — now includes `filesize`; green.
2. **Cap proof (do once, revert):** `printf 'fn _x(){}\n%.0s' {1..601} > src/_probe.rs`
   (a >600-line unpinned file), run `./scripts/check-file-size.sh`, confirm it fails
   naming `src/_probe.rs`; delete the probe.
3. **No-growth proof (do once, revert):** append one blank line to `src/ingest.rs`
   (pinned 610), run the script, confirm it fails "pins may not grow"; revert.
4. **Ratchet-cleanup proof (do once, revert):** lower `src/ingest.rs`'s pin in the
   allowlist to `600`, run the script, confirm it fails "delete its line"; revert.
5. `make check` — full local CI (shellcheck + codespell over the new script).
6. **Campaign integration:** after brief 06/07a shrink `report.rs`/`gak_attack.rs`,
   the implementing PR must lower (or delete) those pins in the same commit — the
   ratchet (`lines < pin - slack`) forces it, so the win is locked in.

## Risks & honesty caveats

- **Intermediate-growth friction.** Brief 08 (CLI registry) may temporarily grow
  `main.rs` before shrinking it; brief 04 may grow a file mid-series. The dev bumps
  that file's pin **with a reason** in the intermediate commit and lowers it when
  the series lands. This is intentional: a pin bump is visible in `git diff` and
  reviewed, never silent. Document this in the allowlist header.
- **`wc -l` counts physical lines**, blanks and comments included. It is a *budget*,
  not a complexity metric — deliberately crude and unfoolable. rustfmt is already
  enforced (`Makefile:18`), so line counts are formatting-stable; an incidental
  ±1 only matters for an exactly-pinned file, where the fix (bump/lower the pin) is
  trivial and the point.
- **Threshold is a judgment call, not a law.** 600 is chosen to sit just above the
  healthy cluster (corpus 512, pipeline_null 529) and is exposed as `MAX_RS_LINES`.
  Once the campaign lands, tightening to 500 is a one-line change plus pinning the
  two or three files then in the 500–600 band — a good follow-up, out of scope here.
- **Not a structure guardrail.** A line cap stops *size* bloat, not *coupling*
  (e.g. `report.rs` importing 27 modules, `00-OVERVIEW.md:93`). That coupling smell
  is owned by brief 06; an architecture-boundary check (the `/workspace`
  `check-boundaries.sh` analogue) is a possible future brief, not this one.
- **Claim ceiling untouched.** Pure tooling; asserts nothing about glyph meaning.

## Out of scope / non-goals

- Any `src/` change, refactor, or actual file split (that is 06/07a/07b).
- A per-function `too_many_lines` clippy lint (noisy; `/workspace` itself relaxes
  it). Could be a separate, narrowly-scoped follow-up.
- An architecture-boundary / import-graph check.
- Tightening the default below 600 or pinning the 500–600 band.
- Replacing `wc -l` with a token/AST line metric.
