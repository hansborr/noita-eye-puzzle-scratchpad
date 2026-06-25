# 07B — Role-directory layout for `lib.rs`

> One-line: regroup the 32 flat `pub mod`s in `lib.rs` into the role directories
> from the overview (`core/ data/ analysis/ nulls/ ciphers/ attack/ experiments/
> report/`) via `#[path]`, with the public crate paths staying byte-identical — a
> pure, behavior-preserving move-refactor that changes no fn body and no reported
> number, plus the *one real edit* it forces: re-rooting the `include_str!` asset
> paths that gain a directory level.
> Status: not started · Depends on: 01 (golden-master safety net) and 07A done;
> 02/03/04/05/06/08 settled · Blocks: — · Size: M
> Sequence: DEAD LAST — after 07A and after 02/03/04/05/06/08 settle. It is
> high-conflict and mostly cosmetic; do it only once the engine + maintainability
> tracks have landed.

## Goal & why it matters

`src/lib.rs:72-103` is a flat wall of 32 `pub mod` declarations (the doc comment
`:1-70` describes each). No role grouping; every module is a direct child of the
crate root. The overview's target groups them under `core/ data/ analysis/
nulls/ ciphers/ attack/ experiments/ report/` (`00-OVERVIEW.md:143-160`), so the
file tree reflects the architecture instead of a single undifferentiated wall.

This brief does the **mechanical** repo-wide regroup: move each module file into
its role directory and repoint `lib.rs` so the **public paths stay flat**
(`crate::analysis::…` keeps working) while the *files* live in role dirs. With
**zero behavior change** — no statistic, no decode, no CLI byte may move.

It is sequenced **dead last** on purpose. Moving every module file is the
highest-conflict diff in the refactor set and is mostly cosmetic, so it must wait
until the engine track (02/03/04) and the maintainability track (05/06/08) — and
the `gak_attack/` split (07A) — have all settled. Otherwise every other brief
fights this one on the same file paths.

The one place this brief is **not** a pure move: a module relocated from
`src/<mod>.rs` to `src/<role>/<mod>.rs` gains a directory level, so its
`include_str!("../research/…")` asset paths must be re-rooted to
`../../research/…`. That is a real source edit (see "include_str! re-rooting").

## Current state (grounded, with file:line)

### `lib.rs` flat layout

`src/lib.rs:72-103` is a flat wall of 32 `pub mod` declarations; the doc comment
`:1-70` describes each. No role grouping; every module is a direct child of the
crate root. The overview's target groups them under `core/ data/ analysis/
nulls/ ciphers/ attack/ experiments/ report/` (`00-OVERVIEW.md:143-160`).

### Thin-move modules owned by other briefs

`ciphers.rs` and `report.rs` are named in the overview as further split
candidates, but those splits are **out of scope for 07B**. The one-file-per-family
split of `ciphers.rs` is a **deferred follow-up** (a future brief-02 extension; not
owned by any current brief), and dissolving `report.rs` into per-error `Display` +
`Report::render` is **brief 06**. 07B does **not** split either file's contents — it
only *relocates* `ciphers.rs` → `ciphers/mod.rs` and `report.rs` → `report/mod.rs`
as **thin moves only**: each new `mod.rs` holds today's file content **verbatim,
unchanged**, so the deferred cipher-family split and brief 06's report dissolve can
land their real splits inside the new directories later. `gak_attack/` is already
a directory after brief 07A; this brief only relocates that directory under
`attack/`. See "Out of scope".

### `include_str!` asset sites (the real-edit surface)

Three modules embed research assets with relative paths that are anchored at the
*module file's* directory. Moving the module file down one directory level changes
what `../` means, so each path must gain one more `../` (verified by grep):

- `src/corpus.rs:318` and `:319` — `include_str!("../research/data/eye-messages/…")`
  (moves into `data/`).
- `src/generator.rs:309` — `include_str!("../research/data/eye-messages/xk_eye.php")`
  (moves into `data/`).
- `src/language.rs:35` and `:38` —
  `include_str!("../research/data/lang/{english,finnish}.txt")` (moves into
  `attack/`, per the overview's placement of `language`).

`gak_attack.rs` has **no `include_str!`** (verified), so nothing in the 07A split
needs an asset-path fix; only these three modules do. Tests are not moved by this
brief (they live under `tests/` and import the binary, not internal paths), so no
test asset paths change.

## Target design (concrete API / types / layout)

### `lib.rs` role grouping

Group the 32 flat modules (`src/lib.rs:72-103`) into the overview's directories
(`00-OVERVIEW.md:143-160`). Use Rust's `path` attribute so the **public paths stay
flat** (`crate::analysis::…` keeps working) while the *files* move into role dirs:

```rust
// src/lib.rs — path stays `crate::analysis`, file lives in analysis/
#[path = "analysis/analysis.rs"] pub mod analysis;
#[path = "nulls/null.rs"]        pub mod null;
// …one line per module, grouped/commented by role
```

A naive nested-`mod` + `pub use` shim does **not** preserve `crate::analysis` —
`pub use analysis_group::*;` re-exports the *items* but changes the module path.
The `#[path]` mechanism is what keeps the flat path byte-identical: **files move
into role directories; public paths are unchanged.**

Grouping per `00-OVERVIEW.md:143-160`:

- `core/` ← `glyph`, `trigram` (sequence/ingest is brief 03's territory — leave
  `glyph` here)
- `data/` ← `corpus`, `generator`
- `analysis/` ← `analysis`, `isomorph`, `periodicity`, `conditional_structure`,
  `modular_diff`, `grouping`, `orientation_homogeneity`, `transitivity`,
  `chaining`, `chaining_graph`, `perfect_isomorphism`, `honeycomb`, `orders`
- `nulls/` ← `null`, `isomorph_null`, `zero_adjacency_null`, `dof_null`,
  `pipeline_null`, `tree_residual`, `perseus`
- `ciphers/` ← `ciphers` (as `ciphers/mod.rs`, content **unchanged/verbatim** — the
  one-file-per-family split is a deferred brief-02 follow-up, out of scope here)
- `attack/` ← `cipher_attack`, `agl_gak`, `gak_attack/` (the dir from 07A),
  and `language` (the n-gram model is consumed only by `cipher_attack`/
  `gak_attack`/`grouping` for the speculative cleartext gate; the overview is
  silent on it, so place it with its attack consumers and add a `// role:` note);
  `solve/` is brief 04's
- `experiments/` ← `pyry_conditions`, `controls`, and the structural-battery
  modules that are clearly experiment drivers (assign conservatively; if a
  module is ambiguous, leave it where the overview is silent and note it)
- `report/` ← `report` (as `report/mod.rs`, content unchanged — brief 06 owns the
  dissolve)

**Deviation latitude:** the overview's grouping is a proposal
(`00-OVERVIEW.md:9-14`). Where a module's role is ambiguous (e.g. `chaining_graph`
is used by both analysis and the gak attack), pick the directory the overview
names and add a one-line `// role: …` comment; do not invent new top-level dirs.

### `include_str!` re-rooting (the one real edit, not a move)

Moving a module from `src/<mod>.rs` to `src/<role>/<mod>.rs` adds a directory
level, so any `include_str!("../research/…")` resolves from one directory deeper
and must be re-rooted with an extra `../`. This is a **real edit, not a pure
move** — the only `+`/`-` inside a fn body / item this whole brief introduces, and
it must be called out explicitly in the diff and the success criteria. Verified
affected sites:

- `src/corpus.rs:318` and `:319` — each `include_str!("../research/data/…")`
  becomes `include_str!("../../research/data/…")` (module moves into `data/`).
- `src/generator.rs:309` — `include_str!("../research/data/eye-messages/xk_eye.php")`
  becomes `include_str!("../../research/data/eye-messages/xk_eye.php")` (into
  `data/`).
- `src/language.rs:35` and `:38` —
  `include_str!("../research/data/lang/{english,finnish}.txt")` each becomes
  `include_str!("../../research/data/lang/{english,finnish}.txt")` (into
  `attack/`).

`gak_attack.rs` has none, so the 07A directory needs no asset fix. Tests stay put
(under `tests/`), so only these three modules' five lines change.

## Implementation steps (ordered, each independently committable & green)

Each step ends green under `make verify` and changes **no fn body** (the only
exception is the `include_str!` string-literal re-rooting, step 3). Run the
golden-master suite from brief 01 after every step and confirm byte-identical CLI
output.

1. **Confirm the prerequisites.** Brief 01's golden master is green, brief 07A has
   landed (`src/gak_attack/` is a directory), and briefs 02/03/04/05/06/08 have
   settled on this branch. Do not start until the high-churn engine and
   maintainability tracks are merged — this brief moves every module file and will
   conflict with anything still in flight.

2. **Move each module file into its role directory and repoint `lib.rs`.** For
   every module, `git mv src/<mod>.rs src/<role>/<mod>.rs` and change the
   declaration to `#[path = "<role>/<mod>.rs"] pub mod <mod>;`, grouped and
   commented by role. Confirm every `crate::<mod>::…` path is unchanged. Do this
   one commit per role directory for smaller, reviewable diffs.

3. **Re-root the `include_str!` asset paths** (the one real edit). In the commit
   that moves `corpus.rs` and `generator.rs` into `data/`, change their
   `include_str!("../research/…")` to `include_str!("../../research/…")`
   (`corpus.rs:318`,`:319`; `generator.rs:309`). In the commit that moves
   `language.rs` into `attack/`, do the same for `language.rs:35`,`:38`. Without
   this the crate will not compile (the asset paths no longer resolve). Green.

4. **Thin-move `ciphers.rs` → `ciphers/mod.rs`, `report.rs` → `report/mod.rs`,
   and `gak_attack/` under `attack/`.** These are relocations only — each `mod.rs`
   holds today's file content **verbatim, unchanged**. The one-file-per-family split
   of `ciphers.rs` is a deferred brief-02 follow-up (out of scope here) and brief 06
   owns the `report/` dissolve; neither happens in 07B. `gak_attack/` is already a
   directory from 07A; move it to `src/attack/gak_attack/`. Confirm
   `crate::ciphers::…`, `crate::report::…`, `crate::gak_attack::…` all still resolve
   via `#[path]`. Green.

5. **Settle `lib.rs`.** The doc comment (`:1-70`) stays, optionally re-grouped to
   mirror the dirs. Confirm the full set of `crate::<mod>::…` public paths is
   byte-identical to before. Run the golden master. Green.

Each step is independently committable (each leaves a compiling, green crate with
the public surface intact). Step 2 can be one commit per role directory.

## Files to create / change / delete

**Create:**
- Role directories: `src/core/`, `src/data/`, `src/analysis/`, `src/nulls/`,
  `src/ciphers/`, `src/attack/`, `src/experiments/`, `src/report/` (as the new
  homes for moved files).

**Change:**
- `src/lib.rs` — regroup the 32 `pub mod` decls into role-commented blocks using
  `#[path]` (paths stay flat); the doc comment (`:1-70`) stays, optionally
  re-grouped to mirror the dirs.
- `src/corpus.rs:318`,`:319` and `src/generator.rs:309` — re-root `include_str!`
  to `../../research/…` (the modules move into `data/`).
- `src/language.rs:35`,`:38` — re-root `include_str!` to `../../research/…` (the
  module moves into `attack/`).

**Move (no content change):**
- Every module file → `<role>/<name>.rs` (`git mv`).
- `ciphers.rs` → `ciphers/mod.rs`, `report.rs` → `report/mod.rs`, `gak_attack/`
  (already a dir from 07A) → `src/attack/gak_attack/` — thin relocations only, each
  `mod.rs` verbatim. The `ciphers.rs` one-file-per-family split is a deferred
  brief-02 follow-up; the `report.rs` dissolve is brief 06 — neither lands here.

**Do not touch:** `tests/*.rs` (all CLI tests must compile and pass unchanged —
they import the binary, not internal paths), `corpus.rs` data, any fn body other
than the five `include_str!` string literals above, and the `gak_attack/` file
*split* (that is brief 07A; here it only relocates wholesale).

## Success criteria

- `lib.rs`'s modules live in the eight role directories from
  `00-OVERVIEW.md:143-160`; the public crate path of every module is unchanged.
- The five `include_str!` asset paths are re-rooted to `../../research/…` and the
  crate compiles; the embedded corpus/lang assets resolve byte-for-byte as before.
- `git diff` contains **only** moves, `mod`/`use`/`#[path]` lines,
  visibility-keyword changes (`pub(crate)`/`pub(super)`), and **the re-rooted
  `include_str!` paths**. No other fn body diff.
- `crate::<mod>::…` for every regrouped module resolves identically before and
  after; `main.rs`, `report.rs`, and every test compile and pass with no path edits.
- `make verify` and `make check` green.

## Verification (exactly how to prove it)

1. **Golden master (the load-bearing proof).** Run brief 01's golden-master suite
   before and after; outputs must be byte-identical. The embedded-asset modules
   (`corpus`, `generator`, `language`) are the ones most at risk from the
   `include_str!` re-rooting — a wrong path is a *compile* failure (loud, good),
   but a swapped asset would be silent, so confirm the corpus round-trip and
   language-calibration tests still pass.
2. **Behavior diff = body diff = the five include_str! lines.** `git diff --stat`
   should show large file moves; `git log -p` per step should reveal no `+`/`-`
   inside any fn body **except** the five `include_str!` string literals. A
   reviewer greps the diff for `fn ` bodies and confirms moves only, plus the
   five expected `../research` → `../../research` changes.
3. **Public-path freeze.** For each regrouped module, `grep -roE
   '<mod>::[A-Za-z_]+' src/ tests/ | sort -u` before vs after must match exactly.
4. **Asset re-rooting.** `grep -rn 'include_str!' src/` after the move shows
   exactly the five expected `../../research/…` paths (corpus ×2, generator ×1,
   language ×2) and no stale `../research/…`.
5. `make verify` then `make check` (fmt + clippy `-D` + tests + rustdoc `-D` +
   cargo-deny + machete + codespell + shellcheck + release build).

## Risks & honesty caveats

- **`#[path]` vs nested `mod` for lib.rs.** `#[path]` keeps flat public paths with
  minimal churn but is slightly unusual; an alternative is plain nested modules +
  `pub use` shims. `#[path]` is preferred for path-fidelity — document the choice.
  Do not change a public path silently; that would break `main.rs`/`report.rs`/
  tests and is a behavior change in disguise.
- **`include_str!` re-rooting is the one real edit — get the depth right.** A
  module moving one directory deeper needs exactly one more `../`. Re-rooting too
  few or too many levels is a compile error (loud), but double-check that no
  module moves *two* levels (none do here — all go from `src/` to `src/<role>/`).
  Verify the five sites individually; do not blanket-replace `../research`.
- **High-conflict, sequence it dead last.** This brief moves every module file and
  will collide with any brief still touching those files. Run it only after 07A
  and 02/03/04/05/06/08 have merged. If anything is still in flight, wait.
- **Re-export / visibility is not widened.** This brief moves files; it must not
  promote any item's visibility. Confirm `cargo public-api`/the grep shows no
  *new* `pub` items — the `#[path]` mechanism preserves both the path and the
  visibility of every module.
- **No claim-surface change.** This refactor touches file layout only; every
  module's honesty caveats and banners move verbatim. The claim ceiling is
  unchanged: *the eyes are deterministic, engine-generated, strikingly structured
  data of unknown meaning; unsolved* (`00-OVERVIEW.md:205-210`).

## Out of scope / non-goals

- **No traits, no logic merges, no fn body edits** (beyond the five `include_str!`
  string-literal re-rootings). `trait Cipher`/`AnyCipher` is brief 02; the solve
  pipeline is brief 04. This brief only moves files between directories.
- **Splitting `gak_attack.rs`** into per-seam files is brief 07A; here the
  `gak_attack/` directory is relocated wholesale under `attack/`, not re-split.
- **Splitting `ciphers.rs` internals** (one file per cipher family) is a **deferred
  brief-02 follow-up, not owned by any current brief** — here `ciphers.rs` only
  becomes `ciphers/mod.rs`, content verbatim/unchanged.
- **Dissolving `report.rs`** into per-error `Display`/`Report::render` is brief 06
  — here `report.rs` only becomes `report/mod.rs`, content verbatim/unchanged.
- **CLI registry / args dedup** is brief 08; the null/experiment harness is brief
  05; external ingest (`core/sequence`) is brief 03 — none are touched here.
