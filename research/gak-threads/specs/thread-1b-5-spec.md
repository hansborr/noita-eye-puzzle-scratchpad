# Implementation spec — Threads 1B + 5 (chaining graph + dihedral verdict)

**Status:** brief for a later implementation wave. Lands code under `-D warnings`
with `make verify` green. Do **not** modify anything under `src/` while reading
this; the spec *describes* the modules to write.

**Scope discipline (non-negotiable, from AGENTS.md + the threads).** Pure
structure: only ciphertext symbol **equality** and group structure. No
symbol→meaning mapping, no language scoring, no reading-order re-selection. Every
structural negative carries a matched null; every positive control fires on known
signal. The strongest defensible claim printed anywhere is: *deterministic,
engine-generated, strikingly structured data of unknown meaning; unsolved; no
primary developer source confirms recoverable plaintext.* The dihedral verdict
constrains the candidate **group set** only — it says nothing about plaintext.

These two threads share the **chain-link primitive** (an observed `symbol →
symbol` pair under a fixed context). Thread 5 (`thread-5-chaining-graph.md`)
builds the full graph (conflict catalogue + coverage); Thread 1B
(`thread-1-dihedral-and-transitivity.md` Part B) is the dihedral-exclusion
verdict that consumes chain links plus the induced-cycle-length argument. They
are specced together to build the primitive once.

---

## 0. Wiki pages under test (cite these exact files in rustdoc + report text)

Content current to 2026-01-16. Preserve every "tentative" label.

- `eye-messages.wiki/Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher.md`
  — the dihedral exclusion (Thread 1B verdict).
- `eye-messages.wiki/Proof-that-GAK-is-transitive.md`
  — the **right**-coset action that justifies "cycle lengths divide element
  order" (NOT the semidirect-product left-action proof; see
  `notes/thread-1b-dihedral-verification.md` Step 1).
- `eye-messages.wiki/Graph-Chaining.md`, `Alphabet-Chaining.md`,
  `Chaining-Conflicts.md`, `Chaining-Conflict-Rates.md` — chaining-graph + conflict
  definitions (Thread 5).
- `eye-messages.wiki/The-Transitivity-Restriction-(6-Groups-for-83).md` — the
  six-group count + transitivity premise (encoded as a test; Thread 1A is the
  proof note).
- `eye-messages.wiki/Dihedral-Group.md`, `Cyclic-Group.md`,
  `Group-Autokey-(GAK).md`, `Hidden-State.md`.

**Honesty caveats to carry verbatim into report text** (from
`notes/thread-1b-dihedral-verification.md`):
- The dihedral exclusion holds **conditional on** the cited 11-wide alignment
  being a single same-plaintext isomorph under one global cipher (assumptions
  A1–A5).
- HOLE 1 (wiki-acknowledged): a single "strategic typo" at col6 or col9 of the
  cited triple dissolves *that triple's* contradiction; the within-triple second
  conflict reuses col6/col9 and does not remove it.
- HOLE 2 (not wiki-flagged): the commutativity-conflict half lives **only** in the
  over-extended col9; on the high-confidence repeated 9-core the order-83 forcing
  fires but **no conflict appears**. Robust refutation needs a
  forcing-plus-conflict witnessed *inside repeated-core columns* of some isomorph
  family — the empirical search this module performs.

---

## 1. Expected-output oracle (pin these as test constants)

From `notes/reading-streams.md` (reproduced byte-for-byte) and
`notes/thread-1b-dihedral-verification.md`:

- Corpus totals (already pinned elsewhere; re-assert in the eye-pin test):
  **1036** trigrams, **83** distinct symbols (contiguous `0..=82`), 0
  adjacent-equal. Order = `accepted_honeycomb_order()` (stable name
  `standard36-u012-d012`).
- The wiki "main isomorph" gap signature is `[0,0,0,0,0,3,0,7,4,0,9]` (window
  length 11). It occurs as **four** instances under the accepted order:
  - `west1 @ 40` → `OLPJ3P-O3QL` (wiki msg1)
  - `west1 @ 70` → `dN1D-15d-)N` (wiki msg3)
  - `east2 @ 45` → `` &-`=Q`_&Q?- `` (wiki msg2)
  - `east2 @ 80` → `IhY47YaI72h` (a fourth instance the wiki did not cite)
- Display convention: `char = value + 32` (display only; the module works on
  `TrigramValue` 0..=82 internally and never builds a symbol→meaning mapping).
- Triple columns (4,6,9) read `3-Q / Q_? / -5)`. Contexts:
  `a = wiki-msg1 → wiki-msg2`, `b = wiki-msg1 → wiki-msg3`.
- Order-83 forcing: a length-3 chain exists under `a` (`L → - → _`, glue via the
  shared symbol `-`) and under `b` (`3 → - → 5`). Forcing survives on core
  columns `{1,6}` (for `a`) and `{4,6}` (for `b`).
- Commutativity conflict (the contradiction's second half): from start `3`,
  `a` then `b` reaches `)` while `b` then `a` reaches `_`
  (`3 →a Q →b )` vs `3 →b - →a _`). This conflict routes through col9 only.

**Acceptance for Thread 1B (the verdict the tests assert):** the module must
locate ≥1 instance of the cited gap signature, reconstruct contexts `a`,`b`,
confirm (i) a length-`>2` chain under each (order-83 forcing) and (ii) the
commutativity conflict, and report `DihedralExcluded` — while explicitly
flagging via the report that the conflict half depends on the col9 over-extension
(HOLE 2) and that a repeated-core-only conflict is the robustness target.

No `thread-1b-5-empirical.md` exists yet; this spec's §1 is the empirical oracle.

---

## 2. Module layout (a)

Two new files; `src/chaining.rs` (Experiment-7B additive, cyclic-only) stays
**UNTOUCHED** (`notes/api-analysis.md` §`chaining.rs`).

### `src/chaining_graph.rs` (Thread 5 — primitive + catalogue + coverage)

Owns the shared chain-link primitive, the conflict catalogue, the
connected-component coverage, and the union-find graph utility (none exists in the
crate — `notes/api-analysis.md:185-191`). Public entry `run_chaining_graph`.

### `src/transitivity.rs` (Thread 1B verdict + 6-group encoding)

Consumes the chain-link primitive from `chaining_graph` (import, do not
duplicate). Owns the dihedral structural verdict (order-83 forcing +
commutativity conflict → `D₁₆₆` excluded) and a test encoding the six group
orders / hidden-subgroup sizes (Part A consequence). Public entry
`run_transitivity`.

Wire both into the gate via the four-file pattern
(`notes/api-infra.md:15-31`): `src/lib.rs` (`pub mod chaining_graph;` /
`pub mod transitivity;`, keep the block at lib.rs:62-88 **alphabetical** —
`chaining_graph` after `chaining`/`cipher_attack`? note alpha order:
`chaining` < `chaining_graph` < `cipher_attack`; `transitivity` after
`tree_residual` before `trigram`); `src/report.rs`; `src/main.rs`. No
`Cargo.toml`/`Makefile`/CI edits.

---

## 3. Public API (b) — documented types + signatures

Every `pub` item (incl. struct fields, enum variants) needs a `///` doc
(`missing_docs`). Signatures below are the contract; `# Errors` rustdoc required
on each fallible `pub fn`.

### 3.1 Shared chain-link primitive (`chaining_graph.rs`)

```rust
/// An opaque identifier for a context (the transformation between two aligned
/// isomorph occurrences). Contexts are never resolved to a group element; only
/// their *action* (a set of chain links) is observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextId(pub u32);

/// A reading-layer ciphertext symbol value (0..=82). Newtype over the verified
/// stream value so chain-link code cannot accidentally mix in a glyph index.
pub type SymbolValue = crate::trigram::TrigramValue;

/// One observed `symbol -> symbol` mapping under a fixed context: at an aligned
/// column the upper occurrence shows `from` and the lower shows `to`, so the
/// context's action sends `from |-> to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainLink {
    /// The context whose action this link witnesses.
    pub context: ContextId,
    /// Source ciphertext symbol.
    pub from: SymbolValue,
    /// Image ciphertext symbol under the context's action.
    pub to: SymbolValue,
    /// Provenance: the (message-pair, column) the link was read from, for the
    /// fragility audit (single-source columns are HOLE-1 style risks).
    pub provenance: LinkProvenance,
}

/// Where a chain link came from, so a verdict can be flagged fragile when it
/// rests on a single column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkProvenance {
    /// Index of the upper occurrence's message in the corpus (0..=8).
    pub upper_message: usize,
    /// Index of the lower occurrence's message in the corpus (0..=8).
    pub lower_message: usize,
    /// Aligned column within the isomorph window.
    pub column: usize,
    /// Whether this column lies inside the twice-repeated isomorph core (true)
    /// or in an over-extension (false). Over-extension links are flagged.
    pub in_repeated_core: bool,
}

/// Build chain links from one aligned isomorph occurrence pair. The two windows
/// must be equal length and from the same isomorph signature; links are emitted
/// only for columns inside the supplied core/extension bound. Returns no links
/// across an allomorphic boundary.
///
/// # Errors
/// `ChainingGraphError::WindowLengthMismatch` if the windows differ in length.
pub fn chain_links_for_pair(
    context: ContextId,
    upper: &AlignedOccurrence<'_>,
    lower: &AlignedOccurrence<'_>,
) -> Result<Vec<ChainLink>, ChainingGraphError>;

/// An aligned isomorph occurrence: a window into one message's value stream,
/// with the bound that separates repeated-core columns from over-extension.
#[derive(Clone, Copy, Debug)]
pub struct AlignedOccurrence<'a> {
    /// Corpus message index this occurrence is read from.
    pub message: usize,
    /// The window's value slice (length == isomorph window length).
    pub window: &'a [SymbolValue],
    /// Number of leading columns that belong to the twice-repeated core; columns
    /// `>= core_len` are over-extension (flagged, not excluded).
    pub core_len: usize,
}
```

### 3.2 Conflict catalogue (`chaining_graph.rs`)

```rust
/// A witnessed non-commutativity: from start symbol `s`, applying context `a`
/// then `b` reaches a different symbol than `b` then `a`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainingConflict {
    /// First context.
    pub a: ContextId,
    /// Second context.
    pub b: ContextId,
    /// Shared start symbol.
    pub start: SymbolValue,
    /// Image of `start` under `a` then `b`.
    pub ab_image: SymbolValue,
    /// Image of `start` under `b` then `a`.
    pub ba_image: SymbolValue,
    /// True if every link in this conflict comes from a repeated-core column
    /// (robust); false if any link is single-source / over-extension (fragile).
    pub robust: bool,
}

/// Tabulated conflict evidence — the quantitative form of the wiki's qualitative
/// "we see chaining conflicts indicating non-commutativity"
/// (`Chaining-Conflicts.md`).
#[derive(Clone, Debug, PartialEq)]
pub struct ConflictCatalogue {
    /// Every distinct `(a, b, start)` conflict found.
    pub conflicts: Vec<ChainingConflict>,
    /// Total conflict count.
    pub total: usize,
    /// Count whose underlying isomorph sets do not share a link (independent).
    pub independent: usize,
    /// Count flagged fragile (depend on a single weak/over-extended column).
    pub fragile: usize,
}
```

### 3.3 Coverage (`chaining_graph.rs`)

```rust
/// Connected-component coverage of the chain-link graph over the 83 symbols —
/// the empirical basis for the *transitivity* premise (`Proof-that-GAK-is-
/// transitive.md`, `The-Transitivity-Restriction-(6-Groups-for-83).md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageReport {
    /// Number of distinct symbols touched by at least one chain link.
    pub symbols_touched: usize,
    /// Size of the largest connected component (symbols).
    pub largest_component: usize,
    /// Number of connected components among touched symbols.
    pub component_count: usize,
    /// Alphabet size used for the denominator (83).
    pub alphabet_size: usize,
}

/// Minimal union-find over `0..alphabet_size` (no such utility exists in-crate;
/// `notes/api-analysis.md:185-191`). Used to compute `CoverageReport`.
#[derive(Clone, Debug)]
pub struct UnionFind { /* parent + rank vecs, private */ }

impl UnionFind {
    /// Create a forest of `n` singletons.
    #[must_use]
    pub fn new(n: usize) -> Self;
    /// Union the sets containing `x` and `y`; out-of-range indices are ignored.
    pub fn union(&mut self, x: usize, y: usize);
    /// Representative of `x`'s set (path-compressed). `None` if out of range.
    pub fn find(&mut self, x: usize) -> Option<usize>;
}
```

### 3.4 Dihedral verdict (`transitivity.rs`)

```rust
/// Structural verdict on whether the eyes can be a dihedral (`D_166`) GAK cipher.
/// This constrains the candidate group set only; it is NOT a decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DihedralVerdict {
    /// Both halves fire: a length-`>2` chain forces order 83 under each context
    /// AND a commutativity conflict is present => `D_166` excluded.
    DihedralExcluded,
    /// Order-83 forcing fires but no conflict found => inconclusive on this data.
    ForcingWithoutConflict,
    /// The cited isomorph alignment was not located in the corpus => surprise,
    /// itself a finding (weakens the exclusion).
    IsomorphNotLocated,
}

/// A single order-83-forcing-plus-conflict witness, with confidence flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExclusionWitness {
    /// Contexts whose >2 chains force order 83.
    pub context_a: ContextId,
    /// Second context.
    pub context_b: ContextId,
    /// The commutativity conflict that completes the contradiction.
    pub conflict: ChainingConflict,
    /// True if BOTH the forcing chains AND the conflict use only repeated-core
    /// columns (the typo-robust, HOLE-2-free case).
    pub core_only: bool,
}
```

### 3.5 Report + config + error (both modules, mirroring `pyry_conditions`)

```rust
// chaining_graph.rs
pub const DEFAULT_SEED: u64 = /* ascii-tagged, e.g. b"chaingrf" packed */;
pub const DEFAULT_TRIALS: usize = /* e.g. 10_000, mirror isomorph_null */;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainingGraphConfig { pub seed: u64, pub trials: usize, /* window, min_core */ }
impl Default for ChainingGraphConfig { /* from DEFAULT_* */ }

#[derive(Clone, Debug, PartialEq)]
pub struct ChainingGraphReport {
    pub config: ChainingGraphConfig,
    pub catalogue: ConflictCatalogue,
    pub coverage: CoverageReport,
    pub null: ConflictCoverageNull,        // shuffle-null bands (see §5)
    pub positive_control: PositiveControlOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainingGraphError {
    Grid(crate::orders::GridError),
    ZeroTrials,
    RandomBoundTooLarge { bound: usize },
    WindowLengthMismatch,
    PositiveControlFailed { /* margin diagnostics */ },
}
// From<GridError>, From<crate::null::RandomBoundError> impls so `?` works.

pub fn run_chaining_graph(
    config: ChainingGraphConfig,
) -> Result<ChainingGraphReport, ChainingGraphError>;

// transitivity.rs
pub const DEFAULT_SEED: u64 = /* ascii-tagged */;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitivityConfig { pub seed: u64, pub trials: usize }
impl Default for TransitivityConfig { /* from DEFAULT_* */ }

#[derive(Clone, Debug, PartialEq)]
pub struct TransitivityReport {
    pub config: TransitivityConfig,
    pub verdict: DihedralVerdict,
    pub witnesses: Vec<ExclusionWitness>,
    pub core_only_witnesses: usize, // HOLE-2 robustness count
    pub catalogue: ConflictCatalogue, // reused from chaining_graph
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitivityError {
    Grid(crate::orders::GridError),
    ChainingGraph(ChainingGraphError),
    ZeroTrials,
    RandomBoundTooLarge { bound: usize },
}

pub fn run_transitivity(
    config: TransitivityConfig,
) -> Result<TransitivityReport, TransitivityError>;
```

---

## 4. Exact reuse points (c) — file:line, verified against the tree

- **Corpus / stream entry** (`notes/api-analysis.md:15-36`, `api-infra.md:58-64`):
  `orders::corpus_grids()` then
  `orders::read_corpus_message_values(&grids, order)` with
  `order = orders::accepted_honeycomb_order()`. Alphabet size
  `orders::READING_LAYER_ALPHABET_SIZE` (= 83, `orders.rs:24`). Message keys via
  `GlyphGrid::message_key` (`orders.rs:121`). Never re-select a reading order.
- **Cross-message isomorph alignment (a)** → `isomorph::PatternSignature::from_window`
  (`src/isomorph.rs:38`; struct at `:31`). Compute the equality signature at each
  candidate offset per message and equate signatures by `==` (`SignatureGroup`
  fields at `isomorph.rs:93-95`). **Do not** rely on `detect_isomorphs`
  (`isomorph.rs:212`) for cross-message alignment — it is within-sequence only
  (`api-analysis.md:112-115`); use it only to find the repeated signature
  *within* a message, then do cross-message bookkeeping yourself.
- **Within-message shuffle null (b)** → `null::fisher_yates`
  (`src/null.rs:111`) applied per message over `message_values.to_vec()`, exactly
  as `isomorph_null` does (`src/isomorph_null.rs:181` `SplitMix64::new(config.seed)`,
  `:8` imports `fisher_yates`). Preserve each message's multiset + length; do not
  concatenate across messages.
- **PRNG** → `null::SplitMix64::new` (`src/null.rs:27`), `null::stateless_splitmix`
  (`:70`), `null::mix_seed` (`:91`), `null::random_index_below` (`:112`),
  `null::shuffled_permutation` (`:148`), `null::RandomBoundError` (`:101`)
  mapped into the module error via `From`. Significance: `null::add_one_p_value`
  (`:80`) and `null::wilson_95` (`:302`).
- **Add-one empirical p** → reuse `null::add_one_p_value(count, trials)`;
  do not reimplement privately. It is the shared `(count+1)/(trials+1)`
  convention used by the Monte-Carlo null modules.
- **Alignment anchors** (`perseus.rs`) — reusable *concepts* for cross-message
  start alignment but currently **private**: `same_offset_common_runs`
  (`perseus.rs:466`), `leading_start` (`perseus.rs:208`/`:408`),
  `is_counterpart_pair` (`perseus.rs:574`), `MIN_SHARED_RUN_LEN` (`perseus.rs:28`,
  public), `SharedSpan` (`perseus.rs:148`). The wiki triple is located by the gap
  *signature* (above), not by same-offset runs, so the spec does **not** require
  promoting perseus internals; reconstruct the isomorph-window alignment from
  `PatternSignature` matches. Cite perseus only as the report/null template.
- **New union-find** → none exists (`api-analysis.md:185-191`: "no union-find, no
  connected-components, no graph traversal, no petgraph"). Add `UnionFind`
  (§3.3) inside `chaining_graph.rs`; keep it private-fielded, public methods.
- **Report/null/positive-control template** → `pyry_conditions.rs` (predicate
  harness: `DEFAULT_SEED` at `:29`, `impl Default` at `:61`, `run_pyry_conditions`
  at `:393`, `validate_config` at `:445`, `evaluate_generated_families` for the
  positive control, `PairInput` arg-bundling at `:553`,
  `let _inserted = …insert(…)` discipline) and `cipher_attack.rs` (within-message
  shuffle null `:340`, `null_model: &'static str` field `:386`,
  `POSITIVE_CONTROL_MIN_MARGIN` `:47`, `PositiveControlFailed` `:90`,
  `impl fmt::Display` `:128`).

---

## 5. Null + positive control (d)

### Matched null (mandatory)

Reuse the within-message multiset shuffle (`isomorph_null`'s shape,
`api-analysis.md:119-132`): per trial, `let mut shuffled = message_values.to_vec();
for v in &mut shuffled { fisher_yates(v, &mut rng)?; }`, then **re-run the entire
chain-link → conflict + coverage pipeline** on the shuffled streams and record:

- conflict counts (total / independent), and
- coverage (`symbols_touched`, `largest_component`, `component_count`).

Report each real statistic against the shuffle distribution as a percentile band
(`ConflictCoverageNull` with `mean/q025/median/q975/max`, mirroring
`IsomorphNullBand`) plus an **add-one** empirical exceedance p. Direction:
conflicts are evidence *for* non-commutativity (upper tail — real ≥ shuffle);
coverage is evidence *for* transitivity (upper tail — real ≥ shuffle). Real
structure must exceed the shuffle null. Frame the dihedral *negative* (D₁₆₆
excluded) as the **expected** structural outcome, reported as exceedance, not as
a bare verdict (`cipher_attack.rs` module-doc discipline, `api-infra.md:76-78`).

### Positive control (mandatory — must fire on known signal)

Generate a **synthetic non-commutative GAK fixture** with known isomorphs
(`thread-5-chaining-graph.md` step 4):

1. Build two **non-commuting** permutations `A`, `B` of `0..83` from
   `null::shuffled_permutation(83, seed)` (`null.rs:127`; pattern at
   `ciphers.rs:1258`). Assert non-commutativity in-test (`A∘B ≠ B∘A` at some
   symbol) — re-draw via `stateless_splitmix`-derived seeds until it holds (it
   will almost always hold for two random `S₈₃` elements; bound the retries).
2. Emit a synthetic "isomorph stack": a base window of distinct symbols, with two
   aligned occurrences whose context action is exactly `A` (one pair) and `B`
   (another pair), planting known chain links that compose to a known conflict and
   touch a known symbol set.
3. Run the *same* `chain_links_for_pair` → catalogue → coverage pipeline. Require:
   at least one conflict recovered, coverage = the planted symbol set, with a
   margin over the shuffle null gated by a `POSITIVE_CONTROL_MIN_MARGIN`-style
   constant. Failure ⇒ `PositiveControlFailed` (methodology suspect, not data —
   `api-infra.md:84-85`).

Keep the fixture mapping-independent: it manufactures *symbols and their equality
structure*, never a symbol→meaning table.

### CLI subcommands + report wiring

Two subcommands, mirroring `run_pyry` / `print_pyry_conditions_report`
(`main.rs:684-697`, `report.rs:2820`):

- `chaining-graph`: `enum Command::ChainingGraph(ChainingGraphArgs)` (main.rs:34
  block), `ChainingGraphArgs { seed, trials }` with
  `#[arg(default_value_t = chaining_graph::DEFAULT_*)]`,
  `impl From<ChainingGraphArgs> for chaining_graph::ChainingGraphConfig` using
  `..Self::default()`, `fn run_chaining_graph(config) -> ExitCode` (clone of
  `run_pyry` at main.rs:684), match arm
  `Command::ChainingGraph(a) => run_chaining_graph(a.into())` (main.rs:447 block).
  In `report.rs`: `pub fn format_chaining_graph_error(&ChainingGraphError) ->
  String` (match every variant, no panic) and
  `pub fn print_chaining_graph_report(&ChainingGraphReport)` (`println!` only,
  private `print_*` sub-helpers).
- `transitivity` (alias `dihedral`): same shape, `format_transitivity_error` +
  `print_transitivity_report`.

Each report ends with an `Interpretation:` paragraph at the defensible-claim
ceiling (`report.rs:580/921/992/1380` are the model) and a `Multiplicity note:`
where several tails are tested (`report.rs:909`). The transitivity report must
print the HOLE-1/HOLE-2 caveats from §0 and state that the verdict constrains the
group set only. Cite the exact wiki page (§0) in the printed text and keep
"tentative" wording.

---

## 6. Lint compliance (e) — `-D warnings`, from `api-infra.md:162-186`

- `missing_docs`: `///` on **every** `pub` item incl. struct fields + enum
  variants (all the types in §3).
- No `unwrap`/`expect`/`panic`/`indexing_slicing`/`string_slice` in lib/CLI:
  index via `.get(i)` + `let Some(x) = … else { return Err(...) }`; slice via
  `.windows()/.chunks()`. Relaxed only inside `#[cfg(test)]` (clippy.toml).
- `unused_results`: bind dropped `#[must_use]`, e.g.
  `let _inserted = set.insert(x);` (`pyry_conditions.rs:681` pattern). `UnionFind`
  call sites that drop `find`/`union` returns must bind them.
- `panic_in_result_fn`: every `-> Result<…>` fn (incl. `run_*`,
  `chain_links_for_pair`) is panic-free.
- `float_cmp`/`lossy_float_literal`: compare band floats with `total_cmp` /
  tolerance, never `==` (`report.rs` uses `.total_cmp`).
- `map_err_ignore`: carry sources via `From` impls so `?` works; no
  `map_err(|_| …)`.
- Any unavoidable allow carries a reason:
  `#[allow(clippy::…, reason = "…")]` — bare `#[allow]` is itself denied
  (`allow_attributes_without_reason`).
- `cognitive-complexity-threshold = 20`, `too-many-arguments-threshold = 7`,
  `max-struct-bools = 3`: the conflict/forcing search is the complexity hotspot —
  factor it into small private fns and bundle args into a struct (the
  `AlignedOccurrence` / a `ConflictSearchInput` bundle, like `PairInput`
  at `pyry_conditions.rs:553`). Note `LinkProvenance` already holds the bool
  fields; keep ≤3 bools per struct.
- `wildcard_imports`: name every import (`use crate::null::{SplitMix64,
  add_one_p_value, fisher_yates, shuffled_permutation, stateless_splitmix};`).
- `unsafe` forbidden crate-wide; `--locked` everywhere (no command re-resolves
  `Cargo.lock`).

### Test checklist (`#[cfg(test)] mod tests`, `api-infra.md:188-201`)

- **Determinism:** `run_chaining_graph(cfg) == run_chaining_graph(cfg)` and
  same for `run_transitivity` at a fixed seed.
- **Eye pin:** assert `1036` total trigrams, `83` distinct, `0` adjacent-equal on
  the accepted order (`pyry_conditions.rs:1430` style).
- **Oracle pin (§1):** assert the gap signature `[0,0,0,0,0,3,0,7,4,0,9]` is
  located at the four documented instances; assert columns (4,6,9) render
  `3-Q / Q_? / -5)` (compute display via `value + 32` in-test only).
- **Verdict pin:** `run_transitivity` returns `DihedralExcluded`; ≥1
  `ExclusionWitness`; assert at least one witness reproduces the
  `3 →a Q →b )` vs `3 →b - →a _` conflict; assert `core_only_witnesses` count is
  reported (expected to be 0 for the cited triple per HOLE 2 — pin it so a future
  data change surfaces).
- **Positive control fires:** synthetic non-commutative GAK fixture yields ≥1
  conflict + planted coverage with margin over null
  (`cipher_attack.rs:1334` style).
- **Null sanity:** a uniform-random / commutative fixture stays inside the
  shuffle band (negative control, `isomorph_null` `uniform_random_*` pattern).
- **UnionFind:** singletons → N components; chained unions → 1 component;
  out-of-range indices ignored (no panic).

---

## 7. Success / failure criteria + honesty caveats (f)

**Thread 5 success (expected):** many *independent* conflicts (non-commutativity
quantified) and near-total single-component coverage (transitivity premise
quantified). Report numbers, not adjectives: e.g. "links touch X/83 symbols in K
components" — quantify "nearly all." Real conflict/coverage statistics exceed the
shuffle null; the positive control fires.

**Thread 5 surprise (valuable):** conflicts few/fragile, or coverage fragmented
(>1 large component). Either weakens a premise of the 6-group reduction — write it
up; it feeds Threads 1 and 2. Coverage is evidence *for* transitivity, **not
proof** of it; state it at that strength (`thread-5-chaining-graph.md:106-108`).

**Thread 1B success (expected):** ≥1 (ideally several) genuine
order-83-forcing-plus-conflict cases reproduce the contradiction →
`DihedralExcluded`; the reduction to `{C₈₃:C₄₁, AGL(1,83), A₈₃, S₈₃}` stands,
reported as audited.

**Thread 1B surprise (valuable):** the cited isomorphs don't align, or the only
conflict depends on an unaligned/over-extended isomorph, or the >2-chain forcing
is an allomorph artifact → `IsomorphNotLocated` / `ForcingWithoutConflict`;
weakens the dihedral exclusion → write it up.

**Honesty caveats the reports MUST print (verbatim intent, §0):**
- The exclusion is **conditional on** assumptions A1–A5 (same plaintext, perfect
  isomorphism, no allomorph crossing, right-coset chaining action, single global
  configuration).
- HOLE 1: single-typo escape hatch at col6/col9 on the cited triple; the
  within-triple second conflict shares those columns and does not remove it.
- HOLE 2: on the cited triple the commutativity conflict exists **only** via the
  over-extended col9; the repeated 9-core shows order-83 forcing but **no
  conflict**. Robust refutation requires a forcing-plus-conflict inside
  repeated-core columns — which is exactly what the corpus-wide search counts and
  what `core_only_witnesses` reports.
- Claim ceiling everywhere: this constrains the candidate group set; it says
  **nothing** about recoverable plaintext. The eyes remain deterministic,
  engine-generated, strikingly structured data of unknown meaning; unsolved; no
  primary developer source confirms recoverable plaintext.

**Part A consequence encoded as a test** (`transitivity.rs`, from
`thread-1a-transitivity-proof.md` §5): a `#[test]` asserting the six candidate
group orders `{83, 166, 3403 (=83·41), 6806 (=83·82), "83!/2", "83!"}` and the
six hidden-subgroup sizes `{1, 2, 41, 82, "82!/2", "82!"}` — the large two as
symbolic markers (not numeric, they overflow), with a comment flagging the
correction from `thread-1a` that the wiki shorthand `{1,2,41,82,…}` hides the
enormous `A₈₃`/`S₈₃` stabilizers. This encodes the assumption rather than leaving
it folkloric; it changes no statistic.
