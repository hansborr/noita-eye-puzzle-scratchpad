# Thread 3 — Perfect-isomorphism scan: implementation spec (gated Rust)

Status of this document. Implementation spec only. It defines a new
library module, its public API, the null + controls + wiki regression checks, the
CLI/report wiring, and the lint/honesty gates. No statistics are computed here;
no number below is a finding. The Python scratch catalog and the conceptual
verification are prior work (`research/gak-threads/notes/thread-3-perfectiso-verification.md`,
`research/gak-threads/notes/reading-streams.md`). There is no
`notes/thread-3-empirical.md` in the tree at spec time; the empirical numbers it
would contain are produced by this module, not assumed by it.

Mapping-independent (non-negotiable). Everything operates on ciphertext
symbol *equality* and group/positional structure only. No symbol→meaning mapping
is invented or assumed. Values are `crate::trigram::TrigramValue` (`0..=82`,
`READING_LAYER_ALPHABET_SIZE = 83`); the only operations are `==`, gap-pattern
(first-occurrence) encoding, and positional alignment.

Honesty ceiling (printed verbatim by the report). The eyes remain
*deterministic, engine-generated, strikingly structured data of unknown meaning;
unsolved; no primary developer source confirms recoverable plaintext.* This
module measures evidence for or against perfect isomorphism, which bears on
family selection only. Perfect isomorphism is not provable without the
plaintext (`Perfect-Isomorphism.md`; `Isomorphs-(Gap-Patterns).md`). A
"supported" outcome keeps the GAK family in the running; it does not mean
"the eyes are GAK." A clean internal violation disfavours / falsifies the
proven-perfect-iso family (CTAK..XGAK) by contrapositive on the containment
proof (`Proof-that-GAK-has-perfect-isomorphism.md`), but does not by itself prove
the eyes are imperfectly isomorphic — XGAK's upper edge is `≤`, not `=`.

---

## Wiki pages this module encodes (cite exactly; preserve "tentative")

| Page (Lymm's eye-messages wiki, github.com/Lymm37/eye-messages/wiki, content to 2026-01-16) | What it gates |
| --- | --- |
| `Perfect-Isomorphism.md` | Definition: same plaintext ⇒ isomorphic outputs for all initial states. The honesty anchor ("not provable without plaintext"). |
| `Allomorphs.md` | Boundary-vs-internal distinction; the three concrete regression checks 3A/3B/3C; "the difference could occur anywhere between the last visible repeat and this point" (boundary *bounds*, not *locates*). |
| `Isomorphs-(Gap-Patterns).md` | Gap-pattern format (`.`/`A`/`B`…); the `A.B.CB.AC` main isomorph (6×, positive control); the per-(repeats × occurrences) chance table (baseline only — recompute under matched null, never quote as a finding). |
| `Isomorphic-Cipher-Hierarchy.md` | `CTAK < GCTAK < GAK < Perfectly Isomorphic`; `GAK < XGAK ≤ Perfectly Isomorphic`; "no good candidates" for imperfectly-isomorphic ciphers. |
| `Proof-that-GAK-has-perfect-isomorphism.md` | The containment proof making a single clean internal violation a family-falsifier. |
| `The-Funny‐looking-Obstacle.md` | Messages 1–2 desync (East1/West1): plaintext difference, not cipher imperfection — a benign desync explanation to gate against. |
| `The-Caboose.md` | Messages 2–3 (West1/East2) 2-char infix: plaintext difference (prefix/suffix/infix/extra word — "unclear", tentative). |
| `The-Stutter-Section.md` | Messages 7–9 (East4/West4/East5) single-char desyncs: under GAK can arise from identical plaintext when first letters differ — *expected*, not a violation. |

Message map (`reading-streams.md`, `corpus.rs`): wiki "messages 1,2,3" = corpus
`east1, west1, east2`; "messages 7,8,9" = `east4, west4, east5`.

---

## (a) Module: `src/perfect_isomorphism.rs`

New engine, mirroring `pyry_conditions.rs` / `cipher_attack.rs` shape. It owns
six capabilities the task enumerates:

1. **Isomorph catalog with significance** — enumerate cross-message gap-pattern
   matches and attach a matched-null significance score.
2. **Maximal-conservative extension** — extend each strong cross-message isomorph
   alignment outward until the gap pattern first diverges, conservatively.
3. **Break localization** — the exact first divergent index per aligned pair.
4. **Boundary/internal classifier** — label each break benign (boundary) vs
   candidate violation (internal), gated by two-sided continuing agreement and
   the three benign desync explanations.
5. **Matched internal-violation null** — within-message shuffle null answering
   "how many internal-violation candidates arise from chance gap-pattern
   collisions alone?".
6. **Safe-isomorph-extent export** — the maximal-extent / boundary map consumed
   by Threads 1B and 5 so they never chain across differing plaintext.

### Constants

```rust
/// Default deterministic seed for the internal-violation null and any sampling.
pub const DEFAULT_SEED: u64;                    // distinct 8-byte tag, e.g. b"perfiso\0"
/// Default within-message shuffle trials for the matched internal-violation null.
/// The empirical headline (§4) used 3000 shuffles for the internal-violation null
/// and 2000 for the catalog-significance null; this default reproduces the headline
/// regime. Do NOT drop to a smaller count silently — the add-one p floor scales as
/// `1/(trials+1)` and the strong-tier zero-event headline needs the larger regime.
pub const DEFAULT_TRIALS: usize = 3_000;        // empirical headline null = 3000 shuffles
/// Minimum gap-pattern window length scanned for cross-message isomorphs. The
/// empirical catalog scanned windows 8/9/11; smaller windows are admitted only to
/// host the lower-window wiki regression checks (e.g. the 8-window `A.B..B.A`
/// 2-repeat cross-cut), never to seed strong isomorphs.
pub const DEFAULT_MIN_WINDOW: usize = 8;        // empirical scanned windows 8/9/11
/// Maximum gap-pattern window length scanned for cross-message isomorphs. MUST be
/// >= 11 so the mandatory positive controls — the w9 `A.B.CB.AC` and the w11
/// `ABC.DC.AD.B` isomorphs — can form their literal `windows(window)` spans. A
/// max of 8 forms no 9- or 11-span window, so the main-isomorph positive control
/// can never fire and the strong-bar headline becomes vacuous.
pub const DEFAULT_MAX_WINDOW: usize = 11;       // empirical scanned windows 8/9/11
/// Minimum same-offset agreement run flanking a break for it to count "internal".
pub const MIN_TWO_SIDED_FLANK: usize = 2;       // = perseus::MIN_SHARED_RUN_LEN
/// Maximum desync-island width (in columns) an internal-violation candidate may
/// span. The empirical's regression-hardened discriminator requires a SHORT island
/// (<=2 columns); wider differing-plaintext gaps are boundary allomorphs, not
/// violations (empirical §2-3, over-extension trap #1).
pub const MAX_ISLAND_COLS: usize = 2;           // empirical "short island (<=2 cols)"
/// Minimum length of the re-synced isomorphic FAR RUN that must follow the island
/// for an internal-violation candidate, carrying a shared cross-island back-reference.
/// Without this guard the classifier reintroduces over-extension trap #2 — late
/// re-convergence on DIFFERENT plaintext faking a violation (the wiki's "3A" case) —
/// which manufactures spurious internal-violation candidates and would break the
/// "0 robust internal violations" headline. The empirical's `POST_MIN = 8` rule is
/// exactly what evaporated the spurious intra-west1 self-pair candidate.
pub const POST_MIN: usize = 8;                  // empirical regression-hardened far-run guard
/// Fixed reading-layer alphabet size (values 0..=82).
pub const ALPHABET_SIZE: usize;                 // = orders::READING_LAYER_ALPHABET_SIZE
/// Minimum repeated symbols in a gap pattern for "strong" classification. The
/// empirical defines strong = >=3 repeats vs loose = >=2 (§4 table); the two strong
/// controls carry 3 (`A.B.CB.AC`) and 4 (`ABC.DC.AD.B`) repeats. At =2 the strong
/// tier would absorb the loose tier — including the loose-bar east4@65/west4@67
/// candidate (null p ≈ 0.049) — and FLIP the headline from "0 robust strong-bar
/// internal violations" to surfacing that benign Stutter-Section candidate.
pub const STRONG_MIN_REPEATS: usize = 3;        // empirical strong bar = >=3 repeats
/// Minimum cross-message occurrence count for "strong".
pub const STRONG_MIN_OCCURRENCES: usize = 2;
/// Pointwise significance threshold for the internal-violation tail.
pub const SIGNIFICANCE_ALPHA: f64 = 0.05;       // = perseus::SIGNIFICANCE_ALPHA
```

### Config / Error / Report (documented public surface)

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfectIsomorphismConfig {
    /// Deterministic PRNG seed for the internal-violation null.
    pub seed: u64,
    /// Within-message shuffle trials.
    pub trials: usize,
    /// Minimum gap-pattern window length scanned.
    pub min_window: usize,
    /// Maximum gap-pattern window length scanned.
    pub max_window: usize,
}
impl Default for PerfectIsomorphismConfig { /* fills from DEFAULT_* */ }
// NOTE (empirical fidelity): the prototype scanned the discrete window set
// {8, 9, 11}, NOT a contiguous 8..=11 (window 10 was never enumerated). With the
// default `min_window = 8 .. max_window = 11`, the scan range as a naive inclusive
// span would also visit window 10. To reproduce the empirical catalog exactly,
// enumerate windows {8, 9, 11} (the two strong controls live at 9 and 11); a
// contiguous 8..=11 is a permissible superset only if window-10 hits are reported
// as new/unvetted, never folded into the strong-bar headline without their own null.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PerfectIsomorphismError {
    /// The verified corpus could not be reconstructed or read.
    Grid(GridError),
    /// At least one shuffle trial is required.
    ZeroTrials,
    /// `min_window > max_window`, or a window is zero/exceeds a message length.
    InvalidWindowRange { min_window: usize, max_window: usize },
    /// A random draw bound did not fit the deterministic PRNG helper.
    RandomBoundTooLarge { bound: usize },
    /// An isomorph primitive rejected a window/period configuration.
    Isomorph(crate::isomorph::IsomorphError),
    /// A regression check failed: the catalog did not reproduce a pinned wiki
    /// gap pattern. Methodology/data is suspect, not a finding.
    RegressionCheckFailed { check: WikiRegressionCheck },
    /// The positive control did not fire on the planted `A.B.CB.AC` signal.
    PositiveControlFailed { detail: String },
}
// From<GridError>, From<crate::null::RandomBoundError>, From<isomorph::IsomorphError>.
// Display + std::error::Error (carries String) so main can take it by `&`.
```

```rust
/// One cross-message gap-pattern match, before extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsomorphCatalogEntry {
    /// Rendered first-occurrence gap pattern (PatternSignature::render).
    pub signature: String,
    /// Number of distinct repeated symbols in the pattern (its "strength").
    pub repeat_count: usize,
    /// (message_key, start_offset) for each occurrence, ascending.
    pub occurrences: Vec<(&'static str, usize)>,
    /// Window length of the matched pattern.
    pub window: usize,
}

/// Significance for one catalog entry under the matched within-message null.
#[derive(Clone, Debug, PartialEq)]
pub struct IsomorphSignificance {
    /// The entry this score belongs to (signature + window identify it).
    pub signature: String,
    pub window: usize,
    /// Observed cross-message occurrence count.
    pub observed_occurrences: usize,
    /// Mean / max occurrence count of this signature under the shuffle null.
    pub null_mean_occurrences: f64,
    pub null_max_occurrences: usize,
    /// Shuffles whose occurrence count >= observed.
    pub empirical_p_count: usize,
    /// Add-one one-sided empirical p `(count+1)/(trials+1)`.
    pub empirical_p: f64,
    /// True iff `empirical_p <= SIGNIFICANCE_ALPHA` AND repeat_count/occurrences
    /// clear STRONG_MIN_*; weak/coincidental entries are labelled, not dropped.
    pub strong: bool,
}

/// How a maximally-extended aligned isomorph pair first diverges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakClass {
    /// Trailing-edge divergence; differing plaintext plausibly follows. Benign,
    /// consistent with perfect isomorphism (Allomorphs.md line 1).
    Boundary,
    /// Divergence flanked on BOTH sides by continuing isomorphic agreement —
    /// candidate perfect-isomorphism violation. Requires the full regression-hardened
    /// discriminator: (a) a SHORT desync island (<= `MAX_ISLAND_COLS` columns), AND
    /// (b) a substantial re-synced isomorphic far run (>= `POST_MIN` columns) that
    /// carries a shared cross-island back-reference identical in both occurrences.
    /// The far-run guard (b) rejects over-extension trap #2 (late re-convergence on
    /// DIFFERENT plaintext faking a violation — the wiki's "3A" case). Not promoted
    /// to a finding until it also survives the three benign-desync gates and the null.
    InternalCandidate,
    /// Internal-looking, but explained by a named benign desync region.
    BenignDesync { region: BenignDesyncRegion },
}

/// Named benign desync regions the wiki already attributes to plaintext, not
/// cipher imperfection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenignDesyncRegion {
    /// The Funny-looking Obstacle (East1/West1).
    FunnyLookingObstacle,
    /// The Caboose (West1/East2).
    Caboose,
    /// The Stutter Section (East4/West4/East5).
    StutterSection,
}

/// One localized break in a maximally-extended aligned isomorph pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakLocalization {
    /// Aligned message pair (left_key, right_key).
    pub pair: (&'static str, &'static str),
    /// Anchor offsets in each message where the shared run began.
    pub anchor: (usize, usize),
    /// Length of two-sided continuing agreement on each side of the break.
    pub left_flank: usize,
    pub right_flank: usize,
    /// First index (relative to the extended window) where gap patterns diverge.
    pub break_index: usize,
    /// Width of the desync island in columns (the contiguous diverging span before
    /// re-sync). An `InternalCandidate` requires `island_cols <= MAX_ISLAND_COLS`;
    /// a wider island is a `Boundary` allomorph.
    pub island_cols: usize,
    /// Length of the re-synced isomorphic far run AFTER the island that carries a
    /// shared cross-island back-reference. An `InternalCandidate` requires
    /// `far_run >= POST_MIN`; a shorter far run is late coincidental re-convergence
    /// (over-extension trap #2 / wiki "3A") and stays `Boundary`.
    pub far_run: usize,
    /// Classification.
    pub class: BreakClass,
}

/// Safe-isomorph extent for one cross-message aligned isomorph: the half-open
/// span of *gap-pattern-confirmed* shared structure, conservative to the break.
/// Exported for Threads 1B / 5 — they must NOT chain past `safe_end`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeIsomorphExtent {
    pub pair: (&'static str, &'static str),
    /// Per-message half-open safe span [start, end) (end excludes the break).
    pub left_span: SafeSpan,
    pub right_span: SafeSpan,
    /// The break that bounds this extent (None iff the run reached message end).
    pub bounding_break: Option<BreakLocalization>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafeSpan { pub start: usize, pub len: usize }
impl SafeSpan { #[must_use] pub const fn end(&self) -> usize { self.start + self.len } }

/// Matched internal-violation null band.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InternalViolationNullBand {
    pub trials: usize,
    /// Mean / median / q975 / max internal-candidate count across shuffles.
    pub count_mean: f64,
    pub count_median: f64,
    pub count_q975: usize,
    pub count_max: usize,
}

/// Pinned wiki gap-pattern regression checks (3A/3B/3C + main-isomorph control).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WikiRegressionCheck {
    /// 3A: East1/West1 shared section `A..BC.D....AB.......DC...` vs `…DC..D`.
    Messages12SharedAllomorph,
    /// 3B: East4/West4/East5 shared tail isomorph `.AB......B.A` (@35) + msg7's
    /// extra `O…O` repeat. Asserts the two load-bearing claims, NOT the wiki's
    /// `*`-annotated rows verbatim (those use `*` relabeling and do not match a
    /// plain gap string character-for-character — empirical §5).
    Messages789ExtraRepeat,
    /// 3C: single-deletion bound `+++++xxxxx?????x++++++++++++` (HYPOTHESIS).
    CorruptionTheoryBound,
    /// Main isomorph `A.B.CB.AC`, 6 occurrences across messages 1–3.
    MainIsomorphPositiveControl,
}

/// One regression-check outcome (exact-equality assertion result + the strings).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WikiRegressionResult {
    pub check: WikiRegressionCheck,
    /// Gap-pattern strings the catalog produced for the cited region.
    pub produced: Vec<String>,
    /// The verbatim wiki strings expected.
    pub expected: Vec<String>,
    /// True iff produced == expected character-for-character. (Exception: 3B
    /// asserts its two load-bearing claims — shared `.AB......B.A` tail + msg7's
    /// extra `O…O` repeat — not verbatim equality of the wiki's `*`-relabeled rows,
    /// which do not match a plain gap string char-for-char; empirical §5.)
    pub reproduced: bool,
    /// For 3C only: carries the explicit "hypothesis, conditional on
    /// single-deletion assumption" label; empty otherwise.
    pub hypothesis_label: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PerfectIsomorphismReport {
    pub config: PerfectIsomorphismConfig,
    pub order: ReadingOrder,
    pub message_lengths: Vec<(&'static str, usize)>,
    pub total_length: usize,
    /// Cross-message gap-pattern catalog, every entry (weak ones labelled).
    pub catalog: Vec<IsomorphCatalogEntry>,
    pub significance: Vec<IsomorphSignificance>,
    /// Localized breaks for each maximally-extended strong isomorph.
    pub breaks: Vec<BreakLocalization>,
    /// Headline: count of internal-violation candidates surviving all gates.
    pub robust_internal_violations: usize,
    pub internal_violation_null: InternalViolationNullBand,
    /// Add-one tail: shuffles whose internal-candidate count >= observed.
    pub empirical_p_count: usize,
    pub empirical_p: f64,
    /// Safe-isomorph extents exported to Threads 1B / 5. Each entry is anchored on
    /// a strong (>=3-repeat) seed and extended left+right to the first divergence
    /// using the conservative (tightest) right boundary over all partners. Empirical
    /// reproducibility anchor: **16 spans**, all in the messages 1–3 (east1/west1/
    /// east2) main-isomorph cluster (empirical §6). This count is deterministic given
    /// the corpus + constants, not a Monte-Carlo estimate.
    pub safe_extents: Vec<SafeIsomorphExtent>,
    /// Wiki regression checks (all must reproduce or the run errors).
    pub regression: Vec<WikiRegressionResult>,
    /// Positive control fired on the planted `A.B.CB.AC` signal.
    pub positive_control_fired: bool,
}
```

### Entry point

```rust
/// Runs the perfect-isomorphism scan on the verified eye corpus.
///
/// # Errors
/// Returns [`PerfectIsomorphismError`] when the corpus cannot be reconstructed,
/// the configuration is invalid, an isomorph primitive rejects a window, a wiki
/// regression check fails to reproduce, or the positive control does not fire.
pub fn run_perfect_isomorphism(
    config: PerfectIsomorphismConfig,
) -> Result<PerfectIsomorphismReport, PerfectIsomorphismError>;
```

Body order (mirrors `pyry_conditions.rs:397-401`, `perseus.rs:322-329`):
`validate_config(config)?` → `grids = orders::corpus_grids()?` →
`order = orders::accepted_honeycomb_order()` →
`message_values = orders::read_corpus_message_values(&grids, order)?` →
build catalog → significance → extend+localize+classify → null → safe extents →
run regression checks (error on mismatch) → run positive control (error on
miss) → assemble report. Never re-select a reading order.

---

## (b) Documented public API signatures

All `pub` items above carry `///` docs (every field/variant — `missing_docs`).
The public free surface is exactly:

- `run_perfect_isomorphism(PerfectIsomorphismConfig) -> Result<PerfectIsomorphismReport, PerfectIsomorphismError>`
- the `DEFAULT_*` / `ALPHABET_SIZE` / `MIN_TWO_SIDED_FLANK` / `STRONG_MIN_*` /
  `SIGNIFICANCE_ALPHA` consts (used as clap `default_value_t`).
- the `Config`, `Report`, `Error`, and all result structs/enums listed in (a),
  consumed by `report.rs` and by Threads 1B/5 (`SafeIsomorphExtent` / `SafeSpan`).

The `From` impls (`GridError`, `null::RandomBoundError`, `isomorph::IsomorphError`)
and `Display`/`Error` are public-by-trait. Everything else (extension walk,
classifier internals, shuffle loop, regression-string builders) is private
`fn`s with no `missing_docs` obligation.

---

## (c) Reuse points (file:line — do not reimplement)

| Need | Reuse | Reference |
| --- | --- | --- |
| Verified corpus grids | `orders::corpus_grids()` | `perseus.rs:324`, `pyry_conditions.rs:397-401` |
| Per-message streams (boundaries kept) | `orders::read_corpus_message_values(&grids, order)` | `perseus.rs` body |
| Accepted order (never re-select) | `orders::accepted_honeycomb_order()` | `pyry_conditions.rs:397` |
| Alphabet size 83 | `orders::READING_LAYER_ALPHABET_SIZE` | `pyry_conditions.rs:33` |
| Gap-pattern (equality) encoding — the load-bearing primitive | `isomorph::PatternSignature::from_window::<TrigramValue>` | `isomorph.rs:38` |
| Render gap pattern to compare with wiki strings | `PatternSignature::render` / `values` | `isomorph.rs:76`, `isomorph.rs:86` |
| Repeat-count strength of a window | `PatternSignature::has_repeated_symbol` (+ count distinct repeated ordinals) | `isomorph.rs:63` |
| Within-sequence informative-signature catalog (per message, to seed cross-message bookkeeping) | `isomorph::detect_isomorphs::<TrigramValue>(seq, window, min_period, max_period)` and `SignatureGroup`/`strongest_signatures` | `isomorph.rs:212`, `isomorph.rs:174` |
| Within-message shuffle null mechanism (copy the shape) | `null::fisher_yates` over `message_values.to_vec()`; `null::SplitMix64::new(seed)` | `isomorph_null.rs:8`, `isomorph_null.rs:301` |
| Per-trial/family derived seeds | `null::mix_seed(seed, tag)` (`stateless_splitmix(seed ^ tag)`) | `null.rs:91` |
| Add-one empirical p | `null::add_one_p_value(count, trials)` | `null.rs:80` |
| Significance helpers if Wilson/Bonferroni wanted | `null::wilson_95`, `null::analytic_headline_bounds` | `null.rs` |
| Same-offset cross-message agreement runs — the alignment substrate | `perseus`'s `same_offset_common_runs` / `collect_pair_runs` (private) | `perseus.rs:466`, `perseus.rs:509` |
| Leading-family / counterpart / global-prefix anchors | `perseus::SharedPartition.leading_start`, `GlobalSharedPrefix`, `is_counterpart_pair` (private fn) | `perseus.rs:208`, `perseus.rs:180`, `perseus.rs:574` |
| Chi-square / IoC baselines (only if a numeric baseline is wanted) | `analysis::chi_square_*`, `analysis::index_of_coincidence` (take `Glyph`, not `TrigramValue`) | `analysis.rs:141-213`, `analysis.rs:76` |

Promotion request (resolve before coding). Perseus's same-offset run
reconstruction (`same_offset_common_runs`, `collect_pair_runs`,
`is_counterpart_pair`, `global_shared_prefix`) is exactly Thread 3's alignment
substrate but is private to `perseus.rs`. Two options, pick one and record it:

1. **Promote** to `pub(crate)` in `perseus.rs` and call from
   `perfect_isomorphism.rs`. Minimal change, single source of truth for "where do
   two messages share the same symbol at the same offset", but edits `perseus.rs`
   (out of scope for the *analysis* run, in scope for this *new module*).
2. **Reimplement** the same-offset walk locally over `message_values` (the walk
   is short — `perseus.rs:513-524`), keeping `perseus.rs` untouched, at the cost
   of a second copy to keep in sync.

The spec recommends option 1 (`pub(crate) fn same_offset_common_runs` +
`pub(crate) fn is_counterpart_pair`), because Thread 5 (chaining graph) and
Thread 1B will want the same anchors and a single definition prevents drift.
Note this is a same-offset alignment; cross-message isomorphs that recur at
*different* offsets (the main isomorph sits at west1@40/@70, east2@45 —
`reading-streams.md`) are found by `PatternSignature::from_window` bookkeeping,
not by the same-offset run finder. Use the run finder for shared-section
anchoring and the signature primitive for offset-free isomorph matching; the two
are complementary, not redundant.

---

## (d) Null + positive controls + wiki allomorph regression checks

### Matched internal-violation null (mandatory, matched)

- **Statistic:** count of *internal-violation candidates* — breaks classified
  `InternalCandidate` — produced by the same catalog → extend → localize →
  classify pipeline. A break is an `InternalCandidate` iff all of: (i) two-sided
  continuing agreement, each flank ≥ `MIN_TWO_SIDED_FLANK`; (ii) a short desync
  island, `island_cols ≤ MAX_ISLAND_COLS`; (iii) a substantial re-synced isomorphic
  far run, `far_run ≥ POST_MIN`, carrying a shared cross-island back-reference
  identical in both occurrences; and (iv) it is not inside a named benign desync
  region. Guards (ii)+(iii) are the empirical's regression-hardened discriminator
  (§2-3): without the `far_run ≥ POST_MIN` guard, late re-convergence on different
  plaintext across the island fakes a violation (over-extension trap #2, wiki "3A")
  and manufactures spurious candidates. Distinct events are deduplicated by break
  column (overlapping seeds pinning one desync count once), matching the empirical
  headline.
- **Null model string** (carry on the report like `cipher_attack`): *"within
  each message, preserve the exact symbol multiset and length, shuffle order,
  recompute the internal-candidate count."* This destroys real shared plaintext
  while conserving per-message symbol statistics, so it answers exactly the
  thread's question: *how many internal violations arise from chance gap-pattern
  collisions alone?* (thread §4).
- **Mechanism (copy the `isomorph_null` shuffle shape):** `let mut rng = SplitMix64::new(null::mix_seed(config.seed, trial_tag));` then per trial
  `let mut shuffled = message_values.to_vec(); for v in &mut shuffled { fisher_yates(v, &mut rng)?; }`
  then rerun catalog+classify on `shuffled` (cross-message; the run finder and
  signature matcher both operate on the shuffled streams).
- **Tail:** `robust_internal_violations` is expected to be low. Frame it as
  an upper-tail exceedance: add-one one-sided p = (shuffles with internal-candidate
  count ≥ observed + 1)/(trials + 1), with an `InternalViolationNullBand`
  (mean/median/q975/max). Report as a tail, not a verdict. Because perfect
  isomorphism predicts *zero* robust internal violations,
  the headline negative ("none survive") is the *expected* outcome and supports
  GAK-family viability; the null calibrates how surprising the *observed* count is.

### Positive control (mandatory, must fire on known signal)

- **Plant the `A.B.CB.AC` main isomorph** (`Isomorphs-(Gap-Patterns).md:9-26`):
  it occurs 6× across messages 1–3. The detector must fire on it — catalog it,
  attach significance with `strong == true`, and (per the wiki's own logic)
  classify its trailing divergences as Boundary, never internal. This is the
  `MainIsomorphPositiveControl` regression check *and* the positive control.
- **Margin gate:** the planted/real `A.B.CB.AC` significance must clear the null
  band with a margin (reuse `cipher_attack`'s `POSITIVE_CONTROL_MIN_MARGIN`
  idiom, `cipher_attack.rs:1255`). Failure ⇒ `PositiveControlFailed` error —
  methodology suspect, not a finding.
- **Negative companion:** a uniform-random within-message stream must yield
  `strong == false` for that signature and zero robust internal violations on
  average (the null band itself doubles as this negative control, per
  `isomorph_null`'s `uniform_random_*` test).

### Wiki allomorph regression checks (exact-string, character-for-character)

Each is a `WikiRegressionResult`; a mismatch is `RegressionCheckFailed`
(validates the wiki's data handling and our `isomorph.rs` simultaneously).

Regression strings are computed over fixed cited spans, not the catalog scan
range. Each check encodes a gap pattern via `PatternSignature::from_window` over
the wiki's cited (offset, length) span directly — e.g. 3A's 24-column window at
offset 1 — which deliberately exceeds `DEFAULT_MAX_WINDOW` (= 11). The `[min_window,
max_window]` range governs only the cross-message strong-isomorph catalog scan; do
not source these verbatim strings from that bounded scan or 3A/3C can never reproduce.

- **3A — `Messages12SharedAllomorph`** (`Allomorphs.md:4-10`,
  `notes/thread-3-perfectiso-verification.md` §3A). Catalog's aligned gap-pattern
  strings for the East1/West1 shared section must equal verbatim:
  - msg 1 (top): `A..BC.D....AB.......DC...`
  - msg 2 (bottom): `A..BC.D....AB.......DC..D`
  Classifier must label the sole differing (last) position Boundary, not
  internal. Assert both strings + the `Boundary` label.
- **3B — `Messages789ExtraRepeat`** (`Allomorphs.md:12-31`, verification §3B).
  Assert only the load-bearing claims, not the `*`-annotated rows verbatim. The
  empirical found that the wiki's `*`-annotated rows use wiki-specific `*` relabeling
  and do not match a plain gap string character-for-character; only the two
  load-bearing facts reproduce, so those are what the check pins:
  - the strong tail isomorph `.AB......B.A` is identical across all of 7/8/9
    (anchored @35); and
  - msg 7 carries an extra `O…O` repeat (anchor-relative positions 10, 16, 26) that
    8/9 lack — the allomorphic feature.
  The classifier must (i) confirm the shared `.AB......B.A` tail isomorph across
  7/8/9, (ii) flag msg 7's `O…O` repeat as the allomorphic feature, (iii) not
  promote anything to internal (it is allomorphic *before* the strong tail —
  `StutterSection` benign). Do not gate on verbatim equality of the `*`-annotated
  rows; pinning those would fail the regression check on a relabeling artefact, not
  a real data error.
- **3C — `CorruptionTheoryBound`** (`Allomorphs.md:31-37`, verification §3C).
  Status: Hypothesis — `hypothesis_label` must carry "conditional on
  single-deletion assumption; bounds where a difference must be, does not locate
  it." Reproduce verbatim the exclusion row:
  - `+++++xxxxx?????x++++++++++++`
  Output framed as *bounds* (`?` range), never "the difference is at position k".
  Dropping the conditional label or emitting a pinpoint is a regression failure.
- **Main-isomorph control — `MainIsomorphPositiveControl`** (above). The wiki's
  quoted ~3×10⁻²⁰ figure is the wiki's estimate, not recomputed; the report
  must recompute significance under the matched null and may *compare to* the
  wiki figure, never *quote it as a finding* (`verification` §cross-cutting note).

---

## (e) CLI subcommand + report wiring

Four files, no `Cargo.toml`/CI edits.

`src/lib.rs` — insert alphabetically between `periodicity` (`:81`) and
`perseus` (`:82`):
```rust
pub mod perfect_isomorphism;
```

**`src/main.rs`**
- Import: add `perfect_isomorphism` to the `use noita_eye_puzzle::{…}` block
  (`main.rs:10-15`), alphabetically.
- `enum Command` (`main.rs:34-84`): add, after `Perseus(PerseusArgs)` (`:67`):
  ```rust
  /// Thread 3 perfect-isomorphism / allomorph-consistency scan.
  #[command(name = "perfectiso", alias = "perfect-isomorphism")]
  Perfectiso(PerfectIsomorphismArgs),
  ```
- `Args` struct + `From` (model on `IsomorphNullArgs` `main.rs:177-189`):
  ```rust
  #[derive(Clone, Copy, Debug, Args)]
  struct PerfectIsomorphismArgs {
      #[arg(long, default_value_t = perfect_isomorphism::DEFAULT_SEED)]
      seed: u64,
      #[arg(long, default_value_t = perfect_isomorphism::DEFAULT_TRIALS)]
      trials: usize,
      #[arg(long = "min-window", default_value_t = perfect_isomorphism::DEFAULT_MIN_WINDOW)]
      min_window: usize,
      #[arg(long = "max-window", default_value_t = perfect_isomorphism::DEFAULT_MAX_WINDOW)]
      max_window: usize,
  }
  impl From<PerfectIsomorphismArgs> for perfect_isomorphism::PerfectIsomorphismConfig {
      fn from(args: PerfectIsomorphismArgs) -> Self {
          Self { seed: args.seed, trials: args.trials,
                 min_window: args.min_window, max_window: args.max_window }
      }
  }
  ```
- Dispatch fn (model on `run_perseus` `main.rs:609`; error taken by `&` since it
  carries a `String`, like `run_cipherattack` / `run_pyry`):
  ```rust
  fn run_perfectiso(config: perfect_isomorphism::PerfectIsomorphismConfig) -> ExitCode {
      let report = match perfect_isomorphism::run_perfect_isomorphism(config) {
          Ok(report) => report,
          Err(error) => {
              eprintln!("perfect-isomorphism error: {}",
                  report::format_perfect_isomorphism_error(&error));
              return ExitCode::FAILURE;
          }
      };
      report::print_perfect_isomorphism_report(&report);
      ExitCode::SUCCESS
  }
  ```
- `main()` match arm after `Command::Perseus` (`main.rs:442`):
  `Command::Perfectiso(args) => run_perfectiso(args.into()),`

**`src/report.rs`**
- Add `perfect_isomorphism` to the `use crate::{…}` block (`report.rs:8-12`),
  alphabetically.
- `format_perfect_isomorphism_error(error: &perfect_isomorphism::PerfectIsomorphismError) -> String`
  (`#[must_use] pub fn`, `&` because it carries `String`; pattern from
  `format_cipher_attack_error` `report.rs:319`, `format_pyry_conditions_error`
  `report.rs:190`): a `match` over every variant returning user-facing text. No
  `unwrap`/`panic`. `RegressionCheckFailed` and `PositiveControlFailed` must say
  "methodology/transcription suspect, not a finding".
- `print_perfect_isomorphism_report(report: &perfect_isomorphism::PerfectIsomorphismReport)`
  (`println!` only; private `fn print_*` sub-sections like `report.rs:815+`):
  - catalog + significance table (mark weak entries "coincidental-class");
  - break table with `BreakClass` labels;
  - headline line: `robust_internal_violations`, the null band, and the add-one
    empirical p;
  - safe-extent table (the export);
  - regression-check pass/fail rows, with 3C carrying its hypothesis label;
  - a `Multiplicity note:` (multiple isomorphs × windows are tested — cite the
    `print_honeycomb_interpretation` idiom `report.rs:909`);
  - a final `Interpretation:` paragraph stating the ceiling (see (g)), citing
    `Perfect-Isomorphism.md` + `Allomorphs.md` and preserving "tentative".

---

## (f) Lint compliance (`-D warnings` in CI)

- `missing_docs`: every `pub` item — including each struct field and enum
  variant above — has a `///`.
- No `unwrap`/`expect`/`panic`/`indexing_slicing`/`string_slice` in lib/CLI.
  Index via `.get(i)` + `let Some(x) = … else { return Err(…) }`; iterate via
  `.windows()`/`.chunks()`/`.iter().zip()`. Relaxed only under `#[cfg(test)]`.
- `unused_results`: bind dropped `#[must_use]` (`let _inserted = set.insert(x);`,
  `pyry_conditions.rs:681`).
- `panic_in_result_fn`: `run_perfect_isomorphism` and all `-> Result` helpers
  never panic — regression mismatches return `RegressionCheckFailed`, not
  `assert!`.
- `float_cmp`/`lossy_float_literal`: compare `empirical_p`/rates with
  `total_cmp`/tolerance, never `==` (`report.rs` uses `.total_cmp`).
- `map_err_ignore`: rely on the `From` impls so `?` carries the source; no
  `map_err(|_| …)`.
- `allow_attributes_without_reason`: any `#[allow]` carries `reason = "…"`.
- `cognitive-complexity-threshold = 20` / `too-many-arguments-threshold = 7` /
  `max-struct-bools = 3`: split the extend→localize→classify walk into small
  private fns; bundle the per-pair walk inputs into a private `struct`
  (cf. `PairInput` `pyry_conditions.rs:552`, `PairRunInput` `perseus.rs:499`);
  keep ≤3 bool fields per struct (the report uses enums/counts, not bool flags).
- `wildcard_imports`: every import named explicitly.
- `unsafe` forbidden crate-wide; `--locked` everywhere (no new deps — all reuse
  is in-crate).

---

## (g) Success / failure criteria + honesty caveats

### Success (engine correctness — gates `make verify`)

- **Determinism:** `run_perfect_isomorphism(cfg) == run_perfect_isomorphism(cfg)`
  for a fixed seed (`cipher_attack.rs:1317`, `pyry_conditions.rs:1446`).
- **Eye pin:** `total_length == 1_036`; nine message lengths match
  `reading-streams.md` (`east1=99 … east5=114`); 83 distinct global symbols
  (`pyry_conditions.rs:1430` idiom).
- **All four wiki regression checks reproduce**, else the run errors. 3A, 3C and
  the `A.B.CB.AC` control reproduce verbatim (character-for-character); 3B
  reproduces its two load-bearing claims (shared `.AB......B.A` tail + msg7's
  extra `O…O` repeat), not the wiki's `*`-relabeled rows verbatim (empirical §5).
  3C carries its hypothesis label.
- **Positive control fires:** `A.B.CB.AC` is catalogued `strong == true` with a
  margin over the null; classified `Boundary` at its trailing divergence
  (`cipher_attack.rs:1334` idiom). Failure ⇒ `PositiveControlFailed`.
- **Negative control:** uniform-random within-message streams give
  `strong == false` and zero robust internal violations on average.

### Headline outcomes (family-selection *evidence*, never a decode)

- **Supports perfect isomorphism (GAK family stays viable):**
  `robust_internal_violations == 0` after the three benign-desync gates, or the
  observed count is within the chance-collision null (`empirical_p` not in the
  upper tail). Report the *strongest defensible statement of support* — without
  claiming proof (plaintext unknown). The Funny-looking Obstacle, Caboose, and
  Stutter breaks must all land as `Boundary`/`BenignDesync`, matching the wiki.
- **Against perfect isomorphism (high-value, redirects the field):** ≥1
  `InternalCandidate` survives the three gates and exceeds the null
  (`empirical_p <= SIGNIFICANCE_ALPHA`). Then GAK is disfavoured; the frontier
  moves to XGAK / imperfectly-isomorphic ciphers — for which the wiki states there
  are no good candidates (`Isomorphic-Cipher-Hierarchy.md`), so this becomes
  an explicit ask back to the community. Each surviving candidate is documented
  *individually* with its two-sided flank lengths and why no benign explanation
  applies.

### Honesty caveats (must appear in the report's `Interpretation:`)

- **Not a decode.** This is mapping-independent; it yields no symbol→meaning
  mapping. "Perfect isomorphism supported" ≠ "the eyes are GAK" — it only keeps
  GAK in the running (thread §Pitfalls; verification §Honesty anchor).
- **Not provable.** Perfect isomorphism cannot be proven without the plaintext
  (`Perfect-Isomorphism.md`). Both outcomes are *evidence*, not proof.
- **Conservatism is load-bearing.** Default every break to `Boundary` unless
  two-sided continuing agreement is unambiguous; over-extending manufactures fake
  internal violations (thread §Pitfalls). The `MIN_TWO_SIDED_FLANK` gate + the
  three benign-desync regions encode this.
- **Corruption theory is a hypothesis** that *bounds* where a difference must
  lie, not a fact and not a unique locator (`Allomorphs.md:31-37`).
- **`≤`, not `=`.** A violation leaves the *proven* perfect-iso region
  (CTAK..XGAK) but does not prove the eyes are imperfectly isomorphic — XGAK's
  upper boundary is open (verification §1). Print "GAK family disfavoured /
  falsified", never "provably imperfectly isomorphic".
- **The ceiling, printed verbatim:** *deterministic, engine-generated, strikingly
  structured data of unknown meaning; unsolved; no primary developer source
  confirms recoverable plaintext.*

### Downstream contract (Threads 1B / 5)

`PerfectIsomorphismReport.safe_extents: Vec<SafeIsomorphExtent>` is the
safe-isomorph list Threads 1B and 5 consume: each `SafeSpan` is conservative
to the bounding break, so chaining/transitivity built on these spans never
crosses differing plaintext (thread §Pitfalls "Feeds Thread 1 and Thread 4").
Consumers must treat `safe_end` as exclusive and must not extend past a
`bounding_break`.
