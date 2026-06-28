//! Unit 2c — EYES STEP 3: the only unit that touches the real eye corpus.
//!
//! Points the matured attack at the verified embedded eye corpus and measures the
//! standing **BLOCKED** conclusion against matched within-message nulls, asserting
//! no decode. The eyes honesty caveats (mapping-is-HYPOTHESIS) live with this code.

use super::*;

// =====================================================================
// UNIT 2c — EYES STEP 3: point the matured attack at the REAL eye corpus.
//
// ## What is recovered vs what is NOT (the honest reality, encoded)
//
// The attack recovers STRUCTURE (visible-coset actions / chain-link constraints),
// NOT cleartext. Even a full recovery of the eye group structure yields abstract
// plaintext-letter INDICES, not readable text, because mapping symbols→letters
// needs an external ANCHOR (exactly the standing blocker). So a "candidate
// cleartext" can ONLY arise by ADDITIONALLY hypothesizing a symbol→letter mapping.
// The cleartext path is therefore SPECULATIVE, gated, Finnish-weighted, and never
// primary.
//
// ## Entry path (EXACT — never deviate)
//
//   orders::corpus_grids() → orders::accepted_honeycomb_order()
//   → orders::read_corpus_message_values(&grids, order)
//
// PER-MESSAGE streams, message boundaries KEPT; NEVER concatenate across messages;
// NEVER re-select a reading order. (notes/reading-streams.md)
//
// ## The kill gates (in spec order; every candidate is a HYPOTHESIS until ALL pass)
//
// 1. HELD-OUT isomorphs. Recover on a SUBSET of each message's isomorph chain links
//    (the TRAIN fold), and require the recovered structure to PREDICT the HELD-OUT
//    fold it was not trained on, beating a MATCHED within-message shuffle null
//    (`fisher_yates` + `add_one_p_value`, identical pipeline/population). An
//    unconstrained fit that cannot predict held-out structure is coincidence.
// 2. THREAD-3 perfect-iso consistency. The implied model must be consistent with
//    `perfect_isomorphism`'s scan: no manufactured TRUE conflicts
//    (`robust_internal_violations == 0`), chaining ONLY within the safe isomorph
//    extents (never over-extending). Reuse the Thread-3 API; never re-derive.
// 3. (LAST, SPECULATIVE) cleartext plausibility — ONLY if (1) AND (2) pass. Score an
//    implied plaintext under the Finnish AND English models behind a matched null;
//    the symbol→letter mapping is a HYPOTHESIS, never recovered, never primary.
// =====================================================================

/// Reading-layer alphabet size of the eye reading layer (`|C|` upper bound), used
/// as the deck `state_size` proxy for the eye chain-link merge threshold.
pub const EYE_READING_ALPHABET_SIZE: usize = orders::READING_LAYER_ALPHABET_SIZE;

/// Minimum gap-pattern window the eye isomorph alignment scans (matches Thread 3's
/// `DEFAULT_MIN_WINDOW`, so the held-out chain links are read from the same
/// isomorph regime Thread 3 validated).
pub const EYE_ISOMORPH_MIN_WINDOW: usize = perfect_isomorphism::DEFAULT_MIN_WINDOW;

/// Maximum gap-pattern window the eye isomorph alignment scans (matches Thread 3's
/// `DEFAULT_MAX_WINDOW`).
pub const EYE_ISOMORPH_MAX_WINDOW: usize = perfect_isomorphism::DEFAULT_MAX_WINDOW;

/// Default deterministic seed for the eyes Step-3 matched within-message null.
pub const EYES_DEFAULT_SEED: u64 = 0x6579_6573_5f73_7470;

/// Default matched within-message shuffle-null trial count for the eyes Step-3 gate.
pub const EYES_DEFAULT_TRIALS: usize = 2_000;

/// Default beam-width LABEL recorded in the eyes candidate-record filename/header;
/// it does NOT affect the eyes held-out scoring (the eyes run performs no per-column
/// marginalization).
pub const EYES_DEFAULT_BEAM_WIDTH: usize = DEFAULT_BEAM_WIDTH;

/// Default directory under which the mandatory eyes candidate record is written.
pub const EYES_DEFAULT_CANDIDATES_DIR: &str = "research/gak-threads/candidates";

/// Configuration for the eyes Step-3 attack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EyesAttackConfig {
    /// Deterministic seed for the matched within-message shuffle null and the
    /// derived candidate-record label (NO wall-clock is ever read).
    pub seed: u64,
    /// Matched within-message shuffle-null trials.
    pub trials: usize,
    /// Disclosed beam-width label recorded in the candidate-record filename/header;
    /// does NOT affect the eyes held-out scoring (the eyes run performs no per-column
    /// marginalization).
    pub beam_width: usize,
    /// Directory under which the mandatory candidate record is written.
    pub candidates_dir: PathBuf,
}

impl Default for EyesAttackConfig {
    fn default() -> Self {
        Self {
            seed: EYES_DEFAULT_SEED,
            trials: EYES_DEFAULT_TRIALS,
            beam_width: EYES_DEFAULT_BEAM_WIDTH,
            candidates_dir: PathBuf::from(EYES_DEFAULT_CANDIDATES_DIR),
        }
    }
}

/// The held-out isomorph evaluation for ONE eye message, real vs matched null.
///
/// Mirrors the synthetic idea-3 held-out machinery but over the real eye isomorphs:
/// the per-message isomorph occurrences are split into a TRAIN fold (the candidate
/// chain links) and a HELD-OUT fold (the validation chain links); the recovered
/// structure (the admitted train edges) must predict the held-out fold. Real and
/// the matched within-message multiset shuffle run the IDENTICAL pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EyeMessageHeldOut {
    /// Message key (e.g. `east1`).
    pub message_key: &'static str,
    /// Reading-layer symbols in this message.
    pub length: usize,
    /// Distinct isomorph signature groups (≥2 occurrences) found in this message.
    pub isomorph_groups: usize,
    /// Aligned isomorph occurrence pairs that yielded chain links.
    pub aligned_pairs: usize,
    /// Distinct reading-layer symbols touched by any chain link (coverage).
    pub symbols_touched: usize,
    /// Fixed-context TRUE-conflict aborts (bad isomorph alignments) on the real
    /// stream — surfaced as a feature (`Chaining-Conflicts.md`).
    pub true_conflict_aborts: usize,
    /// Held-out chain links the uniquely-identified TRAIN context predicted
    /// correctly (real stream).
    pub real_held_out_hits: usize,
    /// Held-out chain links predicted incorrectly (real stream).
    pub real_held_out_misses: usize,
    /// Held-out chain links with no unique confident prediction (real stream).
    pub real_held_out_ambiguous: usize,
    /// The coverage-weighted excess-correctness score for this message (real
    /// stream) — the gate statistic, `(A-1)*hits - A*misses (ambiguous unpenalized)`.
    pub real_score: i64,
}

/// The Thread-3 perfect-isomorphism consistency verdict consulted at Step 3.
///
/// This is read straight from [`perfect_isomorphism::run_perfect_isomorphism`]
/// (the Thread-3 API is REUSED, never re-derived). A candidate may only be named
/// if Thread 3 reports zero robust internal violations (no manufactured TRUE
/// conflicts) and supplies the safe isomorph extents Gate-1 chaining is ENFORCED to
/// stay within (see `eyes_three_consultation`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThreeConsistency {
    /// Thread-3 robust strong-bar internal-violation count (must be `0` for a
    /// consistent model: a non-zero count is a manufactured TRUE conflict).
    pub robust_internal_violations: usize,
    /// Number of conservative safe isomorph extents Thread 3 exported. Gate-1
    /// chaining is ENFORCED to stay within the per-message spans these project to;
    /// an occurrence window is admitted only inside a safe span.
    pub safe_extents: usize,
    /// Whether Thread 3's own positive control fired (the scan is trustworthy).
    pub positive_control_fired: bool,
    /// Whether the candidate model is CONSISTENT with Thread 3: zero robust
    /// internal violations AND the positive control fired.
    pub consistent: bool,
}

/// The held-out positive control on a SYNTHETIC isomorph-rich eye-shaped fixture.
///
/// The held-out predictor must fire on KNOWN signal: a synthetic message built so a
/// FIXED global action recurs across isomorph groups must yield a real
/// coverage-weighted score that strictly beats its matched within-message shuffle
/// null (the shuffle destroys the reusable context classes). If it does not, the
/// held-out gate is not trustworthy and the run aborts
/// ([`GakAttackError::HeldOutPositiveControlFailed`]) — a methodology failure, never
/// an eye finding.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HeldOutPositiveControl {
    /// Real coverage-weighted held-out score on the synthetic fixture.
    pub real_score: i64,
    /// Worst-case (max) matched-null coverage-weighted score over the control
    /// shuffles (the value the real signal must strictly beat).
    pub null_score: i64,
    /// SCOREABLE held-out edges on the synthetic fixture (`hits + misses +
    /// ambiguous`). Used to size the control's OWN population material-effect bar so
    /// the validation ("the detector still clears its own bar") is checked on the
    /// control's population, not the eyes'.
    pub scoreable_edges: usize,
    /// Whether the predictor fired: the real signal strictly beats the worst-case
    /// matched null AND its real-vs-null excess clears the control's OWN
    /// population-relative material-effect bar — so the detector is validated on
    /// the same fair gate the eyes are judged against.
    pub fired: bool,
}

/// The SPECULATIVE cleartext-plausibility result (kill gate 3).
///
/// Present ONLY when a candidate survived BOTH structural gates (the expected case
/// is `None`). The symbol→letter mapping is a HYPOTHESIS, never recovered; this is
/// never primary evidence. Both Finnish and English are scored behind a matched
/// null, with Finnish weighted highly (Noita is a Finnish game). The implied
/// plaintext is logged VERBATIM to the candidate record for human review.
#[derive(Clone, Debug, PartialEq)]
pub struct SpeculativeCleartext {
    /// The implied plaintext under the HYPOTHESIZED symbol→letter mapping (logged
    /// verbatim — a HYPOTHESIS, never a decode).
    pub implied_plaintext: String,
    /// Finnish bigram mean log-likelihood of the implied plaintext.
    pub finnish_score: f64,
    /// English bigram mean log-likelihood of the implied plaintext.
    pub english_score: f64,
    /// Matched-null mean Finnish score over shuffled mappings.
    pub finnish_null_mean: f64,
    /// Matched-null mean English score over shuffled mappings.
    pub english_null_mean: f64,
    /// Whether the implied plaintext beats the matched mapping null in Finnish.
    pub beats_finnish_null: bool,
    /// Whether the implied plaintext beats the matched mapping null in English.
    pub beats_english_null: bool,
}

/// The held-out Gate-1 evaluation: per-message rows, aggregate score, matched-null
/// tail, and the population-relative material-effect verdict.
struct Gate1Evaluation {
    per_message: Vec<EyeMessageHeldOut>,
    real_held_out_hits_total: usize,
    real_held_out_misses_total: usize,
    real_held_out_ambiguous_total: usize,
    real_score: i64,
    /// SCOREABLE held-out edges on the real eyes (`hits + misses + ambiguous`) — the
    /// population whose own max-achievable score sizes the bar.
    scoreable_edges: usize,
    /// The eyes' MAX achievable coverage-weighted score (`scoreable_edges * (A-1)`):
    /// the bar is a fraction of THIS, so genuine eye signal could clear it.
    max_achievable_score: f64,
    null_at_least_real: usize,
    null_mean_score: f64,
    matched_null_p_value: f64,
    material_effect_threshold: f64,
    material_effect_met: bool,
    held_out_beats_null: bool,
}

/// Runs the eyes Gate-1 held-out evaluation: the embargoed-consensus coverage-
/// weighted score on the real per-message streams vs the matched within-message
/// shuffle null, plus the POPULATION-RELATIVE material-effect bar (statistical
/// significance is NECESSARY but NOT SUFFICIENT: the real-vs-null excess must
/// reach [`EYES_MATERIAL_EFFECT_FRACTION`] of the eyes' OWN max achievable score
/// `scoreable_edges * (A-1)`, a bar that scales to whatever population is under test
/// so a genuine eye signal COULD clear it, rather than an absolute value pinned to
/// the much larger synthetic positive control's population).
///
/// Gate-1 chaining is restricted to the Thread-3 safe extents via
/// `safe_spans_by_message`, applied identically to the real eyes and the matched
/// null so the null stays symmetric.
///
/// # Errors
/// Returns [`GakAttackError`] if a matched-null shuffle draw bound does not fit.
fn eyes_gate1_evaluation(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    config: &EyesAttackConfig,
    safe_spans_by_message: &[Vec<(usize, usize)>],
) -> Result<Gate1Evaluation, GakAttackError> {
    let per_message = eyes_per_message_held_out(keys, message_values, safe_spans_by_message);
    let real_held_out_hits_total: usize = per_message.iter().map(|m| m.real_held_out_hits).sum();
    let real_held_out_misses_total: usize =
        per_message.iter().map(|m| m.real_held_out_misses).sum();
    let real_held_out_ambiguous_total: usize =
        per_message.iter().map(|m| m.real_held_out_ambiguous).sum();
    let real_score = eyes_aggregate_score(
        message_values,
        AggregateSafeFilter::PerMessage(safe_spans_by_message),
    );

    let (null_at_least_real, null_mean_score) =
        eyes_matched_null_tail(message_values, config, safe_spans_by_message, real_score)?;
    let matched_null_p_value = add_one_p_value(null_at_least_real, config.trials);

    // A POPULATION-RELATIVE bar. The eyes' own scoreable held-out edges fix their
    // max achievable score `scoreable_edges * (A-1)`; the bar is a fraction of THAT,
    // so a genuine eye signal capturing >= EYES_MATERIAL_EFFECT_FRACTION of the signal
    // achievable on ITS OWN population clears it. This is fair (the bar is below the
    // eyes' max) and validated (the positive control clears its own population's bar).
    let scoreable_edges = real_held_out_hits_total
        .saturating_add(real_held_out_misses_total)
        .saturating_add(real_held_out_ambiguous_total);
    let max_achievable = max_achievable_score(scoreable_edges);
    let real_excess = real_score as f64 - null_mean_score;
    let material_effect_threshold = EYES_MATERIAL_EFFECT_FRACTION * max_achievable;
    let material_effect_met = max_achievable > 0.0 && real_excess >= material_effect_threshold;
    let held_out_beats_null = real_score > 0
        && real_score as f64 > null_mean_score
        && matched_null_p_value <= EYES_SIGNIFICANCE_ALPHA
        && material_effect_met;

    Ok(Gate1Evaluation {
        per_message,
        real_held_out_hits_total,
        real_held_out_misses_total,
        real_held_out_ambiguous_total,
        real_score,
        scoreable_edges,
        max_achievable_score: max_achievable,
        null_at_least_real,
        null_mean_score,
        matched_null_p_value,
        material_effect_threshold,
        material_effect_met,
        held_out_beats_null,
    })
}

/// Runs the eyes Step-3 attack on the verified eye corpus and writes the mandatory
/// candidate record.
///
/// The standing conclusion is the eye decode is BLOCKED on the unknown
/// symbol→meaning mapping. This run measures honestly whether that holds: it points
/// the matured chain-link attack at the real per-message eye streams, evaluates the
/// held-out isomorph gate against a matched within-message shuffle null, consults
/// Thread 3's perfect-isomorphism consistency, and ONLY if BOTH structural gates
/// pass runs the SPECULATIVE Finnish/English cleartext scoring. The expected
/// outcome is NO surviving candidate; the candidate record is written either way.
///
/// # Errors
/// Returns [`GakAttackError`] when the corpus cannot be read, when Thread 3's scan
/// fails, when the held-out positive control does not fire on known synthetic
/// signal, when a language model cannot be built, or when the candidate record
/// cannot be written.
pub fn run_gak_attack_eyes(config: EyesAttackConfig) -> Result<EyesAttackReport, GakAttackError> {
    // ZERO-TRIALS GUARD: the held-out gate's significance is the matched
    // within-message shuffle null, so it must have at least one draw — zero trials
    // would define the p-value and null mean over an empty sample (same discipline
    // as the other modules' ZeroTrials rejection). Reject up front, never a finding.
    if config.trials == 0 {
        return Err(GakAttackError::EyesZeroTrials);
    }

    // ENTRY PATH (exact): per-message streams, boundaries kept, accepted order.
    let grids = orders::corpus_grids()?;
    let keys: Vec<&'static str> = grids
        .iter()
        .map(crate::analysis::orders::GlyphGrid::message_key)
        .collect();
    let order = orders::accepted_honeycomb_order();
    let message_values = orders::read_corpus_message_values(&grids, order)?;

    let total_symbols: usize = message_values.iter().map(Vec::len).sum();
    let distinct_symbols: BTreeSet<u8> = message_values
        .iter()
        .flatten()
        .map(|value| value.get())
        .collect();
    let distinct_symbols = distinct_symbols.len();

    // GATE 1 PRELUDE: the held-out POSITIVE CONTROL must fire on KNOWN signal — now
    // including clearing the control's OWN population-relative material-effect bar,
    // so the bar is proven achievable by genuine signal before the eyes face it.
    let held_out_positive_control = eyes_held_out_positive_control(&config)?;
    if !held_out_positive_control.fired {
        return Err(GakAttackError::HeldOutPositiveControlFailed {
            real_score: held_out_positive_control.real_score,
            null_score: held_out_positive_control.null_score,
        });
    }

    // THREAD-3 CONSULTATION (REUSE the Thread-3 API), run ONCE up front: it yields
    // both the Gate-2 consistency verdict AND the per-message safe isomorph spans
    // Gate-1 chaining is ENFORCED to stay within. Run before Gate 1 so Gate 1 can
    // restrict chaining to those extents.
    let three = eyes_three_consultation(&keys)?;
    let three_consistency = three.verdict;
    let safe_spans_by_message = three.safe_spans_by_message;

    // GATE 1: per-message held-out isomorph recovery vs a MATCHED within-message
    // shuffle null, CHAINING RESTRICTED to the Thread-3 safe extents, plus the
    // population-relative material-effect bar (the leak-proof embargoed-consensus
    // statistic). Boundaries are kept.
    let gate1 = eyes_gate1_evaluation(&keys, &message_values, &config, &safe_spans_by_message)?;

    // GATE 3 + VERDICT + record/report assembly (factored out to keep this entry
    // point thin; the speculative Gate 3 stays gated behind both structural gates).
    finalize_eyes_run(EyesRunFinalize {
        config,
        order,
        message_values,
        total_symbols,
        distinct_symbols,
        gate1,
        three_consistency,
        held_out_positive_control,
    })
}

/// Inputs to [`finalize_eyes_run`]: the structural-gate outputs plus the run context
/// needed to assemble the candidate record and the [`EyesAttackReport`].
struct EyesRunFinalize {
    config: EyesAttackConfig,
    order: orders::ReadingOrder,
    message_values: Vec<Vec<TrigramValue>>,
    total_symbols: usize,
    distinct_symbols: usize,
    gate1: Gate1Evaluation,
    three_consistency: ThreeConsistency,
    held_out_positive_control: HeldOutPositiveControl,
}

/// Runs the SPECULATIVE Gate 3 (only if both structural gates passed), determines the
/// final verdict, writes the mandatory candidate record, and builds the report.
///
/// The verdict is unchanged: a candidate survives ONLY if Gate 1 (held-out beats the
/// matched null AND clears the population-relative material-effect bar) AND Gate 2
/// (Thread-3 consistency) both pass. The expected outcome is NO surviving candidate.
///
/// # Errors
/// Returns [`GakAttackError`] if the language models cannot be built (Gate 3 only) or
/// the candidate record cannot be written.
fn finalize_eyes_run(inputs: EyesRunFinalize) -> Result<EyesAttackReport, GakAttackError> {
    let EyesRunFinalize {
        config,
        order,
        message_values,
        total_symbols,
        distinct_symbols,
        gate1,
        three_consistency,
        held_out_positive_control,
    } = inputs;

    let candidate_survived = gate1.held_out_beats_null && three_consistency.consistent;
    let speculative_cleartext = if candidate_survived {
        Some(eyes_speculative_cleartext(&message_values, &config)?)
    } else {
        None
    };

    let order_name = order.name();
    let trials = config.trials;
    let record_path = config.candidates_dir.join(eyes_record_filename(&config));
    write_eyes_candidate_record(
        &record_path,
        &EyesRecordInputs {
            config: &config,
            order_name: &order_name,
            total_symbols,
            distinct_symbols,
            per_message: &gate1.per_message,
            real_held_out_hits_total: gate1.real_held_out_hits_total,
            real_held_out_misses_total: gate1.real_held_out_misses_total,
            real_held_out_ambiguous_total: gate1.real_held_out_ambiguous_total,
            real_score: gate1.real_score,
            scoreable_edges: gate1.scoreable_edges,
            max_achievable_score: gate1.max_achievable_score,
            null_mean_score: gate1.null_mean_score,
            material_effect_threshold: gate1.material_effect_threshold,
            material_effect_met: gate1.material_effect_met,
            matched_null_p_value: gate1.matched_null_p_value,
            null_at_least_real: gate1.null_at_least_real,
            held_out_beats_null: gate1.held_out_beats_null,
            held_out_positive_control,
            three_consistency,
            candidate_survived,
            speculative_cleartext: speculative_cleartext.as_ref(),
        },
    )?;

    Ok(EyesAttackReport {
        config,
        order_name,
        total_symbols,
        distinct_symbols,
        per_message: gate1.per_message,
        real_held_out_hits_total: gate1.real_held_out_hits_total,
        real_held_out_misses_total: gate1.real_held_out_misses_total,
        real_held_out_ambiguous_total: gate1.real_held_out_ambiguous_total,
        real_score: gate1.real_score,
        scoreable_edges: gate1.scoreable_edges,
        max_achievable_score: gate1.max_achievable_score,
        null_mean_score: gate1.null_mean_score,
        material_effect_threshold: gate1.material_effect_threshold,
        material_effect_met: gate1.material_effect_met,
        trials,
        null_at_least_real: gate1.null_at_least_real,
        matched_null_p_value: gate1.matched_null_p_value,
        held_out_beats_null: gate1.held_out_beats_null,
        held_out_positive_control,
        three_consistency,
        candidate_survived,
        speculative_cleartext,
        record_path,
    })
}

/// Significance threshold for the eyes Step-3 matched-null held-out tail. A real
/// coverage-weighted score must clear this add-one p-value (and beat the null mean)
/// to count as "beats null"; it is the same `0.05` convention used elsewhere.
const EYES_SIGNIFICANCE_ALPHA: f64 = 0.05;

/// POPULATION-RELATIVE MATERIAL-EFFECT fraction (effect size, not just p-value):
/// the real-vs-null-mean held-out excess must reach this FRACTION of
/// the population's OWN max achievable score (`scoreable_edges * (A-1)`) for a
/// candidate to pass Gate 1. Anchoring the bar to the SAME population under test (not
/// to the much larger synthetic positive control's population) makes it FAIR: a
/// genuine eye signal that captures >= 25% of the signal achievable on its own
/// held-out edges clears it, while a thin isomorph-richness leak (excess ~0) fails.
/// The detector is still VALIDATED because the positive control must clear ITS OWN
/// population's bar by the same rule. Set to one quarter of the achievable signal —
/// generous to a real recovery, fatal to a thin leak.
pub const EYES_MATERIAL_EFFECT_FRACTION: f64 = 0.25;

/// Trial count for the Thread-3 consistency consultation. The fields we read
/// (robust internal violations, safe extents, positive-control fire) are
/// trial-count-independent, so this is kept small for speed while still exercising
/// Thread 3's own null/positive-control machinery.
const EYES_THREE_CONSISTENCY_TRIALS: usize = 64;

mod controls;
mod heldout;
mod record;
mod report;
mod speculative;

pub use report::EyesAttackReport;
// Re-exported so the parent's `pub use eyes::*` keeps the prior
// `crate::attack::gak_attack::*` paths (the CLI and gak test suite reach these
// items through that glob). These are also used by this module's orchestration.
pub(crate) use heldout::{
    AggregateSafeFilter, eyes_aggregate_score, eyes_held_out_positive_control, max_achievable_score,
};
pub(crate) use record::EyesRecordInputs;
// Re-exported SOLELY so the gak test suite can reach the held-out scoring entry
// points and the record renderer through `crate::attack::gak_attack::*`; nothing
// outside the test target consumes these paths.
#[cfg(test)]
pub(crate) use heldout::{
    SafeWindowFilter, eyes_message_evidence, synthetic_isomorph_rich_eye_message,
};
#[cfg(test)]
pub(crate) use record::render_eyes_candidate_record;

// Internal wiring for the orchestration kept in this module.
use controls::eyes_three_consultation;
use heldout::{eyes_matched_null_tail, eyes_per_message_held_out};
use record::{eyes_record_filename, write_eyes_candidate_record};
use speculative::eyes_speculative_cleartext;
