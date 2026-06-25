//! Unit 2c — EYES STEP 3: the only unit that touches the real eye corpus.
//!
//! Points the matured attack at the verified embedded eye corpus and measures the
//! standing **BLOCKED** conclusion against matched within-message nulls, asserting
//! no decode. The eyes honesty caveats (mapping-is-HYPOTHESIS) live with this code.

use super::*;

// =====================================================================
// UNIT 2c — EYES STEP 3: point the matured attack at the REAL eye corpus.
//
// This is the ONLY unit that touches the real eyes, and the highest honesty-risk
// unit in the project. The CLAIM CEILING is absolute on every output:
//
//   The eyes are deterministic, engine-generated, strikingly structured data of
//   unknown meaning; unsolved; no primary developer source confirms recoverable
//   plaintext.
//
// Nothing this unit prints, writes, or returns may be stronger. The standing
// conclusion — the eye decode is BLOCKED on the unknown symbol→meaning mapping —
// does NOT change unless a candidate survives the held-out + Thread-3 gates below,
// and even then it is a HYPOTHESIS, never a decode. The EXPECTED, fully reportable
// outcome of this unit is NO surviving candidate: with a near-`S_83` group and very
// little text (`Alphabet-Chaining.md`: "it might actually be unrealistic to expect
// chaining to ever work for the eyes"), a clean honest negative is a SUCCESS here.
//
// ## What is recovered vs what is NOT (the honest reality, encoded)
//
// The attack recovers STRUCTURE (visible-coset actions / chain-link constraints),
// NOT cleartext. Even a full recovery of the eye group structure yields abstract
// plaintext-letter INDICES, not readable text, because mapping symbols→letters
// needs an external ANCHOR (exactly the standing blocker). So a "candidate
// cleartext" can ONLY arise by ADDITIONALLY hypothesizing a symbol→letter mapping,
// which the claim ceiling forbids inventing as a finding. The cleartext path is
// therefore SPECULATIVE, gated, Finnish-weighted, and never primary.
//
// ## Entry path (EXACT — never deviate)
//
//   orders::corpus_grids() → orders::accepted_honeycomb_order()
//   → orders::read_corpus_message_values(&grids, order)
//
// PER-MESSAGE streams, message boundaries KEPT; NEVER concatenate across messages;
// NEVER re-select a reading order. (notes/reading-streams.md, notes/api-analysis.md)
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
/// stay within (F2 — see `eyes_three_consultation`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThreeConsistency {
    /// Thread-3 robust strong-bar internal-violation count (must be `0` for a
    /// consistent model: a non-zero count is a manufactured TRUE conflict).
    pub robust_internal_violations: usize,
    /// Number of conservative safe isomorph extents Thread 3 exported. Gate-1
    /// chaining is ENFORCED to stay within the per-message spans these project to
    /// (F2); an occurrence window is admitted only inside a safe span.
    pub safe_extents: usize,
    /// Whether Thread 3's own positive control fired (the scan is trustworthy).
    pub positive_control_fired: bool,
    /// Whether the candidate model is CONSISTENT with Thread 3: zero robust
    /// internal violations AND the positive control fired.
    pub consistent: bool,
}

/// The complete eyes Step-3 report (the standing "decode blocked" conclusion,
/// measured honestly).
#[derive(Clone, Debug, PartialEq)]
pub struct EyesAttackReport {
    /// Configuration used for the run (carries the seed-derived record label).
    pub config: EyesAttackConfig,
    /// The reading order used (pinned: the accepted honeycomb order, stable name
    /// `standard36-u012-d012`).
    pub order_name: String,
    /// Total reading-layer symbols across all nine messages (must be `1036`).
    pub total_symbols: usize,
    /// Distinct reading-layer symbols across all messages (must be `83`).
    pub distinct_symbols: usize,
    /// Per-message held-out evaluations (real vs matched null), boundaries kept.
    pub per_message: Vec<EyeMessageHeldOut>,
    /// Aggregate real held-out hits across all messages (correct unique predictions).
    pub real_held_out_hits_total: usize,
    /// Aggregate real held-out misses across all messages (wrong predictions).
    pub real_held_out_misses_total: usize,
    /// Aggregate real held-out ambiguous links (no unique confident prediction).
    pub real_held_out_ambiguous_total: usize,
    /// The aggregate real coverage-weighted excess-correctness SCORE (the gate
    /// statistic, summed over messages).
    pub real_score: i64,
    /// SCOREABLE held-out edges on the real eyes (`hits + misses + ambiguous`) — the
    /// population whose own max-achievable score sizes the F1 material-effect bar.
    pub scoreable_edges: usize,
    /// The eyes' MAX achievable coverage-weighted score (`scoreable_edges * (A-1)`,
    /// i.e. every scoreable edge a confident HIT). The material-effect bar is a
    /// fraction of THIS, so a genuine eye signal COULD clear the bar (F1: fair gate).
    pub max_achievable_score: f64,
    /// The mean matched within-message shuffle-null coverage-weighted score.
    pub null_mean_score: f64,
    /// The POPULATION-RELATIVE MATERIAL-EFFECT threshold the real excess had to clear
    /// (`EYES_MATERIAL_EFFECT_FRACTION` of the eyes' own [`Self::max_achievable_score`])
    /// — the effect-size bar that makes p-value significance necessary but not
    /// sufficient, fair to the population under test (F1).
    pub material_effect_threshold: f64,
    /// Whether the real-vs-null-mean excess cleared the population-relative
    /// material-effect bar. Expected `false` for the eyes (their real-vs-null
    /// excess does not clear the bar).
    pub material_effect_met: bool,
    /// Matched within-message shuffle-null trials run.
    pub trials: usize,
    /// Number of null trials whose aggregate coverage-weighted score was at least
    /// the real aggregate score (the matched-null upper tail).
    pub null_at_least_real: usize,
    /// Add-one matched-null p-value for the coverage-weighted score.
    pub matched_null_p_value: f64,
    /// Whether the real aggregate coverage-weighted score STRICTLY beats the matched
    /// within-message shuffle null (kill gate 1). Expected `false` for the eyes.
    pub held_out_beats_null: bool,
    /// The held-out positive control on the synthetic isomorph-rich eye-shaped
    /// fixture (the predictor must fire on KNOWN signal).
    pub held_out_positive_control: HeldOutPositiveControl,
    /// The Thread-3 perfect-isomorphism consistency verdict (kill gate 2).
    pub three_consistency: ThreeConsistency,
    /// THE VERDICT: did ANY candidate survive BOTH structural gates? Expected NO.
    /// A `true` here would be flagged loudly and logged as a HYPOTHESIS, never a
    /// decode.
    pub candidate_survived: bool,
    /// The SPECULATIVE cleartext-plausibility result, present ONLY if both
    /// structural gates passed; `None` is the expected case (gate 3 not run).
    pub speculative_cleartext: Option<SpeculativeCleartext>,
    /// Absolute path of the candidate record this run wrote.
    pub record_path: PathBuf,
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
    /// F1's validation ("the detector still clears its own bar") is checked on the
    /// control's population, not the eyes'.
    pub scoreable_edges: usize,
    /// Whether the predictor fired: the real signal strictly beats the worst-case
    /// matched null AND its real-vs-null excess clears the control's OWN
    /// population-relative material-effect bar (F1) — so the detector is validated on
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
    /// population whose own max-achievable score sizes the F1 bar.
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
/// significance is NECESSARY but NOT SUFFICIENT — F1: the real-vs-null excess must
/// reach [`EYES_MATERIAL_EFFECT_FRACTION`] of the eyes' OWN max achievable score
/// `scoreable_edges * (A-1)`, a bar that scales to whatever population is under test
/// so a genuine eye signal COULD clear it, rather than an absolute value pinned to
/// the much larger synthetic positive control's population).
///
/// Gate-1 chaining is restricted to the Thread-3 safe extents via
/// `safe_spans_by_message` (F2), applied identically to the real eyes and the matched
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

    // F1: a POPULATION-RELATIVE bar. The eyes' own scoreable held-out edges fix their
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
        .map(crate::orders::GlyphGrid::message_key)
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
    // including clearing the control's OWN population-relative material-effect bar
    // (F1), so the bar is proven achievable by genuine signal before the eyes face it.
    let held_out_positive_control = eyes_held_out_positive_control(&config)?;
    if !held_out_positive_control.fired {
        return Err(GakAttackError::HeldOutPositiveControlFailed {
            real_score: held_out_positive_control.real_score,
            null_score: held_out_positive_control.null_score,
        });
    }

    // THREAD-3 CONSULTATION (REUSE the Thread-3 API), run ONCE up front: it yields
    // both the Gate-2 consistency verdict AND the per-message safe isomorph spans
    // Gate-1 chaining is ENFORCED to stay within (F2). Run before Gate 1 so Gate 1 can
    // restrict chaining to those extents.
    let three = eyes_three_consultation(&keys)?;
    let three_consistency = three.verdict;
    let safe_spans_by_message = three.safe_spans_by_message;

    // GATE 1: per-message held-out isomorph recovery vs a MATCHED within-message
    // shuffle null, CHAINING RESTRICTED to the Thread-3 safe extents (F2), plus the
    // population-relative material-effect bar (the leak-proof, codex-validated
    // embargoed-consensus statistic). Boundaries are kept.
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

/// POPULATION-RELATIVE MATERIAL-EFFECT fraction (codex's "effect size, not just
/// p-value"; F1): the real-vs-null-mean held-out excess must reach this FRACTION of
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

/// Builds the per-message held-out isomorph evaluation for the REAL eye streams.
///
/// For each message (boundaries kept, never concatenated) this aligns the message's
/// isomorph occurrences by [`PatternSignature`] over the Thread-3 window range,
/// splits whole signature groups deterministically into TRAIN and HELD-OUT folds,
/// builds context-colored partial actions from each occurrence pair with the SHARED
/// [`chain_links_for_pair`] primitive (load-bearing — never a second graph), and
/// scores the held-out fold by the EMBARGOED-CONSENSUS statistic
/// ([`EyeMessageEvidence::held_out_score`]): a held-out edge scores only when `>= 2`
/// train contexts from DISTINCT signature groups, physically embargoed from the
/// held-out context, AGREE on it. The authoritative null significance is the full
/// trial tail in [`eyes_matched_null_tail`].
///
/// `safe_spans_by_message` (F2) supplies, in the SAME order as `keys`, the Thread-3
/// safe spans each message's Gate-1 chaining is restricted to. A message without
/// safe spans yields no admitted windows (and therefore no scored edges).
fn eyes_per_message_held_out(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    safe_spans_by_message: &[Vec<(usize, usize)>],
) -> Vec<EyeMessageHeldOut> {
    let mut rows = Vec::with_capacity(message_values.len());
    for (index, (key, values)) in keys.iter().copied().zip(message_values).enumerate() {
        let safe_filter = safe_spans_by_message
            .get(index)
            .map_or(SafeWindowFilter::restrict(&[]), |spans| {
                SafeWindowFilter::restrict(spans.as_slice())
            });
        let evidence = eyes_message_evidence(values, safe_filter);
        // Real held-out scoring: the recovered TRAIN context-action LIBRARY predicts
        // the held-out fold via the EMBARGOED-CONSENSUS coverage-weighted statistic
        // (only genuinely transferable cross-group structure scores).
        let real_score = evidence.held_out_score();
        rows.push(EyeMessageHeldOut {
            message_key: key,
            length: values.len(),
            isomorph_groups: evidence.isomorph_groups,
            aligned_pairs: evidence.aligned_pairs,
            symbols_touched: evidence.symbols_touched,
            true_conflict_aborts: evidence.true_conflict_aborts,
            real_held_out_hits: real_score.hits,
            real_held_out_misses: real_score.misses,
            real_held_out_ambiguous: real_score.ambiguous,
            real_score: real_score.coverage_weighted(),
        });
    }
    rows
}

/// Provenance of one context action: which isomorph signature group it came from and
/// the physical spans of its two aligned occurrences, used to enforce the positional
/// embargo (no train context may predict a held-out context it physically overlaps or
/// shares a signature group with — the nested/overlapping-window leak guard).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ContextProvenance {
    /// Stable id of the isomorph signature group this context belongs to.
    signature_id: u64,
    /// `[start, end)` of the upper occurrence in the message.
    upper: (usize, usize),
    /// `[start, end)` of the lower occurrence in the message.
    lower: (usize, usize),
}

impl ContextProvenance {
    /// Whether this context physically overlaps (or is immediately adjacent to)
    /// `other` on either occurrence span — the embargo predicate.
    fn touches(self, other: ContextProvenance) -> bool {
        spans_touch(self.upper, other.upper)
            || spans_touch(self.upper, other.lower)
            || spans_touch(self.lower, other.upper)
            || spans_touch(self.lower, other.lower)
    }
}

/// Whether two half-open spans overlap or are immediately adjacent (a 1-symbol gap
/// still counts as touching, to be conservative about leakage).
fn spans_touch(a: (usize, usize), b: (usize, usize)) -> bool {
    let (a_start, a_end) = a;
    let (b_start, b_end) = b;
    a_start <= b_end.saturating_add(1) && b_start <= a_end.saturating_add(1)
}

/// Restricts Gate-1 chaining to the Thread-3 SAFE ISOMORPH EXTENTS for one message
/// (F2 — ENFORCED, not just claimed). Thread 3 exports conservative per-message safe
/// spans where a cross-message aligned isomorph extends without over-reaching; Gate 1
/// admits an isomorph occurrence window only when its `[start, end)` lies ENTIRELY
/// within one of those safe spans for this message, so chaining never over-extends
/// past a Thread-3 break.
///
/// `spans == None` means NO restriction: used ONLY for the synthetic positive control
/// fixture, which is not a corpus message and has no Thread-3 extent (so the detector
/// is validated on its full known signal). For the real eyes, `spans` is always the
/// (possibly empty) Thread-3 safe-span list for that message — an empty list means
/// Thread 3 found no safe extent there, so NO window in that message is admitted.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SafeWindowFilter<'a> {
    /// `Some(spans)` restricts to those half-open safe spans; `None` admits all.
    spans: Option<&'a [(usize, usize)]>,
}

impl<'a> SafeWindowFilter<'a> {
    /// The unrestricted filter (synthetic positive control only — admits everything).
    pub(crate) const fn unrestricted() -> Self {
        Self { spans: None }
    }

    /// Restricts to the given Thread-3 safe spans for one real eye message.
    const fn restrict(spans: &'a [(usize, usize)]) -> Self {
        Self { spans: Some(spans) }
    }

    /// Whether a window `[start, end)` is admissible: always when unrestricted, else
    /// only when fully contained in at least one Thread-3 safe span.
    fn admits(self, window: (usize, usize)) -> bool {
        match self.spans {
            None => true,
            Some(spans) => spans.iter().any(|&(s, e)| s <= window.0 && window.1 <= e),
        }
    }
}

/// One CONTEXT-COLORED partial action: the injective `from -> to` map of ONE aligned
/// isomorph occurrence pair (`Graph-Chaining.md`: GAK chaining is a Schreier coset
/// graph of context-colored partial permutations, NOT one global symbol map). TRUE
/// conflicts (two arrows out of / into one symbol under this one context) are
/// rejected at construction, so a context action is always a partial bijection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct EyeContextAction {
    /// Forward partial bijection `from -> to` for this single context.
    pub(crate) forward: BTreeMap<u8, u8>,
    /// Provenance for the positional embargo and same-group rejection.
    provenance: ContextProvenance,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct EyeMessageEvidence {
    /// TRAIN-fold context actions (one per train isomorph occurrence pair). The
    /// recovered "model" is this LIBRARY of context-colored partial permutations,
    /// NOT a collapsed global map — the wiki-faithful object.
    pub(crate) train_contexts: Vec<EyeContextAction>,
    /// HELD-OUT-fold context actions (from DISJOINT signature groups). Validation
    /// only; never contributes a train context.
    pub(crate) held_out_contexts: Vec<EyeContextAction>,
    /// Distinct isomorph signature groups (≥2 occurrences).
    isomorph_groups: usize,
    /// Aligned isomorph occurrence pairs that yielded chain links.
    pub(crate) aligned_pairs: usize,
    /// Distinct reading-layer symbols touched by any chain link (coverage).
    pub(crate) symbols_touched: usize,
    /// Fixed-context TRUE-conflict aborts (bad isomorph alignments).
    true_conflict_aborts: usize,
}

/// Anchor links a held-out context exposes (non-scored) to IDENTIFY a matching train
/// action class. The remaining links are scored. `Chaining-Conflicts.md`: near
/// `S_n/S_{n-1}` edge overlap is unsafe, so identification requires the anchor to
/// agree on enough links with a UNIQUE compatible train context.
const HELD_OUT_ANCHOR_LINKS: usize = 3;

/// Minimum exact shared anchor edges a train context must match to be a candidate
/// identification for a held-out context. A single shared edge is never enough
/// (`Chaining-Conflicts.md`: edge overlap does not prove context equality).
const MIN_ANCHOR_AGREEMENT: usize = 2;

/// Minimum number of held-out SCORED links (predicted decisions) required before the
/// coverage-weighted score is meaningful; below this the model committed too little
/// to distinguish from chance and the message contributes nothing.
const MIN_HELD_OUT_COVERAGE: usize = 4;

impl EyeContextAction {
    /// Inserts one observed `from -> to` edge, returning `false` (a TRUE conflict) if
    /// it violates the partial-bijection law (two arrows out of / into one symbol).
    fn insert(&mut self, from: u8, to: u8) -> bool {
        match self.forward.get(&from) {
            Some(existing) if *existing != to => return false,
            Some(_) => return true,
            None => {}
        }
        if self.forward.iter().any(|(k, v)| *v == to && *k != from) {
            return false;
        }
        let _old = self.forward.insert(from, to);
        true
    }

    /// Number of edges where this action and `other` agree exactly on a shared
    /// source (the exact shared-edge support used for identification).
    fn shared_agreement(&self, other: &Self) -> usize {
        self.forward
            .iter()
            .filter(|(from, to)| other.forward.get(*from) == Some(*to))
            .count()
    }

    /// Whether this action CONTRADICTS `other` on any shared source (a `from` both
    /// map, to different `to`s) — the chaining incompatibility test.
    fn contradicts(&self, other: &Self) -> bool {
        self.forward.iter().any(|(from, to)| {
            other
                .forward
                .get(from)
                .is_some_and(|other_to| other_to != to)
        })
    }
}

/// EMBARGOED-CONSENSUS coverage-weighted held-out score for one message.
///
/// For each HELD-OUT context, an anchor subset of its links (the first
/// [`HELD_OUT_ANCHOR_LINKS`]) selects the EMBARGOED compatible TRAIN contexts (a
/// DIFFERENT signature group, NO physical span overlap/adjacency, agreeing on at
/// least [`MIN_ANCHOR_AGREEMENT`] anchor edges, never contradicting). A non-anchor
/// held-out edge scores only when at least [`MIN_INDEPENDENT_PROOFS`] of those train
/// contexts FROM DISTINCT SIGNATURE GROUPS AGREE on its image: a correct image is a
/// HIT, a wrong agreed image a MISS, and anything else (no consensus, too few
/// independent groups, disagreement) is AMBIGUOUS (no prediction). The score is the
/// coverage-weighted excess correctness `(A-1)*hits - A*misses (ambiguous
/// unpenalized)` with `A = 83`, so only genuinely TRANSFERABLE cross-group structure
/// scores — exactly what a within-message shuffle (no transferable structure detected
/// by this gate) cannot produce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct HeldOutScore {
    /// Held-out links predicted correctly by the embargoed-consensus predictor.
    hits: usize,
    /// Held-out links predicted incorrectly.
    misses: usize,
    /// Held-out links with no unique confident prediction (ambiguous / uncovered).
    ambiguous: usize,
}

impl HeldOutScore {
    /// The coverage-weighted excess-correctness scalar, `A = 83`.
    ///
    /// `score = (A-1)*hits - A*misses`. A HIT is a CONFIDENT, CORRECT, UNIQUELY
    /// identified held-out prediction, worth `A-1` because under random guessing the
    /// chance of hitting the right one of `A` symbols is only `1/A`; a MISS is a
    /// CONFIDENT WRONG prediction, penalized slightly harder (`A`) so a model that
    /// commits noisily nets negative. AMBIGUOUS links (no unique identification — "I
    /// don't know") are NOT penalized: ambiguity is the honest near-`S_83` outcome,
    /// not a false claim, and a within-message shuffle produces mostly ambiguity. So
    /// genuine reusable context structure (many confident correct, few wrong) scores
    /// high; a shuffle (few confident, mostly ambiguous) scores near zero.
    ///
    /// COVERAGE CLAMP (an explicit extra gate, applied per message BEFORE the
    /// `(A-1)*hits - A*misses` statistic): below [`MIN_HELD_OUT_COVERAGE`]
    /// confident decisions (`hits + misses`) the message committed too little to be
    /// meaningful, so its coverage-weighted score is clamped to `0`. This clamp is
    /// part of the scored statistic and is documented as such in the candidate
    /// record and the CLI report; it is symmetric (applied identically to the real
    /// eyes and to every matched-null shuffle), so it cannot manufacture a
    /// real-vs-null gap.
    fn coverage_weighted(self) -> i64 {
        let decisions = self.hits.saturating_add(self.misses);
        if decisions < MIN_HELD_OUT_COVERAGE {
            return 0;
        }
        let alphabet = i64::try_from(EYE_READING_ALPHABET_SIZE).unwrap_or(i64::MAX);
        let hits = i64::try_from(self.hits).unwrap_or(i64::MAX);
        let misses = i64::try_from(self.misses).unwrap_or(i64::MAX);
        (alphabet.saturating_sub(1)).saturating_mul(hits) - alphabet.saturating_mul(misses)
    }

    /// SCOREABLE held-out edges = `hits + misses + ambiguous`: every held-out edge
    /// that entered the embargoed-consensus predictor for this population. Used to
    /// size the population-relative material-effect bar in F1: the MAX achievable
    /// coverage-weighted score on a population is `scoreable * (A-1)` (every edge a
    /// HIT), so the bar can be a fraction of THAT, fair to whatever population is
    /// under test (the eyes, or the much larger synthetic positive control).
    fn scoreable_edges(self) -> usize {
        self.hits
            .saturating_add(self.misses)
            .saturating_add(self.ambiguous)
    }

    /// Accumulates another message's held-out counts into this aggregate.
    fn merge(&mut self, other: HeldOutScore) {
        self.hits = self.hits.saturating_add(other.hits);
        self.misses = self.misses.saturating_add(other.misses);
        self.ambiguous = self.ambiguous.saturating_add(other.ambiguous);
    }
}

/// Maximum coverage-weighted score achievable on a population with `scoreable_edges`
/// scoreable held-out edges: every edge a confident HIT, worth `A-1` each. This is
/// the population's own ceiling, so a fraction of it is a FAIR material-effect bar
/// for that population (F1) — unlike an absolute bar pinned to one population's size.
pub(crate) fn max_achievable_score(scoreable_edges: usize) -> f64 {
    let alphabet_minus_one = EYE_READING_ALPHABET_SIZE.saturating_sub(1);
    let max_edges =
        u64::try_from(scoreable_edges.saturating_mul(alphabet_minus_one)).unwrap_or(u64::MAX);
    // `as f64` on a u64 is the intended (lossy-at-extremes) conversion; the eyes'
    // and control's populations are far below the f64-exact integer range.
    max_edges as f64
}

impl EyeMessageEvidence {
    /// Scores the held-out fold against the recovered TRAIN context-action library
    /// using anchor identification + coverage-weighted excess correctness.
    fn held_out_score(&self) -> HeldOutScore {
        let mut score = HeldOutScore::default();
        for held in &self.held_out_contexts {
            self.score_one_held_out_context(held, &mut score);
        }
        score
    }

    /// Scores a held-out context with the EMBARGOED-CONSENSUS predictor.
    ///
    /// A held-out context's anchor links identify the compatible TRAIN contexts, but —
    /// crucially — only TRAIN contexts that are PROVENANCE-EMBARGOED from the held-out
    /// one: from a DIFFERENT signature group AND with no physically overlapping or
    /// adjacent occurrence span ([`ContextProvenance::touches`]). This is the leak fix:
    /// the false positive came from nested/overlapping windows (the same isomorph at
    /// length 8 vs 9, or a directly-adjacent occurrence) trivially reproducing the
    /// held-out edges — exactly the local low-entropy agreement a within-message
    /// shuffle also manufactures. Embargoing physically-overlapping and same-group
    /// train contexts forces the prediction to come from a DISTINCT, NON-ADJACENT part
    /// of the corpus, so only genuinely TRANSFERABLE structure can score. A non-anchor
    /// held-out edge scores only when at least [`MIN_INDEPENDENT_PROOFS`] embargoed
    /// train contexts (from DISTINCT signature groups) cover its source and ALL agree
    /// on the image. The `pi^k` positive control (a real recurring action) passes; the
    /// near-`S_83` eyes (no transferable structure DETECTED BY THIS GATE) do not.
    fn score_one_held_out_context(&self, held: &EyeContextAction, score: &mut HeldOutScore) {
        // Anchor = the first HELD_OUT_ANCHOR_LINKS edges (deterministic, by source).
        let mut anchor = EyeContextAction::default();
        let mut scored: Vec<(u8, u8)> = Vec::new();
        for (index, (from, to)) in held.forward.iter().enumerate() {
            if index < HELD_OUT_ANCHOR_LINKS {
                let _ok = anchor.insert(*from, *to);
            } else {
                scored.push((*from, *to));
            }
        }
        if scored.is_empty() || anchor.forward.len() < MIN_ANCHOR_AGREEMENT {
            return;
        }

        // Compatible train contexts, EMBARGOED: a different signature group AND no
        // physical span overlap/adjacency with the held-out context, agreeing on
        // >= MIN_ANCHOR_AGREEMENT anchor edges and never contradicting the anchor.
        let compatible: Vec<&EyeContextAction> = self
            .train_contexts
            .iter()
            .filter(|train| {
                train.provenance.signature_id != held.provenance.signature_id
                    && !train.provenance.touches(held.provenance)
                    && train.shared_agreement(&anchor) >= MIN_ANCHOR_AGREEMENT
                    && !train.contradicts(&anchor)
            })
            .collect();
        if compatible.is_empty() {
            score.ambiguous = score.ambiguous.saturating_add(scored.len());
            return;
        }

        for (from, to) in scored {
            match predict_by_embargoed_consensus(&compatible, from) {
                Prediction::Confident(image) if image == to => {
                    score.hits = score.hits.saturating_add(1);
                }
                Prediction::Confident(_) => score.misses = score.misses.saturating_add(1),
                Prediction::None => score.ambiguous = score.ambiguous.saturating_add(1),
            }
        }
    }
}

/// Minimum number of DISTINCT-signature-group embargoed train contexts that must
/// cover a held-out source and agree on its image before it scores. Two independent
/// contexts agreeing is strong evidence of transferable structure; a single one could
/// be coincidence.
const MIN_INDEPENDENT_PROOFS: usize = 2;

/// A held-out-source prediction outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prediction {
    /// At least [`MIN_INDEPENDENT_PROOFS`] embargoed train contexts from DISTINCT
    /// signature groups agree on this image.
    Confident(u8),
    /// No confident prediction (too few independent contexts, or they disagree).
    None,
}

/// Predicts a held-out source from the EMBARGOED compatible train contexts: returns
/// [`Prediction::Confident`] only when at least [`MIN_INDEPENDENT_PROOFS`] contexts
/// from DISTINCT signature groups cover the source and ALL agree on the image (any
/// disagreement among the embargoed contexts ⇒ [`Prediction::None`]). Requiring the
/// agreement across DISTINCT signature groups (not just distinct contexts) is what
/// makes the prediction reflect transferable structure rather than the recurrence of a
/// single local isomorph.
fn predict_by_embargoed_consensus(compatible: &[&EyeContextAction], from: u8) -> Prediction {
    let mut image: Option<u8> = None;
    let mut groups: BTreeSet<u64> = BTreeSet::new();
    for train in compatible {
        if let Some(&predicted) = train.forward.get(&from) {
            match image {
                Some(existing) if existing != predicted => return Prediction::None,
                _ => image = Some(predicted),
            }
            let _new = groups.insert(train.provenance.signature_id);
        }
    }
    match image {
        Some(value) if groups.len() >= MIN_INDEPENDENT_PROOFS => Prediction::Confident(value),
        _ => Prediction::None,
    }
}

/// Distills the TRAIN/HELD-OUT chain-link evidence from one eye message.
///
/// Isomorph occurrences are found by grouping every window (over the Thread-3
/// window range) by its [`PatternSignature`]; each signature group with ≥2
/// repeat-bearing occurrences is an isomorph (one distinct context family). The
/// SIGNATURE GROUPS are split deterministically (by a stable hash of the rendered
/// signature) into TRAIN and HELD-OUT — so train and held-out are DISJOINT
/// contexts, the strict out-of-sample regime. Within a TRAIN group, ordered
/// occurrence pairs become fixed contexts whose chain links come straight from
/// [`chain_links_for_pair`]; a non-functional fixed-context action (two arrows out
/// of / into one symbol under ONE alignment) is a TRUE conflict — a bad isomorph
/// alignment — dropped and counted, never a discovery. Train edges feed the
/// recovered model's `from -> {to}` image sets; HELD-OUT group chain links are the
/// validation set.
///
/// `safe_filter` (F2) restricts which isomorph occurrence windows are admitted: a
/// window is only used when [`SafeWindowFilter::admits`] accepts its `[start, end)`,
/// so on the real eyes chaining stays WITHIN Thread-3's safe isomorph extents and
/// never over-extends. The synthetic positive control passes the unrestricted filter.
/// The restriction is positional, so the matched within-message shuffle null (which
/// preserves positions) sees the identical admissibility — the null stays symmetric.
pub(crate) fn eyes_message_evidence(
    values: &[TrigramValue],
    safe_filter: SafeWindowFilter<'_>,
) -> EyeMessageEvidence {
    let mut evidence = EyeMessageEvidence::default();
    let mut touched: BTreeSet<u8> = BTreeSet::new();
    let mut context_index: u32 = 0;

    for window_len in EYE_ISOMORPH_MIN_WINDOW..=EYE_ISOMORPH_MAX_WINDOW {
        if values.len() < window_len {
            continue;
        }
        let mut by_signature: BTreeMap<PatternSignature, Vec<usize>> = BTreeMap::new();
        for (start, window) in values.windows(window_len).enumerate() {
            // F2: admit a window only when it lies within a Thread-3 safe extent (the
            // real eyes); the synthetic control's unrestricted filter admits every
            // window. Applied BEFORE signature grouping so chaining never sees an
            // over-extended occurrence.
            if !safe_filter.admits((start, start.saturating_add(window_len))) {
                continue;
            }
            let signature = PatternSignature::from_window(window);
            if signature.has_repeated_symbol() {
                by_signature.entry(signature).or_default().push(start);
            }
        }
        for (signature, starts) in &by_signature {
            // Spacing-filter coincidental overlaps (same discipline as the deck
            // substrate): genuine isomorph occurrences are ≥window apart.
            let filtered = spacing_filter(starts, window_len);
            if filtered.len() < 2 {
                continue;
            }
            evidence.isomorph_groups = evidence.isomorph_groups.saturating_add(1);
            // WHOLE-GROUP fold assignment (strict, out-of-sample): the entire
            // signature group is TRAIN or HELD-OUT, so train and held-out are
            // disjoint context families. The split is a stable hash of the rendered
            // signature (reproducible, no clock, balanced across the corpus).
            let signature_id = signature_fold_hash(signature, window_len);
            let is_held_out = HELD_OUT_STRIDE != 0
                && usize::try_from(signature_id)
                    .unwrap_or(0)
                    .is_multiple_of(HELD_OUT_STRIDE);
            for (left_index, &upper_start) in filtered.iter().enumerate() {
                for &lower_start in filtered.iter().skip(left_index.saturating_add(1)) {
                    let (Some(upper_window), Some(lower_window)) = (
                        values.get(upper_start..upper_start.saturating_add(window_len)),
                        values.get(lower_start..lower_start.saturating_add(window_len)),
                    ) else {
                        continue;
                    };
                    let upper = AlignedOccurrence {
                        message: 0,
                        window: upper_window,
                        core_len: window_len,
                    };
                    let lower = AlignedOccurrence {
                        message: 0,
                        window: lower_window,
                        core_len: window_len,
                    };
                    let context = ContextId::new(context_index);
                    context_index = context_index.saturating_add(1);
                    let Ok(links) = chain_links_for_pair(context, &upper, &lower) else {
                        continue;
                    };
                    // Build ONE context-colored partial action from this occurrence
                    // pair (Graph-Chaining.md). A fixed-context TRUE conflict (two
                    // arrows out of / into one symbol under ONE alignment) is a bad
                    // isomorph alignment (Chaining-Conflicts.md): dropped, counted,
                    // never a discovery.
                    let mut action = EyeContextAction {
                        forward: BTreeMap::new(),
                        provenance: ContextProvenance {
                            signature_id,
                            upper: (upper_start, upper_start.saturating_add(window_len)),
                            lower: (lower_start, lower_start.saturating_add(window_len)),
                        },
                    };
                    let mut conflicted = false;
                    for link in &links {
                        let _ins = touched.insert(link.from.get());
                        let _ins = touched.insert(link.to.get());
                        if !action.insert(link.from.get(), link.to.get()) {
                            conflicted = true;
                            break;
                        }
                    }
                    if conflicted {
                        evidence.true_conflict_aborts =
                            evidence.true_conflict_aborts.saturating_add(1);
                        continue;
                    }
                    evidence.aligned_pairs = evidence.aligned_pairs.saturating_add(1);
                    if is_held_out {
                        evidence.held_out_contexts.push(action);
                    } else {
                        evidence.train_contexts.push(action);
                    }
                }
            }
        }
    }
    evidence.symbols_touched = touched.len();
    evidence
}

/// A stable, clock-free fold hash for a signature group (the rendered equality
/// pattern + window length). Used to assign WHOLE isomorph groups to the TRAIN or
/// HELD-OUT fold reproducibly and roughly evenly.
fn signature_fold_hash(signature: &PatternSignature, window_len: usize) -> u64 {
    let mut hash: u64 = 0x9e37_79b9_7f4a_7c15 ^ window_len as u64;
    for &value in signature.values() {
        hash = hash
            .wrapping_mul(0x0100_0000_01b3)
            .wrapping_add(value as u64 + 1);
    }
    stateless_splitmix(hash)
}

/// The safe-span restriction for one population's aggregate held-out scoring.
///
/// `PerMessage(spans)` (the real eyes) applies the Thread-3 safe filter to each
/// message by index; `Unrestricted` (the synthetic positive control, a single
/// non-corpus fixture) admits every window so the detector is validated on its full
/// known signal.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AggregateSafeFilter<'a> {
    /// Restrict each message by its Thread-3 safe spans (in `message_values` order).
    PerMessage(&'a [Vec<(usize, usize)>]),
    /// Admit every window (synthetic positive control only).
    Unrestricted,
}

impl<'a> AggregateSafeFilter<'a> {
    /// The filter for the message at `index` (unrestricted control, or this message's
    /// Thread-3 safe spans — an absent index restricts to no admitted window).
    fn for_message(self, index: usize) -> SafeWindowFilter<'a> {
        match self {
            AggregateSafeFilter::Unrestricted => SafeWindowFilter::unrestricted(),
            AggregateSafeFilter::PerMessage(spans_by_message) => spans_by_message
                .get(index)
                .map_or(SafeWindowFilter::restrict(&[]), |spans| {
                    SafeWindowFilter::restrict(spans.as_slice())
                }),
        }
    }
}

/// Scores the aggregate held-out outcome across all messages for one (possibly
/// shuffled) corpus, using the IDENTICAL per-message pipeline and safe-span filter.
///
/// Returns the aggregate [`HeldOutScore`] (hits / misses / ambiguous), from which the
/// scalar coverage-weighted score is recomputed per message so the real eyes and each
/// matched-null shuffle are scored identically. Surfacing the aggregate counts also
/// gives the population's SCOREABLE-edge total, which sizes the F1 material-effect bar
/// (a fraction of the population's own max achievable score).
fn eyes_aggregate_held_out(
    message_values: &[Vec<TrigramValue>],
    safe_filter: AggregateSafeFilter<'_>,
) -> HeldOutScore {
    let mut aggregate = HeldOutScore::default();
    for (index, values) in message_values.iter().enumerate() {
        let evidence = eyes_message_evidence(values, safe_filter.for_message(index));
        aggregate.merge(evidence.held_out_score());
    }
    aggregate
}

/// Scores the aggregate REAL coverage-weighted held-out score across all messages for
/// one (possibly shuffled) corpus, using the IDENTICAL per-message pipeline.
///
/// The score rewards CONFIDENT, CORRECT, UNIQUE held-out predictions and penalizes
/// ambiguity — a corpus with genuine reusable context structure scores high; a
/// within-message shuffle (no reusable context classes) scores near zero / negative.
/// The coverage clamp is applied PER MESSAGE (so it stays symmetric across real and
/// null), hence the per-message recomputation rather than clamping the aggregate.
pub(crate) fn eyes_aggregate_score(
    message_values: &[Vec<TrigramValue>],
    safe_filter: AggregateSafeFilter<'_>,
) -> i64 {
    let mut total: i64 = 0;
    for (index, values) in message_values.iter().enumerate() {
        let evidence = eyes_message_evidence(values, safe_filter.for_message(index));
        total = total.saturating_add(evidence.held_out_score().coverage_weighted());
    }
    total
}

/// Runs the matched within-message shuffle null for the eyes held-out gate.
///
/// Each trial shuffles every message's symbol multiset in place (`fisher_yates`
/// over a clone — multiset and length conserved, only arrangement varies, exactly
/// the `isomorph_null` discipline) and re-runs the IDENTICAL aggregate held-out
/// pipeline. Returns `(null_at_least_real, null_mean_score)`: how many trials had
/// aggregate coverage-weighted score at least the real aggregate (the matched-null
/// upper tail), and the mean null score. A high count / comparable mean means the
/// real eyes do NOT beat the null — the expected outcome.
///
/// # Errors
/// Returns [`GakAttackError`] if a shuffle draw bound does not fit the PRNG.
fn eyes_matched_null_tail(
    message_values: &[Vec<TrigramValue>],
    config: &EyesAttackConfig,
    safe_spans_by_message: &[Vec<(usize, usize)>],
    real_score: i64,
) -> Result<(usize, f64), GakAttackError> {
    // The caller guarantees `config.trials >= 1` (the EyesZeroTrials guard), so the
    // null mean is always defined over a non-empty sample.
    let mut null_at_least_real = 0usize;
    let mut null_sum: i128 = 0;
    for trial in 0..config.trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            0x6579_6573_6e75_6c6c ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        let mut shuffled = message_values.to_vec();
        for values in &mut shuffled {
            fisher_yates(values, &mut rng)?;
        }
        // The shuffle preserves positions, so the SAME Thread-3 safe spans apply —
        // the null is scored under the identical safe-extent restriction (symmetric).
        let null_score = eyes_aggregate_score(
            &shuffled,
            AggregateSafeFilter::PerMessage(safe_spans_by_message),
        );
        null_sum = null_sum.saturating_add(i128::from(null_score));
        if null_score >= real_score {
            null_at_least_real = null_at_least_real.saturating_add(1);
        }
    }
    let trials = config.trials.max(1);
    let null_mean = null_sum as f64 / trials as f64;
    Ok((null_at_least_real, null_mean))
}

/// Runs the held-out POSITIVE CONTROL on a SYNTHETIC isomorph-rich eye-shaped
/// fixture: the predictor must fire on KNOWN signal.
///
/// The fixture (see [`synthetic_isomorph_rich_eye_message`]) carries a FIXED global
/// action `pi` recurring across isomorph groups, so train context classes recur and
/// held-out anchors uniquely identify them. The same per-message held-out pipeline
/// must give a real coverage-weighted score that strictly beats the worst-case
/// (max) matched within-message shuffle null over the control trials AND clears the
/// control's OWN population-relative material-effect bar (F1: a fraction of the
/// control's max achievable score). If it does not fire, the held-out gate is not
/// trustworthy. The fixture is scored UNRESTRICTED (it is not a corpus message and
/// has no Thread-3 safe extent), so the detector is validated on its full known
/// signal.
///
/// # Errors
/// Returns [`GakAttackError`] if a generated value is out of range or a shuffle
/// bound does not fit the PRNG.
pub(crate) fn eyes_held_out_positive_control(
    config: &EyesAttackConfig,
) -> Result<HeldOutPositiveControl, GakAttackError> {
    let fixture = synthetic_isomorph_rich_eye_message(config.seed)?;
    let fixture_slice = std::slice::from_ref(&fixture);
    let real_aggregate = eyes_aggregate_held_out(fixture_slice, AggregateSafeFilter::Unrestricted);
    let real_score = eyes_aggregate_score(fixture_slice, AggregateSafeFilter::Unrestricted);
    let scoreable_edges = real_aggregate.scoreable_edges();

    // Worst-case (max) matched within-message null score over the control trials.
    let mut null_score = i64::MIN;
    let control_trials = config.trials.clamp(1, POSITIVE_CONTROL_NULL_TRIALS);
    for trial in 0..control_trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            0x7063_5f73_796e_7468 ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        let mut shuffled = fixture.clone();
        fisher_yates(&mut shuffled, &mut rng)?;
        let trial_score = eyes_aggregate_score(
            std::slice::from_ref(&shuffled),
            AggregateSafeFilter::Unrestricted,
        );
        if trial_score > null_score {
            null_score = trial_score;
        }
    }
    // FIRE (F1-validated): the real signal's coverage-weighted score strictly beats
    // the WORST-CASE null over the control trials AND its real-vs-null excess clears
    // the control's OWN population-relative material-effect bar — the SAME fair gate
    // the eyes are judged against, so the bar is proven achievable by genuine signal.
    let control_excess =
        f64::from(i32::try_from(real_score.saturating_sub(null_score)).unwrap_or(i32::MAX));
    let control_bar = EYES_MATERIAL_EFFECT_FRACTION * max_achievable_score(scoreable_edges);
    let fired = real_score > null_score && real_score > 0 && control_excess >= control_bar;
    Ok(HeldOutPositiveControl {
        real_score,
        null_score,
        scoreable_edges,
        fired,
    })
}

/// Number of matched-null trials used for the held-out positive control (kept small
/// so the control is fast; the control is a fire/no-fire check, not a headline).
const POSITIVE_CONTROL_NULL_TRIALS: usize = 64;

/// Builds a synthetic isomorph-rich, GLOBALLY-CONSISTENT eye-shaped message for the
/// held-out positive control.
///
/// The fixture stacks several blocks that are copies of one random base block, each
/// advanced by the SAME fixed alphabet bijection `pi` (block `k` is `pi^k(base)`).
/// Aligned occurrences of the same equality pattern across blocks are therefore
/// related by a FIXED, GLOBALLY CONSISTENT, SINGLE-VALUED chain-link action
/// (`from -> to = pi^d` for block gap `d`) — exactly the transferable structure the
/// strict held-out test detects: a `from -> to` recovered from a TRAIN signature
/// group predicts DISJOINT HELD-OUT groups, and a within-message shuffle destroys it
/// (the matched null cannot reproduce a consistent `pi`). All values stay inside the
/// reading-layer range.
///
/// # Errors
/// Returns [`GakAttackError`] if a generated value exceeds the reading-layer range.
pub(crate) fn synthetic_isomorph_rich_eye_message(
    seed: u64,
) -> Result<Vec<TrigramValue>, GakAttackError> {
    let alphabet = EYE_READING_ALPHABET_SIZE;
    let mut rng = SplitMix64::new(mix_seed(seed, 0x6579_6573_6669_7874));
    // The fixed alphabet bijection pi: the GLOBAL, consistent chain-link action.
    // pi is NEAR-IDENTITY (a small, fixed number of transpositions over the FIRST
    // few alphabet symbols) so that pi^d acts on a SMALL, STABLE support: the same
    // compact action recurs IDENTICALLY across many well-separated blocks and yields
    // robust cross-group consensus (the embargoed predictor needs >= 2 distinct
    // non-overlapping signature groups to agree). A full random pi would scramble the
    // whole alphabet after a few steps and make cross-group consensus seed-fragile.
    let mut pi: Vec<usize> = (0..alphabet).collect();
    for k in 0..4usize {
        // Transpose adjacent low symbols: a tiny, deterministic, seed-independent
        // support so the action class is stable across every seed.
        let i = (2 * k) % alphabet;
        let j = (2 * k + 1) % alphabet;
        pi.swap(i, j);
    }

    // A random base block over the SMALL support region plus internal repeats so its
    // windows are repeat-bearing isomorphs that pi acts on non-trivially.
    let support = 12usize;
    let block_len = 18usize;
    let mut base: Vec<usize> = Vec::with_capacity(block_len);
    for _ in 0..block_len {
        // Draw from the small support region so pi acts on most of the block.
        let v = (random_index_below(support, &mut rng)?).min(alphabet.saturating_sub(1));
        base.push(v);
    }
    if let (Some(a), Some(slot)) = (base.first().copied(), base.get_mut(6)) {
        *slot = a;
    }
    if let (Some(a), Some(slot)) = (base.get(3).copied(), base.get_mut(11)) {
        *slot = a;
    }
    if let (Some(a), Some(slot)) = (base.get(2).copied(), base.get_mut(15)) {
        *slot = a;
    }

    // Stack MANY blocks block_k = pi^k(base) so the same pi^d action recurs across a
    // dozen+ well-separated, DISTINCT signature groups (robust cross-group consensus).
    // A short random spacer separates blocks so the boundary does not forge a spurious
    // long isomorph.
    let blocks = 16usize;
    let mut raw: Vec<usize> = Vec::new();
    let mut current = base;
    for block in 0..blocks {
        if block > 0 {
            raw.push(support.saturating_add(block % 8));
            current = current
                .iter()
                .map(|&v| pi.get(v).copied().unwrap_or(v))
                .collect();
        }
        raw.extend_from_slice(&current);
    }

    let mut values = Vec::with_capacity(raw.len());
    for v in raw {
        let raw_value =
            u8::try_from(v).map_err(|_error| GakAttackError::SymbolOutOfRange { value: v })?;
        let value =
            TrigramValue::new(raw_value).map_err(|bad| GakAttackError::SymbolOutOfRange {
                value: usize::from(bad),
            })?;
        values.push(value);
    }
    Ok(values)
}

/// The Thread-3 consultation: the consistency verdict PLUS the per-message safe
/// isomorph spans Gate-1 chaining is ENFORCED to stay within (F2).
struct ThreeConsultation {
    /// The Gate-2 consistency verdict consumed by the report.
    verdict: ThreeConsistency,
    /// For each message (in the SAME order as the corpus keys), the half-open safe
    /// spans Thread 3 exported for that message. Gate-1 windows are admitted only
    /// within these spans; an empty inner list means Thread 3 found no safe extent in
    /// that message, so NO Gate-1 window there is admitted.
    safe_spans_by_message: Vec<Vec<(usize, usize)>>,
}

/// Consults Thread 3's perfect-isomorphism scan for the consistency gate AND the
/// safe-extent enforcement (REUSE — run ONCE, both products derived from one report).
///
/// Reads the Thread-3 report's `robust_internal_violations` (must be `0` — a
/// non-zero count is a manufactured TRUE conflict), `safe_extents` (the conservative
/// per-message spans Gate-1 chaining is RESTRICTED to — F2), and
/// `positive_control_fired` (the scan is trustworthy). The candidate model is
/// CONSISTENT only if there are zero robust internal violations and the positive
/// control fired. The per-message safe spans are projected from the cross-message
/// extents and returned in `keys` order so Gate 1 can enforce them.
///
/// # Errors
/// Returns [`GakAttackError::PerfectIsomorphism`] if the Thread-3 scan fails.
fn eyes_three_consultation(keys: &[&'static str]) -> Result<ThreeConsultation, GakAttackError> {
    // The fields we consult — robust internal violations, safe extents, and the
    // positive-control fire — are DETERMINISTIC in the trial count (trials only
    // size the null band we do not read here), so a small trial count gives the
    // identical verdict far faster. We still run a non-trivial count so Thread 3's
    // own ZeroTrials guard and positive control execute normally.
    let report = perfect_isomorphism::run_perfect_isomorphism(
        perfect_isomorphism::PerfectIsomorphismConfig {
            trials: EYES_THREE_CONSISTENCY_TRIALS,
            ..perfect_isomorphism::PerfectIsomorphismConfig::default()
        },
    )?;
    let consistent = report.robust_internal_violations == 0 && report.positive_control_fired;
    let safe_spans_by_message = eyes_safe_spans_by_message(&report.safe_extents, keys);
    Ok(ThreeConsultation {
        verdict: ThreeConsistency {
            robust_internal_violations: report.robust_internal_violations,
            safe_extents: report.safe_extents.len(),
            positive_control_fired: report.positive_control_fired,
            consistent,
        },
        safe_spans_by_message,
    })
}

/// Projects the cross-message Thread-3 safe extents onto PER-MESSAGE half-open spans,
/// in the SAME order as `keys` (F2 enforcement input).
///
/// Each [`perfect_isomorphism::SafeIsomorphExtent`] is a SAFE cross-message aligned
/// isomorph: its `pair = (left_key, right_key)` carries a `left_span` in the left
/// message and a `right_span` in the right message. A Gate-1 occurrence window in
/// message `key` is admissible only inside a span where THIS message safely
/// participates in a cross-message isomorph alignment, so we collect, for each key,
/// every left span whose `pair.0 == key` and every right span whose `pair.1 == key`.
/// Messages with no safe extent get an empty span list (no Gate-1 window admitted).
fn eyes_safe_spans_by_message(
    extents: &[perfect_isomorphism::SafeIsomorphExtent],
    keys: &[&'static str],
) -> Vec<Vec<(usize, usize)>> {
    keys.iter()
        .map(|&key| {
            let mut spans: Vec<(usize, usize)> = Vec::new();
            for extent in extents {
                if extent.pair.0 == key {
                    spans.push((extent.left_span.start, extent.left_span.end()));
                }
                if extent.pair.1 == key {
                    spans.push((extent.right_span.start, extent.right_span.end()));
                }
            }
            spans
        })
        .collect()
}

/// Runs the SPECULATIVE cleartext-plausibility gate (kill gate 3) — ONLY reached if
/// both structural gates passed (the expected case is that this is never run).
///
/// The symbol→letter mapping here is a HYPOTHESIS, never recovered: the
/// reading-layer symbols are mapped onto the language alphabet by a fixed,
/// explicitly-arbitrary affine projection `value*stride % alphabet_len`, the
/// implied plaintext is scored under the Finnish AND English models (Finnish
/// weighted highly — Noita is a Finnish game), and the scores are compared
/// against a matched null drawn from the SAME affine family (random coprime
/// stride + offset), so the single real stride sits at a well-defined percentile
/// within one exchangeable family rather than against a different-shape draw.
/// This is never primary evidence; the implied plaintext is logged verbatim for
/// human review regardless of the verdict.
///
/// # Errors
/// Returns [`GakAttackError::Language`] if a language model cannot be built.
fn eyes_speculative_cleartext(
    message_values: &[Vec<TrigramValue>],
    config: &EyesAttackConfig,
) -> Result<SpeculativeCleartext, GakAttackError> {
    let finnish = language::finnish_model()?;
    let english = language::english_model()?;
    let alphabet_len = finnish.alphabet().len().max(1);

    // HYPOTHESIZED (arbitrary) symbol→letter mapping: a fixed modular projection of
    // the reading-layer value onto the language alphabet. This is NOT recovered and
    // is labelled a hypothesis everywhere.
    let mapping = eyes_hypothesis_mapping(alphabet_len, config.seed);
    let indices: Vec<usize> = message_values
        .iter()
        .flatten()
        .map(|value| mapping.get(usize::from(value.get())).copied().unwrap_or(0))
        .collect();

    let implied_plaintext = render_implied_plaintext(&indices, &finnish);
    let finnish_score = finnish
        .score_indices(&indices)
        .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);
    let english_score = english
        .score_indices(&indices)
        .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);

    // Matched null: draw other mappings from the SAME affine family (random
    // coprime stride + offset) and re-score. The implied plaintext only "beats"
    // the null if it exceeds the affine-family mean — and even then it is a
    // HYPOTHESIS.
    let (finnish_null_mean, english_null_mean) =
        eyes_mapping_null(message_values, alphabet_len, config, &finnish, &english);

    Ok(SpeculativeCleartext {
        implied_plaintext,
        finnish_score,
        english_score,
        finnish_null_mean,
        english_null_mean,
        beats_finnish_null: finnish_score > finnish_null_mean,
        beats_english_null: english_score > english_null_mean,
    })
}

/// Builds the HYPOTHESIZED (arbitrary, never-recovered) symbol→letter mapping for
/// the speculative gate: a fixed modular projection of each reading-layer value onto
/// the language alphabet. Labelled a hypothesis everywhere it is used.
fn eyes_hypothesis_mapping(alphabet_len: usize, seed: u64) -> Vec<usize> {
    let stride = 1 + (seed as usize % alphabet_len.max(1));
    (0..EYE_READING_ALPHABET_SIZE)
        .map(|value| (value.wrapping_mul(stride)) % alphabet_len)
        .collect()
}

/// Draws one `(stride, offset)` pair from the affine family used by
/// [`eyes_hypothesis_mapping`]: a stride coprime to `len` (so the map is a
/// bijection on `0..len`) and a uniform offset in `0..len`. Returns `None` if an
/// index draw fails (unreachable for `len >= 1` on 64-bit targets).
fn draw_affine_stride_offset(len: usize, rng: &mut SplitMix64) -> Option<(usize, usize)> {
    // Rejection-sample a coprime stride in 1..=len, mirroring the real mapping's
    // `1 + (seed % len)` range. `len` is coprime to itself only when `len == 1`,
    // and `stride == 1` is always coprime, so this loop always terminates.
    let stride = loop {
        let stride = random_index_below(len, rng).ok()? + 1;
        if gcd(stride, len) == 1 {
            break stride;
        }
    };
    let offset = random_index_below(len, rng).ok()?;
    Some((stride, offset))
}

/// Greatest common divisor of two non-negative integers (Euclid's algorithm).
fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

/// Renders the implied plaintext string under a hypothesized mapping (for verbatim
/// logging). Each index becomes its alphabet symbol; out-of-range indices become `?`.
fn render_implied_plaintext(indices: &[usize], model: &LanguageModel) -> String {
    let mut rendered = String::with_capacity(indices.len());
    for &index in indices {
        match model.alphabet().symbol(index) {
            Some(symbol) => rendered.push(symbol),
            None => rendered.push('?'),
        }
    }
    rendered
}

/// Matched null for the speculative cleartext gate: mean Finnish/English bigram
/// scores over mappings drawn from the SAME affine family as the real hypothesis
/// (see [`eyes_hypothesis_mapping`]). Each trial draws a random stride coprime to
/// `alphabet_len` and a random offset and builds `full[value] = (value*a + b) %
/// alphabet_len`, so the single real stride sits at a well-defined percentile of
/// one exchangeable family rather than against a different-shape (random
/// relabeling) draw.
fn eyes_mapping_null(
    message_values: &[Vec<TrigramValue>],
    alphabet_len: usize,
    config: &EyesAttackConfig,
    finnish: &LanguageModel,
    english: &LanguageModel,
) -> (f64, f64) {
    let trials = config.trials.clamp(1, 256);
    let mut finnish_sum = 0.0f64;
    let mut english_sum = 0.0f64;
    let mut counted = 0usize;
    for trial in 0..trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            0x6d61_705f_6e75_6c6c ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        // Draw this trial's mapping from the SAME affine family as the real
        // hypothesis: a stride `a` coprime to `alphabet_len` and an offset `b`.
        let len = alphabet_len.max(1);
        let Some((a, b)) = draw_affine_stride_offset(len, &mut rng) else {
            continue;
        };
        let full: Vec<usize> = (0..EYE_READING_ALPHABET_SIZE)
            .map(|value| (value.wrapping_mul(a).wrapping_add(b)) % len)
            .collect();
        let indices: Vec<usize> = message_values
            .iter()
            .flatten()
            .map(|value| full.get(usize::from(value.get())).copied().unwrap_or(0))
            .collect();
        let f = finnish
            .score_indices(&indices)
            .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);
        let e = english
            .score_indices(&indices)
            .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);
        if f.is_finite() && e.is_finite() {
            finnish_sum += f;
            english_sum += e;
            counted = counted.saturating_add(1);
        }
    }
    if counted == 0 {
        (f64::NEG_INFINITY, f64::NEG_INFINITY)
    } else {
        (finnish_sum / counted as f64, english_sum / counted as f64)
    }
}

/// Derives a STABLE candidate-record filename from the run config/seed (NO clock).
///
/// The record must be reproducible, so the label is derived only from the seed,
/// trial count, and beam width — never a wall-clock timestamp.
fn eyes_record_filename(config: &EyesAttackConfig) -> String {
    format!(
        "eyes-seed-{:016x}-trials-{}-beam-{}.md",
        config.seed, config.trials, config.beam_width
    )
}

/// Bundle of inputs for writing the candidate record (keeps the writer signature
/// small and avoids a long argument list).
pub(crate) struct EyesRecordInputs<'a> {
    pub(crate) config: &'a EyesAttackConfig,
    pub(crate) order_name: &'a str,
    pub(crate) total_symbols: usize,
    pub(crate) distinct_symbols: usize,
    pub(crate) per_message: &'a [EyeMessageHeldOut],
    pub(crate) real_held_out_hits_total: usize,
    pub(crate) real_held_out_misses_total: usize,
    pub(crate) real_held_out_ambiguous_total: usize,
    pub(crate) real_score: i64,
    pub(crate) scoreable_edges: usize,
    pub(crate) max_achievable_score: f64,
    pub(crate) null_mean_score: f64,
    pub(crate) material_effect_threshold: f64,
    pub(crate) material_effect_met: bool,
    pub(crate) matched_null_p_value: f64,
    pub(crate) null_at_least_real: usize,
    pub(crate) held_out_beats_null: bool,
    pub(crate) held_out_positive_control: HeldOutPositiveControl,
    pub(crate) three_consistency: ThreeConsistency,
    pub(crate) candidate_survived: bool,
    pub(crate) speculative_cleartext: Option<&'a SpeculativeCleartext>,
}

/// Writes the mandatory candidate record for the eyes Step-3 run (filename is a
/// STABLE config/seed label, NO clock; re-running the same config overwrites the
/// prior record).
///
/// The record captures what was attempted, how much structure was recovered, the
/// held-out verdict + matched-null p-value, the Thread-3 consistency verdict, and
/// the explicit HYPOTHESIS-not-decode label and claim ceiling. If any candidate
/// cleartext emerged (the speculative gate ran) it is logged VERBATIM in English
/// AND Finnish with its scores and caveats. The expected record is a "NO candidate
/// surfaced — decode remains blocked" entry.
///
/// # Errors
/// Returns [`GakAttackError::CandidateRecordWrite`] if the directory cannot be
/// created or the file cannot be written.
fn write_eyes_candidate_record(
    path: &Path,
    inputs: &EyesRecordInputs<'_>,
) -> Result<(), GakAttackError> {
    let body = render_eyes_candidate_record(inputs).map_err(|_error| {
        GakAttackError::CandidateRecordWrite {
            path: path.display().to_string(),
        }
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_error| GakAttackError::CandidateRecordWrite {
            path: path.display().to_string(),
        })?;
    }
    std::fs::write(path, body).map_err(|_error| GakAttackError::CandidateRecordWrite {
        path: path.display().to_string(),
    })
}

/// Renders the candidate-record markdown body (split out so it is unit-testable
/// without touching the filesystem). Returns a [`std::fmt::Error`] only if a
/// string-buffer write fails (never, for an in-memory `String`).
pub(crate) fn render_eyes_candidate_record(
    inputs: &EyesRecordInputs<'_>,
) -> Result<String, std::fmt::Error> {
    let mut out = String::new();
    let verdict = if inputs.candidate_survived {
        "CANDIDATE SURVIVED BOTH STRUCTURAL GATES — logged as a HYPOTHESIS, NOT a decode"
    } else {
        "NO candidate surfaced — decode remains blocked"
    };
    // Header + claim ceiling (verbatim-in-spirit).
    writeln!(out, "# Eyes Step-3 GAK-attack candidate record")?;
    writeln!(out)?;
    writeln!(
        out,
        "Stable label (NO wall-clock): seed=0x{:016x} trials={} beam={}",
        inputs.config.seed, inputs.config.trials, inputs.config.beam_width
    )?;
    writeln!(out)?;
    writeln!(out, "## Verdict")?;
    writeln!(out)?;
    writeln!(out, "**{verdict}.**")?;
    writeln!(out)?;
    writeln!(
        out,
        "This record is a HYPOTHESIS, NOT a decode. The standing conclusion is the eye"
    )?;
    writeln!(
        out,
        "decode remains BLOCKED on the unknown symbol->meaning mapping, and it is"
    )?;
    writeln!(
        out,
        "preserved by this run unless a candidate survived BOTH structural gates below."
    )?;
    writeln!(out)?;
    writeln!(out, "## Claim ceiling (absolute)")?;
    writeln!(out)?;
    writeln!(
        out,
        "The eyes are deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext."
    )?;
    writeln!(
        out,
        "Nothing in this record is stronger. The EXPECTED outcome of this unit is NO"
    )?;
    writeln!(
        out,
        "surviving candidate; a clean honest negative is a SUCCESS, not a failure."
    )?;
    writeln!(out)?;

    // What was attempted + entry path.
    writeln!(out, "## What was attempted")?;
    writeln!(out)?;
    writeln!(
        out,
        "Pointed the matured chain-link / hidden-state attack at the REAL eye corpus"
    )?;
    writeln!(
        out,
        "via the exact entry path orders::corpus_grids() -> accepted_honeycomb_order()"
    )?;
    writeln!(
        out,
        "-> read_corpus_message_values (per-message, boundaries kept, order `{}`).",
        inputs.order_name
    )?;
    writeln!(
        out,
        "Corpus pins: {} reading-layer symbols, {} distinct (83-symbol reading layer).",
        inputs.total_symbols, inputs.distinct_symbols
    )?;
    writeln!(
        out,
        "The attack recovers STRUCTURE (visible-coset / chain-link constraints), NOT"
    )?;
    writeln!(
        out,
        "cleartext: a full structural recovery still yields abstract letter INDICES,"
    )?;
    writeln!(
        out,
        "not readable text, because symbol->letter mapping needs an external anchor"
    )?;
    writeln!(out, "(the standing blocker).")?;
    writeln!(out)?;

    render_eyes_gate1(&mut out, inputs)?;
    render_eyes_gates_2_3_conclusion(&mut out, inputs)?;
    Ok(out)
}

/// Writes the Gate-1 (held-out isomorphs) section of the candidate record.
fn render_eyes_gate1(out: &mut String, inputs: &EyesRecordInputs<'_>) -> std::fmt::Result {
    // Gate 1: held-out (embargoed-consensus coverage-weighted excess correctness).
    writeln!(
        out,
        "## Gate 1 — held-out isomorphs vs matched within-message null"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "Statistic: EMBARGOED-CONSENSUS coverage-weighted excess correctness. The"
    )?;
    writeln!(
        out,
        "recovered model is a LIBRARY of context-colored partial permutations (one per"
    )?;
    writeln!(
        out,
        "TRAIN isomorph occurrence pair), NOT a collapsed global symbol map. A held-out"
    )?;
    writeln!(
        out,
        "edge scores only when >=2 train contexts from DISTINCT signature groups, with NO",
    )?;
    writeln!(
        out,
        "physical span overlap/adjacency with the held-out context, AGREE on it (the"
    )?;
    writeln!(
        out,
        "embargo kills the nested/overlapping-window leak a shuffle mimics):"
    )?;
    writeln!(
        out,
        "score = (A-1)*hits - A*misses (ambiguous unpenalized), A=83. A per-message"
    )?;
    writeln!(
        out,
        "COVERAGE CLAMP zeroes any message with < 4 confident decisions (hits+misses) —"
    )?;
    writeln!(
        out,
        "an explicit part of the statistic, applied identically to the real eyes and to"
    )?;
    writeln!(
        out,
        "every matched-null shuffle, so it cannot manufacture a real-vs-null gap. Only"
    )?;
    writeln!(
        out,
        "structure transferable across DISTINCT signature groups scores; a within-message"
    )?;
    writeln!(
        out,
        "shuffle has none detected by this gate, so it scores ~0. Gate-1 chaining is"
    )?;
    writeln!(
        out,
        "ENFORCED to stay WITHIN the Thread-3 safe isomorph extents (F2): an occurrence"
    )?;
    writeln!(
        out,
        "window is admitted only when it lies inside a Thread-3 safe span for its message,"
    )?;
    writeln!(
        out,
        "so chaining never over-extends past a Thread-3 break (the restriction is"
    )?;
    writeln!(
        out,
        "positional, so the matched null is scored under the identical restriction)."
    )?;
    render_eyes_gate1_scores(out, inputs)
}

/// Writes the Gate-1 score lines + per-message table of the candidate record.
fn render_eyes_gate1_scores(out: &mut String, inputs: &EyesRecordInputs<'_>) -> std::fmt::Result {
    writeln!(
        out,
        "Held-out positive control on a SYNTHETIC isomorph-rich eye-shaped fixture:"
    )?;
    writeln!(
        out,
        "  real score {} vs worst-case null score {} (on {} scoreable edges) -> fired={}",
        inputs.held_out_positive_control.real_score,
        inputs.held_out_positive_control.null_score,
        inputs.held_out_positive_control.scoreable_edges,
        inputs.held_out_positive_control.fired
    )?;
    writeln!(
        out,
        "  (the predictor must fire on KNOWN signal AND clear its OWN population's"
    )?;
    writeln!(
        out,
        "  material-effect bar, or the held-out gate is not trusted)."
    )?;
    writeln!(
        out,
        "Real eyes aggregate held-out: hits={} misses={} ambiguous={}; coverage-weighted score = {}.",
        inputs.real_held_out_hits_total,
        inputs.real_held_out_misses_total,
        inputs.real_held_out_ambiguous_total,
        inputs.real_score
    )?;
    writeln!(
        out,
        "Matched within-message shuffle null: {} trials, {} >= real; null mean score {:.2}; add-one p = {:.4}.",
        inputs.config.trials,
        inputs.null_at_least_real,
        inputs.null_mean_score,
        inputs.matched_null_p_value
    )?;
    let fraction = EYES_MATERIAL_EFFECT_FRACTION;
    writeln!(
        out,
        "Material-effect bar (p-value alone is NECESSARY, NOT sufficient), POPULATION-RELATIVE"
    )?;
    writeln!(
        out,
        "and FAIR to the eyes: the real-vs-null excess must reach {fraction:.2} of the eyes' OWN max",
    )?;
    writeln!(
        out,
        "achievable score = scoreable_edges*(A-1) = {}*82 = {:.0}, so the bar = {:.1}. The eyes",
        inputs.scoreable_edges, inputs.max_achievable_score, inputs.material_effect_threshold
    )?;
    writeln!(
        out,
        "COULD clear this bar with real signal (the bar is BELOW their max achievable); their"
    )?;
    let real_excess = inputs.real_score as f64 - inputs.null_mean_score;
    writeln!(
        out,
        "excess is {real_excess:.1} (real {} - null mean {:.2}), threshold {:.1}, so met={}. The detector is validated: the positive control clears its own",
        inputs.real_score,
        inputs.null_mean_score,
        inputs.material_effect_threshold,
        inputs.material_effect_met
    )?;
    writeln!(out, "population's bar by the identical rule.")?;
    writeln!(
        out,
        "GATE 1 VERDICT (held-out beats matched null AND clears the material-effect bar): {}.",
        inputs.held_out_beats_null
    )?;
    writeln!(out)?;
    writeln!(out, "Per-message (boundaries kept; never concatenated):")?;
    for m in inputs.per_message {
        writeln!(
            out,
            "  {:<6} len={:<3} iso-groups={:<3} pairs={:<4} touched={:<3} aborts={:<3} hits={} miss={} amb={} score={}",
            m.message_key,
            m.length,
            m.isomorph_groups,
            m.aligned_pairs,
            m.symbols_touched,
            m.true_conflict_aborts,
            m.real_held_out_hits,
            m.real_held_out_misses,
            m.real_held_out_ambiguous,
            m.real_score
        )?;
    }
    writeln!(out)?;
    Ok(())
}

/// Writes the Gate-2, Gate-3, and Standing-conclusion sections of the record.
fn render_eyes_gates_2_3_conclusion(
    out: &mut String,
    inputs: &EyesRecordInputs<'_>,
) -> std::fmt::Result {
    // Gate 2: Thread-3 consistency.
    writeln!(
        out,
        "## Gate 2 — Thread-3 perfect-isomorphism consistency (reused API)"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "robust internal violations: {} (must be 0 — a non-zero count is a manufactured",
        inputs.three_consistency.robust_internal_violations
    )?;
    writeln!(out, "TRUE conflict and would disqualify the model).")?;
    writeln!(
        out,
        "safe isomorph extents exported: {} (Gate-1 chaining is ENFORCED to stay within",
        inputs.three_consistency.safe_extents
    )?;
    writeln!(
        out,
        "these per-message safe spans (F2) — an occurrence window is admitted only inside a"
    )?;
    writeln!(
        out,
        "Thread-3 safe span, so chaining never over-extends past them)."
    )?;
    writeln!(
        out,
        "Thread-3 positive control fired: {}.",
        inputs.three_consistency.positive_control_fired
    )?;
    writeln!(
        out,
        "GATE 2 VERDICT (model consistent with Thread 3): {}.",
        inputs.three_consistency.consistent
    )?;
    writeln!(out)?;
    render_eyes_gate3_conclusion(out, inputs)
}

/// Writes the Gate-3 (speculative cleartext) and Standing-conclusion sections.
fn render_eyes_gate3_conclusion(
    out: &mut String,
    inputs: &EyesRecordInputs<'_>,
) -> std::fmt::Result {
    // Gate 3: speculative cleartext.
    writeln!(
        out,
        "## Gate 3 — SPECULATIVE cleartext plausibility (Finnish-weighted)"
    )?;
    writeln!(out)?;
    match inputs.speculative_cleartext {
        None => {
            writeln!(
                out,
                "NOT RUN. Gate 1 and/or Gate 2 did not pass (the expected case), so the"
            )?;
            writeln!(
                out,
                "speculative cleartext path is correctly NOT executed and NO candidate"
            )?;
            writeln!(out, "cleartext is reported. The decode remains blocked.")?;
        }
        Some(s) => {
            writeln!(
                out,
                "RAN (both structural gates passed). The symbol->letter mapping below is a",
            )?;
            writeln!(
                out,
                "HYPOTHESIS, never recovered; this is NEVER primary evidence. Logged VERBATIM",
            )?;
            writeln!(
                out,
                "for human review (Finnish weighted highly — Noita is Finnish)."
            )?;
            writeln!(out)?;
            writeln!(
                out,
                "Finnish bigram score {:.4} vs matched-mapping null mean {:.4} -> beats={}",
                s.finnish_score, s.finnish_null_mean, s.beats_finnish_null
            )?;
            writeln!(
                out,
                "English bigram score {:.4} vs matched-mapping null mean {:.4} -> beats={}",
                s.english_score, s.english_null_mean, s.beats_english_null
            )?;
            writeln!(out)?;
            writeln!(out, "Implied plaintext (HYPOTHESIS, verbatim):")?;
            writeln!(out, "```")?;
            writeln!(out, "{}", s.implied_plaintext)?;
            writeln!(out, "```")?;
        }
    }
    writeln!(out)?;
    writeln!(out, "## Standing conclusion")?;
    writeln!(out)?;
    if inputs.candidate_survived {
        writeln!(
            out,
            "A candidate survived both structural gates. It is logged here as a HYPOTHESIS",
        )?;
        writeln!(
            out,
            "for human review, NOT a decode. The standing claim is softened to \"a candidate",
        )?;
        writeln!(
            out,
            "structure passed the held-out + Thread-3 checks\" — it is NOT a recovered"
        )?;
        writeln!(out, "plaintext and the claim ceiling still binds.")?;
    } else {
        writeln!(
            out,
            "No candidate surfaced. The eye decode REMAINS BLOCKED on the unknown"
        )?;
        writeln!(
            out,
            "symbol->meaning mapping. This negative is the expected, reportable outcome."
        )?;
    }
    Ok(())
}
