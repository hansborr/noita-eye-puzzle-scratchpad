//! The eyes Step-3 report type and its rendered CLI output.
//!
//! Holds [`EyesAttackReport`] (the standing "decode blocked" conclusion, measured
//! honestly) and its [`Report`] rendering. The claim-ceiling and HYPOTHESIS-not-
//! decode framing is rendered verbatim here; nothing printed may be stronger than
//! the conclusion the structural gates support.

use super::super::*;
use crate::report::{self, Report};

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
    /// population whose own max-achievable score sizes the material-effect bar.
    pub scoreable_edges: usize,
    /// The eyes' MAX achievable coverage-weighted score (`scoreable_edges * (A-1)`,
    /// i.e. every scoreable edge a confident HIT). The material-effect bar is a
    /// fraction of THIS, so a genuine eye signal COULD clear the bar.
    pub max_achievable_score: f64,
    /// The mean matched within-message shuffle-null coverage-weighted score.
    pub null_mean_score: f64,
    /// The POPULATION-RELATIVE MATERIAL-EFFECT threshold the real excess had to clear
    /// (`EYES_MATERIAL_EFFECT_FRACTION` of the eyes' own [`Self::max_achievable_score`])
    /// — the effect-size bar that makes p-value significance necessary but not
    /// sufficient, fair to the population under test.
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

impl Report for EyesAttackReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Thread 4 EYES Step 3 (the ONLY unit that touches the real eye corpus)"
        );
        report::appendln!(
            &mut out,
            "Claim ceiling: the eyes are deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext. Nothing here is stronger."
        );
        report::appendln!(
            &mut out,
            "Expected outcome: NO surviving candidate. The standing conclusion is the eye decode remains BLOCKED on the unknown symbol->meaning mapping; a clean honest negative is a SUCCESS, not a failure."
        );
        report::appendln!(
            &mut out,
            "What is recovered: STRUCTURE (visible-coset / chain-link constraints), NOT cleartext. A full structural recovery still yields abstract plaintext-letter INDICES, not readable text, because symbol->letter mapping needs an external ANCHOR (the standing blocker). Any candidate is a HYPOTHESIS, never a decode."
        );
        report::appendln!(
            &mut out,
            "entry path (exact): orders::corpus_grids() -> accepted_honeycomb_order() -> read_corpus_message_values (per-message, boundaries kept, never concatenated, never re-ordered)"
        );
        report::appendln!(
            &mut out,
            "  reading order `{}`; {} reading-layer symbols; {} distinct (the 83-symbol reading layer); {} messages",
            self.order_name,
            self.total_symbols,
            self.distinct_symbols,
            self.per_message.len()
        );
        report::appendln!(&mut out);
        append_eyes_gate1(&mut out, self);
        report::appendln!(&mut out);
        append_eyes_gates_2_3_verdict(&mut out, self);
        out
    }
}

fn append_eyes_gate1(out: &mut String, eyes_report: &EyesAttackReport) {
    // GATE 1: held-out isomorphs (embargoed-consensus coverage-weighted score).
    report::appendln!(
        out,
        "GATE 1 -- held-out isomorphs vs matched within-message shuffle null"
    );
    report::appendln!(
        out,
        "  statistic: EMBARGOED-CONSENSUS coverage-weighted excess correctness. The recovered model is a LIBRARY of context-colored partial permutations (one per TRAIN isomorph occurrence pair), NOT a collapsed global symbol map. A held-out edge scores only when >=2 train contexts from DISTINCT signature groups -- with NO physical span overlap/adjacency with the held-out context -- AGREE on it; that embargo kills the nested/overlapping-window leak a within-message shuffle mimics, so only genuinely TRANSFERABLE structure scores. score = (A-1)*hits - A*misses (ambiguous unpenalized), A=83, with a per-message COVERAGE CLAMP that zeroes any message with < 4 confident decisions (an explicit part of the statistic, applied identically to real and null). Gate-1 chaining is ENFORCED to stay within the Thread-3 safe isomorph extents (F2). A shuffle has no transferable structure detected by this gate, so it scores ~0."
    );
    report::appendln!(
        out,
        "  held-out POSITIVE CONTROL on a synthetic isomorph-rich eye-shaped fixture: real score {} vs worst-case null score {} (on {} scoreable edges) -> fired={} (the predictor must fire on KNOWN signal AND clear its OWN population's material-effect bar, or the gate is not trusted)",
        eyes_report.held_out_positive_control.real_score,
        eyes_report.held_out_positive_control.null_score,
        eyes_report.held_out_positive_control.scoreable_edges,
        report::yes_no(eyes_report.held_out_positive_control.fired)
    );
    report::appendln!(
        out,
        "  real eyes aggregate held-out: hits={} misses={} ambiguous={}; coverage-weighted score = {}",
        eyes_report.real_held_out_hits_total,
        eyes_report.real_held_out_misses_total,
        eyes_report.real_held_out_ambiguous_total,
        eyes_report.real_score
    );
    report::appendln!(
        out,
        "  matched within-message shuffle null: {} trials, {} >= real; null mean score {:.2}; add-one p = {:.4}",
        eyes_report.trials,
        eyes_report.null_at_least_real,
        eyes_report.null_mean_score,
        eyes_report.matched_null_p_value
    );
    report::appendln!(
        out,
        "  material-effect bar (p-value is NECESSARY, NOT sufficient), POPULATION-RELATIVE and FAIR to the eyes: the real-vs-null excess must reach {:.0}% of the eyes' OWN max achievable score = scoreable_edges*(A-1) = {}*{} = {:.0}, so threshold = {:.1} (BELOW the eyes' max, so genuine signal COULD clear it); met={} (the detector is validated: the positive control clears its own population's bar by the identical rule)",
        EYES_MATERIAL_EFFECT_FRACTION * 100.0,
        eyes_report.scoreable_edges,
        EYE_READING_ALPHABET_SIZE - 1,
        eyes_report.max_achievable_score,
        eyes_report.material_effect_threshold,
        report::yes_no(eyes_report.material_effect_met)
    );
    report::appendln!(
        out,
        "  GATE 1 VERDICT (held-out beats matched null AND clears the calibrated material-effect bar): {}",
        report::yes_no(eyes_report.held_out_beats_null)
    );
    report::appendln!(out, "  per-message (boundaries kept; never concatenated):");
    report::appendln!(
        out,
        "    {:<6} {:>4} {:>10} {:>6} {:>8} {:>7} {:>5} {:>5} {:>5} {:>7}",
        "msg",
        "len",
        "iso-groups",
        "pairs",
        "touched",
        "aborts",
        "hits",
        "miss",
        "amb",
        "score"
    );
    for message in &eyes_report.per_message {
        report::appendln!(
            out,
            "    {:<6} {:>4} {:>10} {:>6} {:>8} {:>7} {:>5} {:>5} {:>5} {:>7}",
            message.message_key,
            message.length,
            message.isomorph_groups,
            message.aligned_pairs,
            message.symbols_touched,
            message.true_conflict_aborts,
            message.real_held_out_hits,
            message.real_held_out_misses,
            message.real_held_out_ambiguous,
            message.real_score
        );
    }
}

fn append_eyes_gates_2_3_verdict(out: &mut String, eyes_report: &EyesAttackReport) {
    // GATE 2: Thread-3 consistency.
    report::appendln!(
        out,
        "GATE 2 -- Thread-3 perfect-isomorphism consistency (Thread-3 API REUSED, never re-derived)"
    );
    report::appendln!(
        out,
        "  robust internal violations: {} (must be 0 -- a non-zero count is a manufactured TRUE conflict that would disqualify the model)",
        eyes_report.three_consistency.robust_internal_violations
    );
    report::appendln!(
        out,
        "  safe isomorph extents exported: {} (Gate-1 chaining is ENFORCED to stay within these per-message safe spans (F2): an occurrence window is admitted only inside a Thread-3 safe span, so chaining never over-extends past them)",
        eyes_report.three_consistency.safe_extents
    );
    report::appendln!(
        out,
        "  Thread-3 positive control fired: {}",
        report::yes_no(eyes_report.three_consistency.positive_control_fired)
    );
    report::appendln!(
        out,
        "  GATE 2 VERDICT (model consistent with Thread 3): {}",
        report::yes_no(eyes_report.three_consistency.consistent)
    );
    report::appendln!(out);

    // GATE 3: speculative cleartext.
    report::appendln!(
        out,
        "GATE 3 -- SPECULATIVE cleartext plausibility (LAST, Finnish-weighted, NEVER primary)"
    );
    match &eyes_report.speculative_cleartext {
        None => {
            report::appendln!(
                out,
                "  NOT RUN. Gate 1 and/or Gate 2 did not pass (the expected case), so the SPECULATIVE cleartext path is correctly NOT executed and NO candidate cleartext is reported."
            );
        }
        Some(cleartext) => {
            report::appendln!(
                out,
                "  RAN (both structural gates passed). The symbol->letter mapping is a HYPOTHESIS, never recovered; this is NEVER primary evidence. Implied plaintext logged VERBATIM to the candidate record for human review (Finnish weighted highly -- Noita is Finnish)."
            );
            report::appendln!(
                out,
                "  Finnish bigram {:.4} vs matched-mapping null {:.4} -> beats={}; English bigram {:.4} vs null {:.4} -> beats={}",
                cleartext.finnish_score,
                cleartext.finnish_null_mean,
                report::yes_no(cleartext.beats_finnish_null),
                cleartext.english_score,
                cleartext.english_null_mean,
                report::yes_no(cleartext.beats_english_null)
            );
        }
    }
    report::appendln!(out);

    // The verdict + interpretation (honesty lock).
    report::appendln!(
        out,
        "THE VERDICT: candidate survived BOTH structural gates: {}",
        report::yes_no(eyes_report.candidate_survived)
    );
    if eyes_report.candidate_survived {
        report::appendln!(
            out,
            "Interpretation: a candidate survived the held-out + Thread-3 checks. It is logged as a HYPOTHESIS for human review, NOT a decode. The claim ceiling still binds: this is NOT a recovered eye plaintext. FLAGGED LOUDLY for human review."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: no candidate surfaced. This is the EXPECTED, reportable outcome -- with a near-S_83 group and very little eye text, recovered structure does not predict held-out isomorphs above the matched null (no transferable structure DETECTED BY THIS GATE). The eye decode REMAINS BLOCKED on the unknown symbol->meaning mapping. This is a HYPOTHESIS-free honest negative, NOT a decode."
        );
    }
    report::appendln!(
        out,
        "Candidate-logging protocol: every eyes run writes a dated, clock-free record under research/gak-threads/candidates/ capturing the attempt, the recovered-structure amount, the held-out verdict + matched-null p-value, the Thread-3 verdict, and the explicit HYPOTHESIS-not-decode label; any candidate cleartext (English OR Finnish) is logged VERBATIM for human review. This run's record: {}",
        eyes_report.record_path.display()
    );
}
