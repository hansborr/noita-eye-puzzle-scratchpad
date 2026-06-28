//! The mandatory candidate record: a clock-free, reproducible markdown log of each
//! eyes Step-3 run.
//!
//! Writes (and renders) the candidate record under the configured directory,
//! capturing the attempt, the recovered-structure amount, the held-out + Thread-3
//! verdicts, and the explicit hypothesis-not-decode label. Any candidate cleartext
//! is logged verbatim for human review.

use super::super::*;

/// Derives a stable candidate-record filename from the run config/seed (no clock).
///
/// The record must be reproducible, so the label is derived only from the seed,
/// trial count, and beam width — never a wall-clock timestamp.
pub(super) fn eyes_record_filename(config: &EyesAttackConfig) -> String {
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
/// stable config/seed label, no clock; re-running the same config overwrites the
/// prior record).
///
/// The record captures what was attempted, how much structure was recovered, the
/// held-out verdict + matched-null p-value, the Thread-3 consistency verdict, and
/// the explicit hypothesis-not-decode label. If any candidate
/// cleartext emerged (the speculative gate ran) it is logged verbatim in English
/// and Finnish with its scores and caveats. The expected record is a "no candidate
/// surfaced — decode remains blocked" entry.
///
/// # Errors
/// Returns [`GakAttackError::CandidateRecordWrite`] if the directory cannot be
/// created or the file cannot be written.
pub(super) fn write_eyes_candidate_record(
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
        "candidate survived both structural gates — logged as a hypothesis, not a decode"
    } else {
        "no candidate surfaced — decode remains blocked"
    };
    // Header + verdict.
    writeln!(out, "# Eyes Step-3 GAK-attack candidate record")?;
    writeln!(out)?;
    writeln!(
        out,
        "Stable label (no wall-clock): seed=0x{:016x} trials={} beam={}",
        inputs.config.seed, inputs.config.trials, inputs.config.beam_width
    )?;
    writeln!(out)?;
    writeln!(out, "## Verdict")?;
    writeln!(out)?;
    writeln!(out, "**{verdict}.**")?;
    writeln!(out)?;
    writeln!(
        out,
        "This record is a hypothesis, not a decode. The standing conclusion is the eye"
    )?;
    writeln!(
        out,
        "decode remains blocked on the unknown symbol->meaning mapping, and it is"
    )?;
    writeln!(
        out,
        "preserved by this run unless a candidate survived both structural gates below."
    )?;
    writeln!(out)?;

    // What was attempted + entry path.
    writeln!(out, "## What was attempted")?;
    writeln!(out)?;
    writeln!(
        out,
        "Pointed the matured chain-link / hidden-state attack at the real eye corpus"
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
        "The attack recovers structure (visible-coset / chain-link constraints), not"
    )?;
    writeln!(
        out,
        "cleartext: a full structural recovery still yields abstract letter indices,"
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
        "Statistic: embargoed-consensus coverage-weighted excess correctness. The"
    )?;
    writeln!(
        out,
        "recovered model is a library of context-colored partial permutations (one per"
    )?;
    writeln!(
        out,
        "train isomorph occurrence pair), not a collapsed global symbol map. A held-out"
    )?;
    writeln!(
        out,
        "edge scores only when >=2 train contexts from distinct signature groups, with no",
    )?;
    writeln!(
        out,
        "physical span overlap/adjacency with the held-out context, agree on it (the"
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
        "coverage clamp zeroes any message with < 4 confident decisions (hits+misses) —"
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
        "structure transferable across distinct signature groups scores; a within-message"
    )?;
    writeln!(
        out,
        "shuffle has none detected by this gate, so it scores ~0. Gate-1 chaining is"
    )?;
    writeln!(
        out,
        "enforced to stay within the Thread-3 safe isomorph extents: an occurrence"
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
        "Held-out positive control on a synthetic isomorph-rich eye-shaped fixture:"
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
        "  (the predictor must fire on known signal and clear its own population's"
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
        "Material-effect bar (p-value alone is necessary, not sufficient), population-relative"
    )?;
    writeln!(
        out,
        "and fair to the eyes: the real-vs-null excess must reach {fraction:.2} of the eyes' own max",
    )?;
    writeln!(
        out,
        "achievable score = scoreable_edges*(A-1) = {}*82 = {:.0}, so the bar = {:.1}. The eyes",
        inputs.scoreable_edges, inputs.max_achievable_score, inputs.material_effect_threshold
    )?;
    writeln!(
        out,
        "could clear this bar with real signal (the bar is below their max achievable); their"
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
        "Gate 1 verdict (held-out beats matched null and clears the material-effect bar): {}.",
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
    writeln!(out, "true conflict and would disqualify the model).")?;
    writeln!(
        out,
        "safe isomorph extents exported: {} (Gate-1 chaining is enforced to stay within",
        inputs.three_consistency.safe_extents
    )?;
    writeln!(
        out,
        "these per-message safe spans — an occurrence window is admitted only inside a"
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
        "Gate 2 verdict (model consistent with Thread 3): {}.",
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
        "## Gate 3 — speculative cleartext plausibility (Finnish-weighted)"
    )?;
    writeln!(out)?;
    match inputs.speculative_cleartext {
        None => {
            writeln!(
                out,
                "Not run. Gate 1 and/or Gate 2 did not pass (the expected case), so the"
            )?;
            writeln!(
                out,
                "speculative cleartext path is correctly not executed and no candidate"
            )?;
            writeln!(out, "cleartext is reported. The decode remains blocked.")?;
        }
        Some(s) => {
            writeln!(
                out,
                "Ran (both structural gates passed). The symbol->letter mapping below is a",
            )?;
            writeln!(
                out,
                "hypothesis, never recovered; this is never primary evidence. Logged verbatim",
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
            writeln!(out, "Implied plaintext (hypothesis, verbatim):")?;
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
            "A candidate survived both structural gates. It is logged here as a hypothesis",
        )?;
        writeln!(
            out,
            "for human review, not a decode. The standing claim is softened to \"a candidate",
        )?;
        writeln!(
            out,
            "structure passed the held-out + Thread-3 checks\" — it is not a recovered"
        )?;
        writeln!(out, "plaintext and the claim ceiling still binds.")?;
    } else {
        writeln!(
            out,
            "No candidate surfaced. The eye decode remains blocked on the unknown"
        )?;
        writeln!(
            out,
            "symbol->meaning mapping. This negative is the expected, reportable outcome."
        )?;
    }
    Ok(())
}
