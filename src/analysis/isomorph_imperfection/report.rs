//! Rendering for the isomorph-imperfection scan report.
//!
//! Extracted verbatim from the leaf module; the byte-exact stdout render
//! (verdict language and claim ceiling included) is preserved unchanged.

use crate::analysis::perfect_isomorphism::{MAX_ISLAND_COLS, POST_MIN, SIGNIFICANCE_ALPHA};
use crate::report::{self, Report};

use super::{IsomorphImperfectionReport, NullOutcome};

impl Report for IsomorphImperfectionReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Thread G2 isomorph-imperfection disproof scan");
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "null trials: {}, family trials per rate: {}",
            self.config.null_trials,
            self.config.family_trials
        );
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(
            &mut out,
            "mapping-independent scope: ciphertext symbol equality and first-occurrence gap structure only"
        );
        report::appendln!(&mut out);
        append_window_section(&mut out, self);
        report::appendln!(&mut out);
        append_null_section(&mut out, self);
        report::appendln!(&mut out);
        append_stutter_section(&mut out, self);
        report::appendln!(&mut out);
        append_loose_candidates_section(&mut out, self);
        report::appendln!(&mut out);
        append_family_section(&mut out, self);
        report::appendln!(&mut out);
        append_verdict_section(&mut out, self);
        out
    }
}

fn append_window_section(out: &mut String, report: &IsomorphImperfectionReport) {
    report::appendln!(out, "extended-window push");
    report::appendln!(
        out,
        "  shortest message: {} (bound for the longest extended window {})",
        report.shortest_message,
        report.extended_windows.last().copied().unwrap_or_default()
    );
    report::appendln!(
        out,
        "  base windows {:?}: robust {}, loose {}",
        report.base_windows,
        report.base_counts.robust_internal_violations,
        report.base_counts.loose_candidates
    );
    report::appendln!(
        out,
        "  extended windows {:?}: robust {}, loose {}",
        report.extended_windows,
        report.extended_counts.robust_internal_violations,
        report.extended_counts.loose_candidates
    );
    report::appendln!(
        out,
        "  word-boundary discount: a break with no resync (trailing-edge divergence, no cross-island back-reference) is attributed to a possible plaintext word/segment boundary and discounted to internalness 0; only a two-sided break flanking a short island (<= {MAX_ISLAND_COLS}) with a far resync (>= {POST_MIN}) carrying a cross-island back-reference earns positive internalness"
    );
    report::appendln!(
        out,
        "  detector blind spot (tested envelope): a break counts as a robust violation ONLY if far_run >= {POST_MIN} AND island_cols <= {MAX_ISLAND_COLS} AND a cross-island back-reference exists; otherwise it is discounted to internalness 0 (invisible). The eye scan AND the entire positive-control family exercise only ONE geometry (single fresh-singleton island = 1, long far resync), so \"the detector fires on imperfections\" is demonstrated ONLY for that shape. Short-resync (far_run < {POST_MIN}) or wide-island (> {MAX_ISLAND_COLS}) imperfections are OUTSIDE the tested envelope"
    );
}

fn append_null_section(out: &mut String, report: &IsomorphImperfectionReport) {
    report::appendln!(
        out,
        "matched within-message-shuffle nulls (multiset-preserving, SplitMix64 Fisher-Yates) -- NOTE: this shuffle is STRUCTURE-DESTROYING for the isomorph statistics; it is weak for the robust falsifier (see the reading line). It is NOT the calibration of the family-falsifier statistic."
    );
    append_null_row(out, "loose-candidate class", &report.loose_null);
    append_null_row(out, "robust internal      ", &report.robust_null);
    report::appendln!(
        out,
        "  reading: the robust (non-benign) count is the family-falsifier statistic, but this within-message shuffle is NOT its calibration -- the shuffle destroys the very isomorphs an internal divergence lives in, so for observed robust {} the add-one p {} is the TRIVIAL COUNT FLOOR (0 is the minimum possible count) and carries NO evidential weight. The BINDING calibration of the robust statistic is the generative epsilon = 0 family (mean robust 0) in the family-fit section below. For the same structure-destroying reason the loose-candidate count EXCEEDS the shuffle null (add-one p small) -> that loose excess is genuine benign isomorph structure, not imperfection.",
        report.robust_null.observed,
        report::format_probability(report.robust_null.p)
    );
    report::appendln!(
        out,
        "  community context: the borderline A.B..B.A pattern is cited at ~13% chance coincidence; here the discriminating statistic is the non-benign robust count, which is {}.",
        report.extended_counts.robust_internal_violations
    );
}

fn append_null_row(out: &mut String, label: &str, outcome: &NullOutcome) {
    report::appendln!(
        out,
        "  {label}: observed {}, null mean {:.3}, median {:.1}, q97.5 {}, max {}, add-one p {}",
        outcome.observed,
        outcome.band.mean,
        outcome.band.median,
        outcome.band.q975,
        outcome.band.max,
        report::format_probability(outcome.p)
    );
}

fn append_stutter_section(out: &mut String, report: &IsomorphImperfectionReport) {
    report::appendln!(out, "east4/west4 Stutter loose-candidate chase");
    match report.stutter_candidate {
        Some(candidate) => {
            report::appendln!(
                out,
                "  located east4@{} / west4@{}: island {}, far-run {}, internalness {}, benign-Stutter {}",
                candidate.left_offset,
                candidate.right_offset,
                candidate.island_cols,
                candidate.far_run,
                candidate.internalness,
                candidate.benign_stutter
            );
            report::appendln!(
                out,
                "  promoted to robust internal violation: {}",
                candidate.promoted_to_violation
            );
        }
        None => report::appendln!(
            out,
            "  no qualifying east4/west4 loose candidate located under the extended windows"
        ),
    }
}

fn append_loose_candidates_section(out: &mut String, report: &IsomorphImperfectionReport) {
    report::appendln!(
        out,
        "all loose candidates (every break surviving the word-boundary discount; the negative is CONDITIONAL on EACH being benign-attributed, not only the east4/west4 one)"
    );
    report::appendln!(out, "  count: {}", report.loose_candidates.len());
    for candidate in &report.loose_candidates {
        report::appendln!(
            out,
            "  {}@{} / {}@{}: island {}, far-run {}, internalness {}, region {}, promoted {}",
            candidate.left_key,
            candidate.left_offset,
            candidate.right_key,
            candidate.right_offset,
            candidate.island_cols,
            candidate.far_run,
            candidate.internalness,
            candidate
                .benign_region
                .unwrap_or("UNATTRIBUTED (non-benign -> robust violation)"),
            candidate.promoted_to_violation
        );
    }
}

fn append_family_section(out: &mut String, report: &IsomorphImperfectionReport) {
    let family = &report.family;
    report::appendln!(
        out,
        "imperfect-isomorph family fit (model-conditional: one constructed family, not all imperfect ciphers)"
    );
    report::appendln!(
        out,
        "  {} synthetic messages, {} draws per rate",
        family.messages,
        family.trials_per_epsilon
    );
    report::appendln!(
        out,
        "  {:>7} {:>12} {:>10} {:>12} {:>10}",
        "epsilon",
        "mean-robust",
        "max-robust",
        "mean-loose",
        "max-loose"
    );
    for row in &family.rows {
        report::appendln!(
            out,
            "  {:>7.2} {:>12.3} {:>10} {:>12.3} {:>10}",
            row.epsilon,
            row.mean_robust,
            row.max_robust,
            row.mean_loose,
            row.max_loose
        );
    }
    report::appendln!(
        out,
        "  positive control: epsilon {:.2} mean-robust {:.3} vs baseline {:.3} -> {}",
        family.high_epsilon,
        family.high_mean_robust,
        family.baseline_mean_robust,
        if family.positive_control_fired {
            "FIRED"
        } else {
            "did not fire"
        }
    );
    report::appendln!(
        out,
        "  detection threshold (first rate with mean-robust >= 1): {}",
        family
            .detection_threshold
            .map_or_else(|| "none in grid".to_owned(), |value| format!("{value:.2}"))
    );
    report::appendln!(
        out,
        "  eyes observed robust {} -> best-fit epsilon {:.2}",
        family.observed_robust,
        family.best_fit_epsilon
    );
    if family.observed_robust == 0 {
        let min_positive_mean = family
            .rows
            .iter()
            .filter(|row| row.epsilon > 0.0)
            .map(|row| row.mean_robust)
            .fold(f64::INFINITY, f64::min);
        report::appendln!(
            out,
            "    note: with observed robust = 0 this best-fit is DEGENERATE -- epsilon = 0 gives mean robust 0 while every epsilon > 0 gives mean robust >= {:.3}, so the argmin is forced to 0. It is a restatement of \"robust count = 0,\" NOT an independent gradient fit. The epsilon axis is QUALITATIVE only: the family has {} synthetic messages vs the eyes' 9, robust counts scale with the message-pair count, and the motif geometry differs.",
            min_positive_mean,
            family.messages
        );
    } else {
        report::appendln!(
            out,
            "    note: the epsilon axis is QUALITATIVE only -- the family has {} synthetic messages vs the eyes' 9, robust counts scale with the message-pair count, and the motif geometry differs.",
            family.messages
        );
    }
}

fn append_verdict_section(out: &mut String, report: &IsomorphImperfectionReport) {
    report::appendln!(out, "verdict");
    report::appendln!(out, "  {}", verdict_line(report));
    report::appendln!(
        out,
        "  Claim ceiling: the eyes remain deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext."
    );
}

fn verdict_line(report: &IsomorphImperfectionReport) -> String {
    let robust = report.extended_counts.robust_internal_violations;
    let promoted = report
        .stutter_candidate
        .is_some_and(|candidate| candidate.promoted_to_violation);
    let fire_at = report
        .family
        .detection_threshold
        .unwrap_or(report.family.high_epsilon);
    if robust == 0 && !promoted {
        format!(
            "HARDENED NEGATIVE: 0 robust non-benign internal violations under extended windows {:?}; every loose candidate is attributed to a named benign desync region and the east4/west4 Stutter candidate does not promote. The binding calibration is the generative epsilon = 0 family (mean robust 0); the within-message shuffle is structure-destroying, so the robust-null add-one p {} at observed 0 is the trivial count floor, not evidence. The imperfect-family detector fires at epsilon >= {:.2}, and the eyes' observed robust 0 trivially places them at epsilon = 0 (a restatement of robust = 0, not an independent fit). Scope: this rules out only imperfections that produce single/double-column islands (<= {}) with a far resync (>= {}) carrying a cross-island back-reference; short-resync (far_run < {}) or wide-island (> {}) imperfections are OUTSIDE the tested envelope. Within that envelope the eyes are NOT FALSIFIED by perfect isomorphism (consistent with it) -> GAK not falsified (mildly strengthened). This does NOT prove the eyes are GAK (XGAK's upper edge is <=, not equality) and is CONDITIONAL on the benign attribution of east4/west4 (and of every loose candidate listed above).",
            report.extended_windows,
            report::format_probability(report.robust_null.p),
            fire_at,
            MAX_ISLAND_COLS,
            POST_MIN,
            POST_MIN,
            MAX_ISLAND_COLS,
        )
    } else if report.robust_null.p <= SIGNIFICANCE_ALPHA {
        format!(
            "FAMILY-EJECTING VIOLATION: {robust} robust non-benign internal violation(s) under extended windows survive the word-boundary discount AND sit in the upper tail of the matched robust null (add-one p {} <= alpha {}); the eyes leave the perfectly-isomorphic family. Caveat: the binding calibration remains the generative epsilon = 0 family, and the falsifier is restricted to single/double-column islands (<= {}) with a far resync (>= {}) -- imperfections outside that envelope are untested.",
            report::format_probability(report.robust_null.p),
            SIGNIFICANCE_ALPHA,
            MAX_ISLAND_COLS,
            POST_MIN,
        )
    } else {
        format!(
            "CANDIDATE VIOLATION REQUIRING FOLLOW-UP: {robust} robust non-benign internal violation(s) survive the word-boundary discount but sit WITHIN the matched robust null (add-one p {} > alpha {}). This does NOT eject the family on its own: the within-message shuffle null is structure-destroying and weak (see the nulls section), so a count inside it is not yet a falsification. Binding calibration is the generative epsilon = 0 family; this break warrants direct follow-up against a structure-preserving null.",
            report::format_probability(report.robust_null.p),
            SIGNIFICANCE_ALPHA,
        )
    }
}
