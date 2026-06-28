//! Gate-2 consistency control: the Thread-3 perfect-isomorphism consultation.
//!
//! Consults Thread 3's scan (REUSED, never re-derived) for the consistency verdict
//! AND the per-message safe isomorph extents Gate-1 chaining is ENFORCED to stay
//! within. The verdict is only trusted when Thread 3's own POSITIVE CONTROL
//! fired, so this is the eyes' consistency-control layer.

use super::super::{GakAttackError, ThreeConsistency, perfect_isomorphism};
use super::EYES_THREE_CONSISTENCY_TRIALS;

/// The Thread-3 consultation: the consistency verdict PLUS the per-message safe
/// isomorph spans Gate-1 chaining is ENFORCED to stay within.
pub(super) struct ThreeConsultation {
    /// The Gate-2 consistency verdict consumed by the report.
    pub(super) verdict: ThreeConsistency,
    /// For each message (in the SAME order as the corpus keys), the half-open safe
    /// spans Thread 3 exported for that message. Gate-1 windows are admitted only
    /// within these spans; an empty inner list means Thread 3 found no safe extent in
    /// that message, so NO Gate-1 window there is admitted.
    pub(super) safe_spans_by_message: Vec<Vec<(usize, usize)>>,
}

/// Consults Thread 3's perfect-isomorphism scan for the consistency gate AND the
/// safe-extent enforcement (REUSE — run ONCE, both products derived from one report).
///
/// Reads the Thread-3 report's `robust_internal_violations` (must be `0` — a
/// non-zero count is a manufactured TRUE conflict), `safe_extents` (the conservative
/// per-message spans Gate-1 chaining is RESTRICTED to), and
/// `positive_control_fired` (the scan is trustworthy). The candidate model is
/// CONSISTENT only if there are zero robust internal violations and the positive
/// control fired. The per-message safe spans are projected from the cross-message
/// extents and returned in `keys` order so Gate 1 can enforce them.
///
/// # Errors
/// Returns [`GakAttackError::PerfectIsomorphism`] if the Thread-3 scan fails.
pub(super) fn eyes_three_consultation(
    keys: &[&'static str],
) -> Result<ThreeConsultation, GakAttackError> {
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
/// in the SAME order as `keys`.
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
