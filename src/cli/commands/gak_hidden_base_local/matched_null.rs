//! Matched-null rendering for the hidden-base local CLI report.

use std::fmt::Write as _;
use std::time::Duration;

use noita_eye_puzzle::attack::gak_attack::lymm_deck::HiddenBaseLocalRecoveryState;

use super::metrics::{format_duration, format_range};
use super::{LocalTrialReport, MatchedNullTrialReport};

pub(super) fn append_matched_null_surface(out: &mut String, trials: &[LocalTrialReport]) {
    let null_trials = trials
        .iter()
        .filter_map(|trial| trial.matched_null.as_ref())
        .count();
    if null_trials == 0 {
        writeln!(out, "matched post-anchor label-shuffle null: not run").expect("write to String");
        return;
    }
    let exact = trials
        .iter()
        .filter_map(|trial| trial.matched_null.as_ref())
        .filter(|trial| trial.report.has_exact_recovery())
        .count();
    writeln!(
        out,
        "matched post-anchor label-shuffle null: trials={} exact={} changed-symbols min/max={} states equivalent-key={} ambiguous={} no-candidate={} search-cap={}",
        null_trials,
        exact,
        format_range(null_range(trials, |trial| trial.changed_symbols)),
        state_count(trials, HiddenBaseLocalRecoveryState::RecoveredEquivalentKey),
        state_count(trials, HiddenBaseLocalRecoveryState::AmbiguousEquivalentClass),
        state_count(trials, HiddenBaseLocalRecoveryState::NoCandidate),
        state_count(trials, HiddenBaseLocalRecoveryState::SearchCapExceeded)
    )
    .expect("write to String");
    writeln!(
        out,
        "matched null work: retained min/max={} state-sat-hypotheses min/max={} unsat min/max={} variables min/max={} clauses min/max={} replay-events min/max={} elapsed-total={}",
        format_range(null_range(trials, |trial| {
            trial.report.top_source_hypotheses_retained
        })),
        format_range(null_range(trials, |trial| {
            trial.report.state_sat_hypotheses_attempted
        })),
        format_range(null_range(trials, |trial| {
            trial.report.state_sat_hypotheses_unsat
        })),
        format_range(null_range(trials, |trial| trial.report.state_sat_variables)),
        format_range(null_range(trials, |trial| trial.report.state_sat_clauses)),
        format_range(null_range(trials, |trial| {
            trial.report.state_sat_replay_event_evaluations
        })),
        format_duration(
            trials
                .iter()
                .filter_map(|trial| trial.matched_null.as_ref())
                .map(|trial| trial.report.elapsed)
                .fold(Duration::ZERO, Duration::saturating_add)
        )
    )
    .expect("write to String");
}

fn state_count(trials: &[LocalTrialReport], state: HiddenBaseLocalRecoveryState) -> usize {
    trials
        .iter()
        .filter_map(|trial| trial.matched_null.as_ref())
        .filter(|trial| trial.report.state == state)
        .count()
}

fn null_range(
    trials: &[LocalTrialReport],
    value: impl Fn(&MatchedNullTrialReport) -> usize,
) -> Option<(usize, usize)> {
    let mut values = trials
        .iter()
        .filter_map(|trial| trial.matched_null.as_ref())
        .map(value);
    let first = values.next()?;
    Some(values.fold((first, first), |(min, max), current| {
        (min.min(current), max.max(current))
    }))
}
