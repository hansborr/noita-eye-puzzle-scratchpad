//! Aggregate metrics for the hidden-base local CLI report.

use std::time::Duration;

use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    HiddenBaseLocalRecoveryReport, HiddenBaseLocalRecoveryState,
};

use super::LocalTrialReport;

pub(super) fn local_state_count(
    trials: &[LocalTrialReport],
    state: HiddenBaseLocalRecoveryState,
) -> usize {
    trials
        .iter()
        .filter(|trial| trial.report.state == state)
        .count()
}

pub(super) fn local_range(
    trials: &[LocalTrialReport],
    value: impl Fn(&HiddenBaseLocalRecoveryReport) -> usize,
) -> Option<(usize, usize)> {
    let mut values = trials.iter().map(|trial| value(&trial.report));
    let first = values.next()?;
    Some(values.fold((first, first), |(min, max), current| {
        (min.min(current), max.max(current))
    }))
}

pub(super) fn optional_local_range(
    trials: &[LocalTrialReport],
    value: impl Fn(&HiddenBaseLocalRecoveryReport) -> Option<usize>,
) -> Option<(usize, usize)> {
    let mut values = trials.iter().filter_map(|trial| value(&trial.report));
    let first = values.next()?;
    Some(values.fold((first, first), |(min, max), current| {
        (min.min(current), max.max(current))
    }))
}

pub(super) fn format_range(range: Option<(usize, usize)>) -> String {
    range.map_or_else(|| "n/a".to_owned(), |(min, max)| format!("{min}/{max}"))
}

pub(super) fn total_elapsed(trials: &[LocalTrialReport]) -> Duration {
    sum_duration(trials, |report| report.elapsed)
}

pub(super) fn top_source_elapsed(trials: &[LocalTrialReport]) -> Duration {
    sum_duration(trials, |report| report.top_source_elapsed)
}

pub(super) fn state_sat_elapsed(trials: &[LocalTrialReport]) -> Duration {
    sum_duration(trials, |report| report.state_sat_elapsed)
}

fn sum_duration(
    trials: &[LocalTrialReport],
    value: impl Fn(&HiddenBaseLocalRecoveryReport) -> Duration,
) -> Duration {
    trials
        .iter()
        .map(|trial| value(&trial.report))
        .fold(Duration::ZERO, Duration::saturating_add)
}

pub(super) fn format_duration(duration: Duration) -> String {
    let micros = duration.as_micros();
    if micros >= 1_000 {
        format!("{}.{:03} ms", micros / 1_000, micros % 1_000)
    } else {
        format!("{micros} us")
    }
}
