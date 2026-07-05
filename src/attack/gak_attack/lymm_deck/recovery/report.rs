//! Recovery report construction helpers.

use std::collections::{BTreeMap, BTreeSet};

use super::residual::ResidualDomains;
use super::{
    AlignedMessage, LetterRecoveryVerdict, RecoveredLetter, RecoveryReport, SwapRecoveryConfig,
    SwapRecoveryError, SwapRecoveryStats, occurrence_counts, pairs_from_messages, report_shell,
    round_trip_check,
};
use crate::attack::gak_attack::lymm_deck::LymmDeckSpec;

pub(super) fn build_report_from_assignment(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
    residual: &ResidualDomains,
    assignment: &BTreeMap<char, usize>,
    stats: SwapRecoveryStats,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let mut occurrences = occurrence_counts(spec, messages);
    let mut used_targets = BTreeSet::new();
    let mut pt_mapping = BTreeMap::new();
    let mut letters = Vec::with_capacity(spec.pt_alphabet.len());
    for &letter in &spec.pt_alphabet {
        let count = occurrences.remove(&letter).unwrap_or(0);
        let candidate_index = assignment
            .get(&letter)
            .copied()
            .or_else(|| {
                residual
                    .by_letter
                    .get(&letter)
                    .and_then(|domain| domain.first().copied())
            })
            .or(Some(0));
        let witness = candidate_index.and_then(|index| residual.witness(index));
        if let Some(found) = &witness {
            let _old = pt_mapping.insert(letter, found.permutation.clone());
        }
        let target = witness.as_ref().map(|found| found.top_image);
        let no_doubles = target.is_none_or(|value| value != 0 && used_targets.insert(value));
        let equivalent_count = residual
            .by_letter
            .get(&letter)
            .map_or(usize::from(witness.is_some()), Vec::len);
        let candidate_permutations =
            residual
                .by_letter
                .get(&letter)
                .map_or_else(Vec::new, |domain| {
                    domain
                        .iter()
                        .filter_map(|&index| residual.witness(index))
                        .map(|candidate| candidate.permutation)
                        .collect()
                });
        let verdict = if count == 0 {
            LetterRecoveryVerdict::NoCandidate
        } else {
            LetterRecoveryVerdict::Candidate
        };
        letters.push(RecoveredLetter {
            letter,
            occurrences: count,
            target,
            support: witness
                .as_ref()
                .map_or_else(Vec::new, |found| found.support.clone()),
            permutation: witness.map(|found| found.permutation),
            candidate_permutations,
            canonical_swaps: candidate_index
                .and_then(|index| residual.witness(index))
                .map_or_else(Vec::new, |found| found.canonical_swaps),
            equivalent_count,
            no_doubles,
            verdict,
        });
    }
    let placeholder = report_shell(config, letters, pt_mapping, stats);
    let pairs = pairs_from_messages(messages);
    let round_trip = round_trip_check(spec, &placeholder, &pairs)?;
    let mut report = placeholder;
    report.round_trip = round_trip;
    classify_exact_residual_report(&mut report);
    Ok(report)
}

fn classify_exact_residual_report(report: &mut RecoveryReport) {
    if !report.round_trip.exact() {
        report.verdict = LetterRecoveryVerdict::Candidate;
        return;
    }

    let mut all_unique = true;
    let mut any_observed = false;
    for letter in &mut report.letters {
        if letter.occurrences == 0 {
            letter.verdict = LetterRecoveryVerdict::NoCandidate;
            continue;
        }
        any_observed = true;
        if letter.equivalent_count == 1 {
            letter.verdict = LetterRecoveryVerdict::RecoveredUnique;
        } else {
            letter.verdict = LetterRecoveryVerdict::RecoveredAmbiguous;
            all_unique = false;
        }
    }
    report.verdict = if any_observed && all_unique {
        LetterRecoveryVerdict::RecoveredUnique
    } else if any_observed {
        LetterRecoveryVerdict::RecoveredAmbiguous
    } else {
        LetterRecoveryVerdict::NoCandidate
    };
}
