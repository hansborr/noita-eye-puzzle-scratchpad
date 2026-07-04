use std::collections::{BTreeMap, BTreeSet};

use super::super::{
    KnownPlaintextPair, LymmDeckSpec, encrypt_lymm_deck, generate_random_pt_mapping,
    lymm_default_ct_alphabet,
};
use super::propagation::{PropagationOptions, propagate_partial_states};
use super::residual::{
    ResidualDomains, build_residual_domains, restrict_to_targets, verify_candidate_assignment,
};
use super::target_solver::TargetAssignmentSolver;
use super::{
    LetterRecoveryVerdict, RecoveryReport, SwapRecoveryConfig, SwapRecoveryError,
    SwapRecoveryStats, align_pairs, recover_known_plaintext_swaps,
};

#[test]
fn ns3_planted_control_recovers_through_production_path() {
    let (spec, planted, pairs) = small_ns3_control();
    let mut config = SwapRecoveryConfig::with_max_swaps(3).with_planted_truth(planted.clone());
    config.max_nodes = Some(20_000);

    let report = recover_known_plaintext_swaps(&spec, &pairs, config)
        .expect("small planted ns=3 control must recover through production path");

    assert!(report.round_trip.exact());
    assert_eq!(report.round_trip.matched, report.round_trip.total);
    assert!(
        report.stats.truth_preservation_checks
            >= report
                .stats
                .target_clauses_learned
                .saturating_add(report.stats.candidate_clauses_learned),
        "every learned clause in the planted control must pass truth tracking"
    );
    assert!(
        !report.stats.measured_target_domain_entries.is_empty(),
        "planted ns=3 control must record the target-slice residual measurement"
    );
    assert_eq!(
        report.stats.measured_target_total_entries,
        report
            .stats
            .measured_target_domain_entries
            .iter()
            .map(|&(_letter, count)| count)
            .sum()
    );
    eprintln!(
        "small ns=3 target-slice residual: total={} max={} per-letter={:?}",
        report.stats.measured_target_total_entries,
        report.stats.measured_target_max_domain,
        report.stats.measured_target_domain_entries
    );
    assert_report_preserves_planted_membership(&report, &planted);
}

#[test]
fn ns3_planted_truth_survives_target_cegar_pruning() {
    let (spec, planted, pairs) = small_ns3_control();
    let messages = align_pairs(&spec, &pairs).expect("aligned pairs");

    let config = SwapRecoveryConfig::with_max_swaps(3);
    let mut residual = build_residual_domains(&spec, &messages, &config).expect("ns=3 residual");
    let mut broad_stats = SwapRecoveryStats {
        enumerated_candidates: residual.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    let broad = propagate_partial_states(
        &spec,
        &messages,
        &mut residual,
        &mut broad_stats,
        PropagationOptions::ns3_broad(),
    )
    .expect("broad ns=3 propagation must preserve truth");
    let planted_targets = planted_targets(&residual, &planted);
    assert_planted_candidates_survive("broad", &residual, &planted);

    let mut target_solver =
        TargetAssignmentSolver::new(&spec, &messages, &broad.state_domains, &residual);
    assert!(
        target_solver
            .assignment_is_satisfiable(&planted_targets)
            .expect("planted target assignment check"),
        "target SAT pre-solver rejected the planted ns=3 targets"
    );

    let broad_entries = domain_entry_count(&residual);
    let mut targeted = residual.clone();
    restrict_to_targets(&mut targeted, &planted_targets).expect("restrict planted targets");
    assert_planted_candidates_survive("target-restricted", &targeted, &planted);

    let mut targeted_stats = SwapRecoveryStats {
        enumerated_candidates: targeted.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    let _targeted_propagation = propagate_partial_states(
        &spec,
        &messages,
        &mut targeted,
        &mut targeted_stats,
        PropagationOptions {
            max_passes: 2,
            exhaustive_arc: false,
        },
    )
    .expect("targeted deterministic propagation must preserve truth");
    assert_planted_candidates_survive("targeted", &targeted, &planted);

    let assignment = planted_candidate_assignment(&targeted, &planted);
    assert_eq!(
        verify_candidate_assignment(&spec, &messages, &targeted, &assignment)
            .expect("candidate verification"),
        Ok(()),
        "planted ns=3 candidate assignment no longer exactly re-encrypts"
    );
    assert_eq!(planted_targets.len(), 3);
    assert!(
        domain_entry_count(&targeted) <= broad_entries,
        "targeted ns=3 propagation should not grow residual domains"
    );
}

fn small_ns3_control() -> (
    LymmDeckSpec,
    BTreeMap<char, Vec<usize>>,
    Vec<KnownPlaintextPair>,
) {
    let spec = LymmDeckSpec::from_shift_decimation(7, "ABC", &lymm_default_ct_alphabet(7), 2, 3)
        .expect("small Lymm spec");
    let planted = generate_random_pt_mapping(&spec, 3, 0x5a17_0200_0000_0033).expect("ns=3 plant");
    let pairs = encrypted_control_pairs(
        &spec,
        &planted.pt_mapping,
        &[("1", "ABCABCACB"), ("2", "CBAABCACB"), ("3", "BACCBACAB")],
    )
    .expect("encrypted pairs");
    (spec, planted.pt_mapping, pairs)
}

fn encrypted_control_pairs(
    spec: &LymmDeckSpec,
    mapping: &BTreeMap<char, Vec<usize>>,
    rows: &[(&str, &str)],
) -> Result<Vec<KnownPlaintextPair>, SwapRecoveryError> {
    rows.iter()
        .map(|&(label, plaintext)| {
            let ciphertext = encrypt_lymm_deck(spec, mapping, plaintext)?;
            Ok(KnownPlaintextPair {
                label: label.to_owned(),
                plaintext: plaintext.to_owned(),
                ciphertext,
            })
        })
        .collect()
}

fn planted_targets(
    residual: &ResidualDomains,
    planted: &BTreeMap<char, Vec<usize>>,
) -> BTreeMap<char, usize> {
    let mut targets = BTreeMap::new();
    let mut used = BTreeSet::new();
    for &letter in &residual.letters {
        let target = planted
            .get(&letter)
            .and_then(|perm| perm.first().copied())
            .expect("observed planted letter");
        assert_ne!(target, 0, "planted target for {letter} must be nonzero");
        assert!(
            used.insert(target),
            "planted target {target} for {letter} must be distinct"
        );
        let _old = targets.insert(letter, target);
    }
    targets
}

fn assert_planted_candidates_survive(
    label: &str,
    residual: &ResidualDomains,
    planted: &BTreeMap<char, Vec<usize>>,
) {
    for &letter in &residual.letters {
        let planted_perm = planted.get(&letter).expect("observed planted letter");
        let survived = residual
            .by_letter
            .get(&letter)
            .into_iter()
            .flat_map(|domain| domain.iter().copied())
            .any(|candidate_index| {
                residual
                    .candidates
                    .get(candidate_index)
                    .is_some_and(|candidate| &candidate.perm == planted_perm)
            });
        assert!(
            survived,
            "{label} ns=3 pruning dropped the planted candidate for {letter}"
        );
    }
}

fn planted_candidate_assignment(
    residual: &ResidualDomains,
    planted: &BTreeMap<char, Vec<usize>>,
) -> BTreeMap<char, usize> {
    residual
        .letters
        .iter()
        .map(|&letter| {
            let planted_perm = planted.get(&letter).expect("observed planted letter");
            let candidate_index = residual
                .by_letter
                .get(&letter)
                .into_iter()
                .flat_map(|domain| domain.iter().copied())
                .find(|&candidate_index| {
                    residual
                        .candidates
                        .get(candidate_index)
                        .is_some_and(|candidate| &candidate.perm == planted_perm)
                })
                .expect("planted candidate survived");
            (letter, candidate_index)
        })
        .collect()
}

fn domain_entry_count(residual: &ResidualDomains) -> usize {
    residual.by_letter.values().map(Vec::len).sum()
}

fn assert_report_preserves_planted_membership(
    report: &RecoveryReport,
    planted: &BTreeMap<char, Vec<usize>>,
) {
    for letter in &report.letters {
        if letter.occurrences == 0 {
            continue;
        }
        let planted_perm = planted
            .get(&letter.letter)
            .expect("observed control letter must be planted");
        match letter.verdict {
            LetterRecoveryVerdict::RecoveredUnique => assert_eq!(
                letter.permutation.as_ref(),
                Some(planted_perm),
                "unique ns=3 control recovery for {} must equal the plant",
                letter.letter
            ),
            LetterRecoveryVerdict::RecoveredAmbiguous => assert!(
                letter
                    .candidate_permutations
                    .iter()
                    .any(|candidate| candidate == planted_perm),
                "ambiguous ns=3 control recovery for {} must include the plant",
                letter.letter
            ),
            LetterRecoveryVerdict::Candidate | LetterRecoveryVerdict::NoCandidate => {
                panic!(
                    "observed ns=3 control letter {} did not earn recovered verdict",
                    letter.letter
                );
            }
        }
    }
}
