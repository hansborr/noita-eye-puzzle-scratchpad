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
use super::{SwapRecoveryError, SwapRecoveryStats, align_pairs};

#[test]
fn ns3_planted_truth_survives_target_cegar_pruning() {
    let spec =
        LymmDeckSpec::from_shift_decimation(13, "ABCDE", &lymm_default_ct_alphabet(13), 4, 5)
            .expect("small Lymm spec");
    let planted = generate_random_pt_mapping(&spec, 3, 0x5a17_0200_0000_0033).expect("ns=3 plant");
    let pairs = encrypted_control_pairs(
        &spec,
        &planted.pt_mapping,
        &[
            ("1", "ABCDEABCDEEDCBA"),
            ("2", "EDCBAABCDEABCDE"),
            ("3", "BADCEDCBAABCDEA"),
        ],
    )
    .expect("encrypted pairs");
    let messages = align_pairs(&spec, &pairs).expect("aligned pairs");

    let mut residual = build_residual_domains(&spec, &messages, 3).expect("ns=3 residual");
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
    let planted_targets = planted_targets(&residual, &planted.pt_mapping);
    assert_planted_candidates_survive("broad", &residual, &planted.pt_mapping);

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
    assert_planted_candidates_survive("target-restricted", &targeted, &planted.pt_mapping);

    let mut targeted_stats = SwapRecoveryStats {
        enumerated_candidates: targeted.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    let _targeted_propagation = propagate_partial_states(
        &spec,
        &messages,
        &mut targeted,
        &mut targeted_stats,
        PropagationOptions::ns2_default(),
    )
    .expect("targeted deterministic propagation must preserve truth");
    assert_planted_candidates_survive("targeted", &targeted, &planted.pt_mapping);

    let assignment = planted_candidate_assignment(&targeted, &planted.pt_mapping);
    assert_eq!(
        verify_candidate_assignment(&spec, &messages, &targeted, &assignment)
            .expect("candidate verification"),
        Ok(()),
        "planted ns=3 candidate assignment no longer exactly re-encrypts"
    );
    assert_eq!(planted_targets.len(), 5);
    assert!(
        domain_entry_count(&targeted) <= broad_entries,
        "targeted ns=3 propagation should not grow residual domains"
    );
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
