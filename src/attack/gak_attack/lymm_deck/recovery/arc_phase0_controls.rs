//! Built-in controls for the Phase-0 arc-provenance instrument.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::arc_phase0::{
    broad_replay_rejects_arc_clause, measure_ns3_arc_provenance, minimize_arc_reason,
};
use super::arc_phase0_types::{
    GakSwapArcControlLeg, GakSwapArcPhase0Config, GakSwapArcPhase0ControlsReport,
    SHORT_CONFLICT_LIMIT,
};
use super::domain_build::build_residual_domains;
use super::domain_oracle::LetterDomainOracle;
use super::propagation::{PropagationOptions, propagate_partial_states};
use super::residual::ResidualDomains;
use super::target_reason::{ArcLiteral, ArcReason};
use super::{
    AlignedMessage, SwapRecoveryConfig, SwapRecoveryError, SwapRecoveryStats, align_pairs,
};
use crate::attack::gak_attack::lymm_deck::{
    KnownPlaintextPair, LymmDeckSpec, encrypt_lymm_deck, generate_random_pt_mapping,
    lymm_default_ct_alphabet,
};

/// Runs the Phase-0 measurement instrument's built-in controls.
///
/// # Errors
/// Returns [`SwapRecoveryError`] when a control fixture cannot be built.
pub fn gak_swap_arc_phase0_controls(
    config: GakSwapArcPhase0Config,
) -> Result<GakSwapArcPhase0ControlsReport, SwapRecoveryError> {
    let positive = run_positive_control(config)?;
    let matched_null = run_matched_null_control(&config)?;
    let matched_null_context = run_context_leak_matched_null_control(&config)?;
    Ok(GakSwapArcPhase0ControlsReport {
        positive,
        matched_null,
        matched_null_context,
    })
}

fn run_positive_control(
    mut config: GakSwapArcPhase0Config,
) -> Result<GakSwapArcControlLeg, SwapRecoveryError> {
    config.max_rejections = 1;
    config.wall_time = Duration::from_secs(30);
    let (spec, pairs) = positive_control_fixture()?;
    let report = measure_ns3_arc_provenance(&spec, &pairs, config)?;
    let Some(first) = report.rejections.first() else {
        return Ok(GakSwapArcControlLeg {
            label: "planted-positive",
            passed: false,
            detail: format!(
                "no deterministic rejection observed; stop={}",
                report.stop.as_str()
            ),
        });
    };
    let passed = first.bin.counts_for_go_rule()
        && first.literal_count <= SHORT_CONFLICT_LIMIT
        && broad_replay_rejects_arc_clause(
            &spec,
            &align_pairs(&spec, &pairs)?,
            &rebuilt_broad_residual(&spec, &pairs)?,
            &first
                .minimized_arc_literals
                .iter()
                .copied()
                .map(ArcLiteral::from)
                .collect::<Vec<_>>(),
            &first.minimized_context_targets,
        )?;
    Ok(GakSwapArcControlLeg {
        label: "planted-positive",
        passed,
        detail: format!(
            "bin={} size{}{} replay_checks={}",
            first.bin.as_str(),
            if first.literal_count_is_upper_bound {
                "<="
            } else {
                "="
            },
            first.literal_count,
            first.replay_checks
        ),
    })
}

fn run_matched_null_control(
    config: &GakSwapArcPhase0Config,
) -> Result<GakSwapArcControlLeg, SwapRecoveryError> {
    let (spec, messages, residual, reason) = known_long_replay_fixture();
    let minimized = minimize_arc_reason(
        &spec,
        &messages,
        &residual,
        &reason,
        config.replays_per_rejection,
    )?;
    let passed =
        minimized.bin.counts_for_go_rule() && minimized.literal_count > SHORT_CONFLICT_LIMIT;
    Ok(GakSwapArcControlLeg {
        label: "matched-null",
        passed,
        detail: format!(
            "known-long minimal reason reported bin={} size{}{} replay_checks={}",
            minimized.bin.as_str(),
            if minimized.literal_count_is_upper_bound {
                "<="
            } else {
                "="
            },
            minimized.literal_count,
            minimized.replay_checks
        ),
    })
}

fn run_context_leak_matched_null_control(
    config: &GakSwapArcPhase0Config,
) -> Result<GakSwapArcControlLeg, SwapRecoveryError> {
    let (spec, messages, residual, reason) = context_leak_replay_fixture();
    let minimized = minimize_arc_reason(
        &spec,
        &messages,
        &residual,
        &reason,
        config.replays_per_rejection,
    )?;
    let would_fake_go =
        minimized.bin.counts_for_go_rule() && minimized.literal_count <= SHORT_CONFLICT_LIMIT;
    Ok(GakSwapArcControlLeg {
        label: "matched-null-context",
        passed: !would_fake_go,
        detail: format!(
            "context-dependent short arcs reported bin={} size{}{} replay_checks={}",
            minimized.bin.as_str(),
            if minimized.literal_count_is_upper_bound {
                "<="
            } else {
                "="
            },
            minimized.literal_count,
            minimized.replay_checks
        ),
    })
}

fn positive_control_fixture() -> Result<(LymmDeckSpec, Vec<KnownPlaintextPair>), SwapRecoveryError>
{
    let spec = LymmDeckSpec::from_shift_decimation(7, "ABC", &lymm_default_ct_alphabet(7), 2, 3)?;
    let planted = generate_random_pt_mapping(&spec, 3, 0x5a17_0200_0100_0002)?;
    let rows = anchored_abc_rows(4);
    let pairs = rows
        .iter()
        .map(|(label, plaintext)| {
            let ciphertext = encrypt_lymm_deck(&spec, &planted.pt_mapping, plaintext)?;
            Ok(KnownPlaintextPair {
                label: label.clone(),
                plaintext: plaintext.clone(),
                ciphertext,
            })
        })
        .collect::<Result<Vec<_>, SwapRecoveryError>>()?;
    Ok((spec, pairs))
}

fn anchored_abc_rows(width: usize) -> Vec<(String, String)> {
    let alphabet = ['A', 'B', 'C'];
    (0..4)
        .map(|offset| {
            let mut plaintext = String::from("A");
            plaintext.push_str(&exhaustive_word_sequence(&alphabet, width, offset));
            ((offset + 1).to_string(), plaintext)
        })
        .collect()
}

fn exhaustive_word_sequence(alphabet: &[char], width: usize, offset: usize) -> String {
    let total = alphabet
        .len()
        .pow(u32::try_from(width).expect("small calibration width"));
    let mut text = String::with_capacity(total.saturating_mul(width));
    for raw in 0..total {
        let mut value = (raw + offset) % total;
        let mut word = Vec::with_capacity(width);
        for _ in 0..width {
            word.push(
                alphabet
                    .get(value % alphabet.len())
                    .copied()
                    .expect("calibration alphabet is nonempty"),
            );
            value /= alphabet.len();
        }
        text.extend(word);
    }
    text
}

fn rebuilt_broad_residual(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
) -> Result<ResidualDomains, SwapRecoveryError> {
    let messages = align_pairs(spec, pairs)?;
    let recovery_config = SwapRecoveryConfig::with_max_swaps(3);
    let mut residual = build_residual_domains(spec, &messages, &recovery_config)?;
    let mut stats = SwapRecoveryStats {
        enumerated_candidates: residual.candidate_count(),
        ..SwapRecoveryStats::default()
    };
    let _propagation = propagate_partial_states(
        spec,
        &messages,
        &mut residual,
        &mut stats,
        PropagationOptions::ns3_broad(),
    )?;
    Ok(residual)
}

fn known_long_replay_fixture() -> (
    LymmDeckSpec,
    Vec<AlignedMessage>,
    ResidualDomains,
    ArcReason,
) {
    let spec = LymmDeckSpec::from_shift_decimation(9, "A", &lymm_default_ct_alphabet(9), 1, 1)
        .expect("known-long fixture spec");
    let arcs = (0..4)
        .map(|index| ArcLiteral {
            letter: 'A',
            post_position: index + 1,
            pre_position: index + 5,
        })
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for missing in 0..arcs.len() {
        let perm = valid_perm_missing_arc(missing);
        candidates.push(control_candidate(
            &spec,
            perm.first()
                .copied()
                .expect("fixture permutation is nonempty"),
            missing,
            &perm,
        ));
    }
    let domains = super::super::TopSwapDomains {
        candidates,
        by_top_image: BTreeMap::new(),
        by_support: BTreeMap::new(),
        branch_strategy: super::super::GeneratorBranchStrategy::TopSwapSupport,
    };
    let residual = ResidualDomains {
        domains,
        oracle: LetterDomainOracle::top_swap(&spec),
        by_letter: BTreeMap::from([('A', vec![0, 1, 2, 3])]),
        letters: vec!['A'],
    };
    let reason = arcs
        .into_iter()
        .fold(ArcReason::default(), |mut reason, literal| {
            reason.union_with(&ArcReason::from_arc(literal));
            reason
        });
    (spec, Vec::new(), residual, reason)
}

fn context_leak_replay_fixture() -> (
    LymmDeckSpec,
    Vec<AlignedMessage>,
    ResidualDomains,
    ArcReason,
) {
    let spec = LymmDeckSpec::from_shift_decimation(9, "A", &lymm_default_ct_alphabet(9), 1, 1)
        .expect("context-leak fixture spec");
    let arcs = (0..3)
        .map(|index| ArcLiteral {
            letter: 'A',
            post_position: index + 1,
            pre_position: index + 4,
        })
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for missing in 0..arcs.len() {
        let perm = valid_perm_for_arc_profile(spec.n, 1, &arcs, Some(missing));
        candidates.push(control_candidate(&spec, 1, missing, &perm));
    }
    let all_arcs_perm = valid_perm_for_arc_profile(spec.n, 2, &arcs, None);
    candidates.push(control_candidate(&spec, 2, arcs.len(), &all_arcs_perm));
    let domains = super::super::TopSwapDomains {
        candidates,
        by_top_image: BTreeMap::new(),
        by_support: BTreeMap::new(),
        branch_strategy: super::super::GeneratorBranchStrategy::TopSwapSupport,
    };
    let residual = ResidualDomains {
        domains,
        oracle: LetterDomainOracle::top_swap(&spec),
        by_letter: BTreeMap::from([('A', vec![0, 1, 2, 3])]),
        letters: vec!['A'],
    };
    let reason = arcs.into_iter().fold(
        ArcReason::from_context_target('A', 1),
        |mut reason, literal| {
            reason.union_with(&ArcReason::from_arc(literal));
            reason
        },
    );
    (spec, Vec::new(), residual, reason)
}

fn control_candidate(
    spec: &LymmDeckSpec,
    top_image: usize,
    canonical_marker: usize,
    perm: &[usize],
) -> super::super::TopSwapCandidate {
    let base_inverse = base_inverse(spec);
    let sigma_images = perm
        .iter()
        .filter_map(|&image| base_inverse.get(image).copied())
        .collect::<Vec<_>>();
    super::super::TopSwapCandidate {
        canonical_swaps: vec![canonical_marker],
        top_image,
        support: (0..spec.n).collect(),
        sigma_images,
        perm_images: perm.to_vec(),
    }
}

fn base_inverse(spec: &LymmDeckSpec) -> Vec<usize> {
    let mut inverse = vec![0usize; spec.n];
    for (position, &image) in spec.base.iter().enumerate() {
        if let Some(slot) = inverse.get_mut(image) {
            *slot = position;
        }
    }
    inverse
}

fn valid_perm_for_arc_profile(
    n: usize,
    target: usize,
    arcs: &[ArcLiteral],
    missing: Option<usize>,
) -> Vec<usize> {
    let mut perm = vec![usize::MAX; n];
    let mut used = BTreeSet::new();
    if let Some(slot) = perm.get_mut(0) {
        *slot = target;
    }
    let _inserted = used.insert(target);
    for (index, literal) in arcs.iter().enumerate() {
        let pre = if missing == Some(index) {
            (0..n)
                .find(|candidate| *candidate != literal.pre_position && !used.contains(candidate))
                .expect("context-leak fixture has a spare preimage")
        } else {
            literal.pre_position
        };
        if let Some(slot) = perm.get_mut(literal.post_position) {
            *slot = pre;
        }
        let _inserted = used.insert(pre);
    }
    let mut unused = (0..n)
        .filter(|value| !used.contains(value))
        .collect::<Vec<_>>();
    for slot in &mut perm {
        if *slot == usize::MAX {
            *slot = unused.remove(0);
        }
    }
    perm
}

fn valid_perm_missing_arc(missing: usize) -> Vec<usize> {
    let mut perm = vec![usize::MAX; 9];
    let mut used = BTreeSet::new();
    if let Some(slot) = perm.get_mut(0) {
        *slot = 1;
    }
    let _inserted = used.insert(1);
    for index in 0..4 {
        let post = index + 1;
        let required_pre = index + 5;
        let pre = if index == missing {
            (0..9)
                .find(|candidate| *candidate != required_pre && !used.contains(candidate))
                .expect("known-long fixture has a spare preimage")
        } else {
            required_pre
        };
        if let Some(slot) = perm.get_mut(post) {
            *slot = pre;
        }
        let _inserted = used.insert(pre);
    }
    let mut unused = (0..9)
        .filter(|value| !used.contains(value))
        .collect::<Vec<_>>();
    for slot in perm.iter_mut().skip(5) {
        *slot = unused.remove(0);
    }
    perm
}

#[cfg(test)]
mod tests {
    use super::{
        context_leak_replay_fixture, gak_swap_arc_phase0_controls, measure_ns3_arc_provenance,
        minimize_arc_reason, positive_control_fixture,
    };
    use crate::attack::gak_attack::lymm_deck::recovery::arc_phase0_types::{
        GakSwapArcPhase0Config, GakSwapArcPhase0Stop, SHORT_CONFLICT_LIMIT,
    };

    #[test]
    fn phase0_arc_controls_pass() {
        let report = gak_swap_arc_phase0_controls(GakSwapArcPhase0Config {
            max_rejections: 1,
            replays_per_rejection: 32,
            ..GakSwapArcPhase0Config::default()
        })
        .expect("phase-0 controls must run");
        assert!(
            report.passed(),
            "phase-0 controls failed: positive={:?} null={:?} context_null={:?}",
            report.positive,
            report.matched_null,
            report.matched_null_context
        );
    }

    #[test]
    fn planted_positive_extracts_short_arc_reason() {
        let (spec, pairs) = positive_control_fixture().expect("positive fixture");
        let report = measure_ns3_arc_provenance(
            &spec,
            &pairs,
            GakSwapArcPhase0Config {
                max_rejections: 1,
                replays_per_rejection: 32,
                ..GakSwapArcPhase0Config::default()
            },
        )
        .expect("positive measurement must run");
        assert_eq!(report.stop, GakSwapArcPhase0Stop::RejectionCap);
        let first = report
            .rejections
            .first()
            .expect("positive must produce one rejection");
        assert!(first.bin.counts_for_go_rule(), "{first:?}");
        assert!(
            !first.minimized_arc_literals.is_empty(),
            "positive must minimize to at least one transition-arc literal: {first:?}"
        );
        assert!(first.literal_count <= SHORT_CONFLICT_LIMIT, "{first:?}");
        assert!(
            first.replay_checks <= 32,
            "positive exceeded replay cap: {first:?}"
        );
    }

    #[test]
    fn context_leak_null_does_not_count_as_short_go_conflict() {
        let (spec, messages, residual, reason) = context_leak_replay_fixture();
        let minimized =
            minimize_arc_reason(&spec, &messages, &residual, &reason, 32).expect("minimize null");
        assert!(
            !(minimized.bin.counts_for_go_rule()
                && minimized.literal_count <= SHORT_CONFLICT_LIMIT),
            "context-dependent arcs must not fake a short go conflict: {minimized:?}"
        );
        assert_eq!(minimized.bin.as_str(), "context-expressible");
        assert_eq!(minimized.arcs.len(), SHORT_CONFLICT_LIMIT);
        assert_eq!(minimized.context_targets, vec![('A', 1)]);
        assert_eq!(minimized.literal_count, SHORT_CONFLICT_LIMIT + 1);
    }
}
