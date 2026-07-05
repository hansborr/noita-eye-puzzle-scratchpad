//! Implicit candidate-permutation oracle for residual letter domains.

use super::super::{GeneratorBranchStrategy, LymmDeckSpec, TopSwapCandidate, TopSwapDomains};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LetterDomainOracleBackend {
    TopSwap,
    ExplicitGeneratorMitm,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CandidateWitness {
    pub(super) permutation: Vec<usize>,
    pub(super) top_image: usize,
    pub(super) support: Vec<usize>,
    pub(super) canonical_swaps: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LetterDomainOracle {
    backend: LetterDomainOracleBackend,
    n: usize,
    base: Vec<usize>,
    base_inverse: Vec<usize>,
}

impl LetterDomainOracle {
    pub(super) fn top_swap(spec: &LymmDeckSpec) -> Self {
        Self::new(spec, LetterDomainOracleBackend::TopSwap)
    }

    pub(super) fn explicit_generator_mitm(spec: &LymmDeckSpec) -> Self {
        Self::new(spec, LetterDomainOracleBackend::ExplicitGeneratorMitm)
    }

    pub(super) fn for_domains(spec: &LymmDeckSpec, domains: &TopSwapDomains) -> Self {
        match domains.branch_strategy {
            GeneratorBranchStrategy::TopSwapSupport => Self::top_swap(spec),
            GeneratorBranchStrategy::SmallTranspositionSupport
            | GeneratorBranchStrategy::WordMitm { .. } => Self::explicit_generator_mitm(spec),
        }
    }

    #[cfg(test)]
    pub(super) const fn backend(&self) -> LetterDomainOracleBackend {
        self.backend
    }

    pub(super) fn image_mask(
        &self,
        domains: &TopSwapDomains,
        candidate_index: usize,
        input_positions: u128,
    ) -> u128 {
        let Some(candidate) = domains.candidates.get(candidate_index) else {
            return 0;
        };
        let mut mask = 0u128;
        for input_position in bit_positions(input_positions) {
            if let Some(output_position) = self.candidate_value(candidate, input_position) {
                mask |= bit(output_position);
            }
        }
        mask
    }

    pub(super) fn preimage_mask(
        &self,
        domains: &TopSwapDomains,
        candidate_index: usize,
        image_positions: u128,
    ) -> u128 {
        let Some(candidate) = domains.candidates.get(candidate_index) else {
            return 0;
        };
        let mut mask = 0u128;
        for image_position in bit_positions(image_positions) {
            let Some(&sigma_image) = self.base_inverse.get(image_position) else {
                continue;
            };
            let candidate_position = candidate
                .support
                .iter()
                .zip(&candidate.sigma_images)
                .find_map(|(&support_position, &image)| {
                    (image == sigma_image).then_some(support_position)
                })
                .unwrap_or(sigma_image);
            mask |= bit(candidate_position);
        }
        mask
    }

    pub(super) fn transition_possible(
        &self,
        domains: &TopSwapDomains,
        candidate_index: usize,
        post_position: usize,
        pre_position: usize,
    ) -> bool {
        domains
            .candidates
            .get(candidate_index)
            .and_then(|candidate| self.candidate_value(candidate, post_position))
            == Some(pre_position)
    }

    pub(super) fn witness(
        &self,
        domains: &TopSwapDomains,
        candidate_index: usize,
    ) -> Option<CandidateWitness> {
        let candidate = domains.candidates.get(candidate_index)?;
        let permutation = (0..self.n)
            .map(|position| self.candidate_value(candidate, position))
            .collect::<Option<Vec<_>>>()?;
        Some(CandidateWitness {
            permutation,
            top_image: candidate.top_image,
            support: candidate.support.clone(),
            canonical_swaps: candidate.canonical_swaps.clone(),
        })
    }

    pub(super) fn candidate_value(
        &self,
        candidate: &TopSwapCandidate,
        position: usize,
    ) -> Option<usize> {
        if position >= self.n {
            return None;
        }
        let sigma_image = candidate
            .support
            .iter()
            .zip(&candidate.sigma_images)
            .find_map(|(&support_position, &image)| (support_position == position).then_some(image))
            .unwrap_or(position);
        self.base.get(sigma_image).copied()
    }

    fn new(spec: &LymmDeckSpec, backend: LetterDomainOracleBackend) -> Self {
        let mut base_inverse = vec![0usize; spec.n];
        for (position, &image) in spec.base.iter().enumerate() {
            if let Some(slot) = base_inverse.get_mut(image) {
                *slot = position;
            }
        }
        Self {
            backend,
            n: spec.n,
            base: spec.base.clone(),
            base_inverse,
        }
    }
}

pub(super) fn bit(position: usize) -> u128 {
    1u128 << position
}

pub(super) fn bit_positions(mut mask: u128) -> impl Iterator<Item = usize> {
    std::iter::from_fn(move || {
        if mask == 0 {
            return None;
        }
        let bit = mask & mask.wrapping_neg();
        mask &= !bit;
        Some(bit.trailing_zeros() as usize)
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{LetterDomainOracle, LetterDomainOracleBackend, bit, bit_positions};
    use crate::attack::gak_attack::lymm_deck::recovery::{
        RecoveryGeneratorSet, SwapRecoveryConfig, align_pairs,
    };
    use crate::attack::gak_attack::lymm_deck::{
        KnownPlaintextPair, LymmDeckSpec, LymmGeneratorSet, TopSwapConstraints, TopSwapDomains,
        compose_lymm, encrypt_lymm_deck, enumerate_generator_domains, enumerate_top_swap_domains,
        generate_random_pt_mapping, lymm_default_ct_alphabet,
    };

    #[test]
    fn top_swap_oracle_matches_materialized_ns1_ns2_frontier() {
        for max_swaps in 1..=2 {
            for n in 2..=17 {
                assert_top_swap_oracle_matches_materialized(n, max_swaps);
            }
            assert_top_swap_oracle_matches_materialized(83, max_swaps);
        }
    }

    #[test]
    fn top_swap_oracle_matches_materialized_small_ns3_and_planted_control() {
        for n in 3..=9 {
            assert_top_swap_oracle_matches_materialized(n, 3);
        }

        let (spec, pairs) = planted_ns3_control();
        let messages = align_pairs(&spec, &pairs).expect("aligned planted ns=3 control");
        let residual = super::super::domain_build::build_residual_domains(
            &spec,
            &messages,
            &SwapRecoveryConfig::with_max_swaps(3),
        )
        .expect("planted ns=3 residual");
        assert_eq!(
            residual.oracle.backend(),
            LetterDomainOracleBackend::TopSwap
        );
        assert_oracle_matches_materialized(
            &spec,
            &residual.domains,
            &residual.oracle,
            residual
                .by_letter
                .values()
                .flat_map(|domain| domain.iter().copied()),
        );
    }

    #[test]
    fn explicit_mitm_oracle_matches_materialized_noncommuting_split_forced_domains() {
        let spec = identity_spec(7, "ABC");
        let generator_set = noncommuting_generator_set(spec.n);
        assert_generators_do_not_commute(&generator_set);

        let constraints = TopSwapConstraints::up_to(2);
        let full_domains =
            enumerate_generator_domains(&spec, &generator_set, &constraints).expect("MITM domain");
        assert!(matches!(
            full_domains.branch_strategy,
            crate::attack::gak_attack::lymm_deck::GeneratorBranchStrategy::WordMitm { split: 1 }
        ));
        assert!(
            full_domains
                .candidates
                .iter()
                .any(|candidate| candidate.canonical_swaps.len() == 2)
        );

        let full_oracle = LetterDomainOracle::for_domains(&spec, &full_domains);
        assert_eq!(
            full_oracle.backend(),
            LetterDomainOracleBackend::ExplicitGeneratorMitm
        );
        assert_oracle_matches_materialized(
            &spec,
            &full_domains,
            &full_oracle,
            0..full_domains.candidates.len(),
        );

        let planted = planted_len2_mapping(&spec, &full_domains);
        let pairs = encrypted_pairs(
            &spec,
            &planted,
            &[("a", "ABCAB"), ("b", "BCABC"), ("c", "CABCA")],
        );
        let messages = align_pairs(&spec, &pairs).expect("aligned explicit MITM control");
        let residual = super::super::domain_build::build_residual_domains(
            &spec,
            &messages,
            &SwapRecoveryConfig::with_max_swaps(2)
                .with_generator_set(RecoveryGeneratorSet::Explicit(generator_set)),
        )
        .expect("explicit MITM residual");

        assert_eq!(
            residual.oracle.backend(),
            LetterDomainOracleBackend::ExplicitGeneratorMitm
        );
        assert!(matches!(
            residual.domains.branch_strategy,
            crate::attack::gak_attack::lymm_deck::GeneratorBranchStrategy::WordMitm { split: 1 }
        ));
        assert!(residual.candidate_count() < full_domains.candidates.len());
        assert!(
            residual
                .by_letter
                .values()
                .all(|domain| !domain.is_empty() && domain.len() < full_domains.candidates.len())
        );
        assert!(
            residual
                .by_letter
                .values()
                .flat_map(|domain| domain.iter().copied())
                .any(|index| residual
                    .domains
                    .candidates
                    .get(index)
                    .is_some_and(|candidate| candidate.canonical_swaps.len() == 2))
        );
        assert_oracle_matches_materialized(
            &spec,
            &residual.domains,
            &residual.oracle,
            residual
                .by_letter
                .values()
                .flat_map(|domain| domain.iter().copied()),
        );
    }

    fn assert_top_swap_oracle_matches_materialized(n: usize, max_swaps: usize) {
        let spec = LymmDeckSpec::from_shift_decimation(
            n,
            "ABC",
            &lymm_default_ct_alphabet(n),
            n.saturating_sub(1),
            1,
        )
        .expect("top-swap gate spec");
        let domains = enumerate_top_swap_domains(&spec, &TopSwapConstraints::up_to(max_swaps))
            .expect("top-swap domains");
        let oracle = LetterDomainOracle::for_domains(&spec, &domains);
        assert_eq!(oracle.backend(), LetterDomainOracleBackend::TopSwap);
        assert_oracle_matches_materialized(&spec, &domains, &oracle, 0..domains.candidates.len());
    }

    fn assert_oracle_matches_materialized(
        spec: &LymmDeckSpec,
        domains: &TopSwapDomains,
        oracle: &LetterDomainOracle,
        candidate_indexes: impl IntoIterator<Item = usize>,
    ) {
        let mut indexes = candidate_indexes.into_iter().collect::<Vec<_>>();
        indexes.sort_unstable();
        indexes.dedup();
        for candidate_index in indexes {
            let candidate = domains
                .candidates
                .get(candidate_index)
                .expect("candidate index in domain");
            let materialized = candidate.permutation(spec);
            let witness = oracle
                .witness(domains, candidate_index)
                .expect("oracle witness");
            assert_eq!(witness.permutation, materialized);
            assert_eq!(
                Some(witness.top_image),
                materialized.get(spec.emit_index).copied()
            );
            assert_eq!(witness.support, candidate.support);
            assert_eq!(witness.canonical_swaps, candidate.canonical_swaps);

            for mask in mask_suite(spec.n) {
                assert_eq!(
                    oracle.image_mask(domains, candidate_index, mask),
                    materialized_image_mask(&materialized, mask),
                    "image mask mismatch candidate={candidate_index} mask={mask:#x}"
                );
                assert_eq!(
                    oracle.preimage_mask(domains, candidate_index, mask),
                    materialized_preimage_mask(&materialized, mask),
                    "preimage mask mismatch candidate={candidate_index} mask={mask:#x}"
                );
            }

            for (post_position, &materialized_pre) in materialized.iter().enumerate() {
                for pre_position in 0..spec.n {
                    assert_eq!(
                        oracle.transition_possible(
                            domains,
                            candidate_index,
                            post_position,
                            pre_position,
                        ),
                        materialized_pre == pre_position,
                        "transition mismatch candidate={candidate_index} post={post_position} pre={pre_position}"
                    );
                }
            }
        }
    }

    fn mask_suite(n: usize) -> Vec<u128> {
        let full = if n >= u128::BITS as usize {
            u128::MAX
        } else {
            (1u128 << n) - 1
        };
        let mut masks = vec![0, full];
        masks.extend((0..n).map(bit));
        masks.push(
            (0..n)
                .step_by(2)
                .fold(0, |acc, position| acc | bit(position)),
        );
        masks.push(
            (1..n)
                .step_by(2)
                .fold(0, |acc, position| acc | bit(position)),
        );
        masks.sort_unstable();
        masks.dedup();
        masks
    }

    fn materialized_image_mask(perm: &[usize], input_positions: u128) -> u128 {
        bit_positions(input_positions)
            .filter_map(|input_position| perm.get(input_position).copied())
            .fold(0, |acc, output_position| acc | bit(output_position))
    }

    fn materialized_preimage_mask(perm: &[usize], image_positions: u128) -> u128 {
        perm.iter()
            .copied()
            .enumerate()
            .filter_map(|(position, image)| (image_positions & bit(image) != 0).then_some(position))
            .fold(0, |acc, position| acc | bit(position))
    }

    fn planted_ns3_control() -> (LymmDeckSpec, Vec<KnownPlaintextPair>) {
        let spec =
            LymmDeckSpec::from_shift_decimation(7, "ABC", &lymm_default_ct_alphabet(7), 2, 3)
                .expect("small Lymm spec");
        let planted =
            generate_random_pt_mapping(&spec, 3, 0x5a17_0200_0000_0033).expect("ns=3 plant");
        let pairs = encrypted_pairs(
            &spec,
            &planted.pt_mapping,
            &[("1", "ABCABCACB"), ("2", "CBAABCACB"), ("3", "BACCBACAB")],
        );
        (spec, pairs)
    }

    fn noncommuting_generator_set(n: usize) -> LymmGeneratorSet {
        LymmGeneratorSet::from_permutations(
            n,
            vec![
                transposition(n, 0, 1),
                vec![1, 2, 0, 3, 4, 5, 6],
                vec![3, 1, 2, 4, 0, 5, 6],
            ],
        )
        .expect("noncommuting generator set")
    }

    fn assert_generators_do_not_commute(generator_set: &LymmGeneratorSet) {
        let first = generator_set.permutation(0).expect("first generator");
        let second = generator_set.permutation(1).expect("second generator");
        assert_ne!(
            compose_lymm(first, second).expect("left composition"),
            compose_lymm(second, first).expect("right composition")
        );
    }

    fn planted_len2_mapping(
        spec: &LymmDeckSpec,
        domains: &TopSwapDomains,
    ) -> BTreeMap<char, Vec<usize>> {
        let mut mapping = BTreeMap::new();
        let mut used_targets = Vec::new();
        for &letter in &['A', 'B', 'C'] {
            let candidate = domains
                .candidates
                .iter()
                .find(|candidate| {
                    candidate.canonical_swaps.len() == 2
                        && candidate.top_image != 0
                        && !used_targets.contains(&candidate.top_image)
                })
                .expect("enough distinct length-2 candidates");
            used_targets.push(candidate.top_image);
            let _old = mapping.insert(letter, candidate.permutation(spec));
        }
        mapping
    }

    fn identity_spec(n: usize, pt_alphabet: &str) -> LymmDeckSpec {
        LymmDeckSpec::from_base(
            n,
            pt_alphabet,
            &lymm_default_ct_alphabet(n),
            (0..n).collect(),
        )
        .expect("identity spec")
    }

    fn transposition(n: usize, left: usize, right: usize) -> Vec<usize> {
        let mut permutation = (0..n).collect::<Vec<_>>();
        permutation.swap(left, right);
        permutation
    }

    fn encrypted_pairs(
        spec: &LymmDeckSpec,
        mapping: &BTreeMap<char, Vec<usize>>,
        rows: &[(&str, &str)],
    ) -> Vec<KnownPlaintextPair> {
        rows.iter()
            .map(|&(label, plaintext)| KnownPlaintextPair {
                label: label.to_owned(),
                plaintext: plaintext.to_owned(),
                ciphertext: encrypt_lymm_deck(spec, mapping, plaintext).expect("encrypt"),
            })
            .collect()
    }
}
