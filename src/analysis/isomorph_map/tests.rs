//! Tests for equality-pattern span detection and trimmed column-map extraction.

use std::collections::BTreeMap;

use super::{
    ColumnMap, DEFAULT_CLOSURE_CAP, DEFAULT_MIN_SPAN_LEN, DEFAULT_NULL_TRIALS, DEFAULT_SEED,
    DEFAULT_TOP_K, DEFAULT_TRIM, MapKind, PatternSpan, close_full_maps, extract_column_map,
    find_pattern_spans, isomorph_map_scan, validate_chains,
};
use crate::nulls::null::{SplitMix64, random_index_below};

#[test]
fn pattern_isomorph_allows_relabeling_not_literal_repeat() {
    let mut stream = vec![9, 9, 9, 9];
    let first = [0, 1, 2, 3, 4, 5, 0, 2];
    let second = [2, 0, 4, 1, 5, 3, 2, 4];
    stream.extend(first);
    stream.extend([8, 8, 8]);
    let second_start = stream.len();
    stream.extend(second);
    stream.extend([7, 7, 7]);

    let spans = find_pattern_spans(&stream, 10, first.len(), 4);
    assert!(
        spans.iter().any(|span| {
            span.gap == second_start - 4
                && span.first <= 4
                && span.first + span.length >= 4 + first.len()
        }),
        "relabelled span should be detected, allowing boundary overextension: {spans:?}"
    );

    let map = extract_column_map(
        &stream,
        10,
        PatternSpan {
            length: 8,
            first: 4,
            second: second_start,
            gap: second_start - 4,
        },
        0,
    )
    .expect("map extracts");
    assert_eq!(map.kind, MapKind::Partial);
    assert_eq!(map.mapping.first(), Some(&Some(2)));
    assert_eq!(map.mapping.get(1), Some(&Some(0)));
    assert_eq!(map.mapping.get(2), Some(&Some(4)));
    assert_eq!(map.mapping.get(5), Some(&Some(3)));
}

#[test]
fn full_map_is_classified_when_trimmed_core_covers_alphabet() {
    let stream = [0, 1, 2, 3, 4, 5, 0, 2, 2, 0, 4, 1, 5, 3, 2, 4];
    let map = extract_column_map(
        &stream,
        6,
        PatternSpan {
            length: 8,
            first: 0,
            second: 8,
            gap: 8,
        },
        0,
    )
    .expect("map extracts");
    assert_eq!(map.kind, MapKind::Full);
    assert_eq!(map.permutation, Some(vec![2, 0, 4, 1, 5, 3]));
}

#[test]
fn boundary_trim_drops_poisoned_edge_positions() {
    // The outer positions are pattern-compatible and would complete a fake full
    // map with 5->0. Trimming one symbol per side leaves the honest core map
    // over 0..4 and reports the deliberate boundary drop.
    let stream = [5, 0, 1, 2, 3, 4, 0, 1, 5, 0, 1, 2, 3, 4, 5, 1, 2, 0];
    let untrimmed = extract_column_map(
        &stream,
        6,
        PatternSpan {
            length: 9,
            first: 0,
            second: 9,
            gap: 9,
        },
        0,
    )
    .expect("untrimmed map extracts");
    assert_eq!(untrimmed.kind, MapKind::Full);
    assert_eq!(untrimmed.permutation, Some(vec![1, 2, 3, 4, 5, 0]));

    let trimmed = extract_column_map(
        &stream,
        6,
        PatternSpan {
            length: 9,
            first: 0,
            second: 9,
            gap: 9,
        },
        1,
    )
    .expect("trimmed map extracts");
    assert_eq!(trimmed.kind, MapKind::Partial);
    assert_eq!(trimmed.mapping.get(5), Some(&None));
    assert_eq!(trimmed.boundary_positions_dropped, 2);
    assert_eq!(trimmed.core_len, 7);
}

#[test]
fn planted_pattern_clears_markov_null_and_extracts_full_map() {
    const ALPHABET: usize = 8;
    const LEN: usize = 56;
    let permutation = [3, 6, 1, 7, 0, 5, 2, 4];
    let mut rng = SplitMix64::new(0xfeed_face_cafe_beef);
    let mut stream: Vec<u16> = (0..260)
        .map(|_| u16::try_from(random_index_below(ALPHABET, &mut rng).expect("draw")).unwrap_or(0))
        .collect();
    let first = 24usize;
    let second = 170usize;
    for offset in 0..LEN {
        let source = if offset < ALPHABET {
            offset
        } else {
            random_index_below(ALPHABET, &mut rng).expect("draw")
        };
        if let Some(slot) = stream.get_mut(first + offset) {
            *slot = u16::try_from(source).unwrap_or(0);
        }
        if let (Some(slot), Some(&target)) =
            (stream.get_mut(second + offset), permutation.get(source))
        {
            *slot = u16::try_from(target).unwrap_or(0);
        }
    }

    let report =
        isomorph_map_scan(&stream, ALPHABET, 12, 0, 8, 32, DEFAULT_SEED).expect("scan runs");
    assert!(report.significant, "{report:?}");
    assert!(report.observed_max >= LEN);
    assert!(report.null.ceiling < LEN);
    assert!(
        report
            .maps
            .iter()
            .any(|map| map.permutation.as_deref() == Some(&permutation)),
        "planted full map missing: {:?}",
        report.maps
    );
}

#[test]
fn self_test_controls_pass() {
    let result = super::isomorph_map_self_test(DEFAULT_SEED).expect("self-test runs");
    assert!(result.gak_positive_passed, "{result:?}");
    assert_eq!(result.positive_group_order, 6);
    assert!(result.null_rejected, "{result:?}");
    assert_eq!(result.null_group_order, 1);
    assert!(result.dirty_boundary_passed, "{result:?}");
    assert!(result.passed, "{result:?}");
}

fn full_column_map(first: usize, second: usize, permutation: Vec<usize>) -> ColumnMap {
    ColumnMap {
        span: PatternSpan {
            length: 12,
            first,
            second,
            gap: second - first,
        },
        trim: 0,
        core_len: 12,
        boundary_positions_dropped: 0,
        kind: MapKind::Full,
        mapping: permutation.iter().copied().map(Some).collect(),
        permutation: Some(permutation),
    }
}

#[test]
fn chain_validation_accepts_matching_composition_and_reports_conflict() {
    let ab = full_column_map(0, 10, vec![1, 2, 0]);
    let bc = full_column_map(10, 20, vec![2, 0, 1]);
    let ac = full_column_map(0, 20, vec![0, 1, 2]);
    let valid = validate_chains(&[ab.clone(), bc.clone(), ac]);
    assert_eq!(valid.checked, 1);
    assert!(valid.violations.is_empty());

    let bad_ac = full_column_map(0, 20, vec![1, 0, 2]);
    let invalid = validate_chains(&[ab, bc, bad_ac]);
    assert_eq!(invalid.checked, 1);
    assert!(
        invalid
            .violations
            .iter()
            .any(|v| v.first == 0 && v.middle == 10 && v.third == 20)
    );
}

fn permutation_from_cycles(size: usize, cycles: &[&[usize]]) -> Vec<usize> {
    let mut permutation: Vec<usize> = (0..size).collect();
    for cycle in cycles {
        for (index, &source) in cycle.iter().enumerate() {
            let target = cycle
                .get((index + 1) % cycle.len())
                .copied()
                .unwrap_or(source);
            if let Some(slot) = permutation.get_mut(source) {
                *slot = target;
            }
        }
    }
    permutation
}

fn recon_generators() -> Vec<Vec<usize>> {
    vec![
        permutation_from_cycles(12, &[&[0, 5, 1], &[2, 10, 3], &[4, 9, 8], &[6, 11, 7]]),
        permutation_from_cycles(12, &[&[0, 2, 10], &[1, 3, 5], &[4, 6, 8], &[7, 9, 11]]),
        permutation_from_cycles(12, &[&[1, 4], &[2, 11], &[5, 8], &[7, 10]]),
        permutation_from_cycles(12, &[&[0, 4, 5], &[1, 8, 9], &[2, 3, 7], &[6, 10, 11]]),
    ]
}

fn expected_order_histogram() -> BTreeMap<usize, usize> {
    [(1, 1), (2, 15), (3, 32)].into_iter().collect()
}

fn has_mod3_blocks(blocks: &[Vec<usize>]) -> bool {
    let expected = vec![vec![0, 3, 6, 9], vec![1, 4, 7, 10], vec![2, 5, 8, 11]];
    blocks == expected
}

#[test]
fn recon_generators_close_to_recorded_order_48_structure() {
    let closure = close_full_maps(&recon_generators(), 12, DEFAULT_CLOSURE_CAP).expect("closure");
    assert_eq!(closure.order, 48);
    assert_eq!(closure.element_order_histogram, expected_order_histogram());
    assert!(closure.transitive);
    assert_eq!(closure.point_stabilizer_order, 4);
    assert!(
        closure
            .block_systems
            .iter()
            .any(|system| has_mod3_blocks(&system.blocks)),
        "mod-3 residue block system missing: {:?}",
        closure.block_systems
    );
}

fn parse_two() -> Vec<u16> {
    const TWO: &str = include_str!("../../../research/data/practice-puzzles/two");
    const ALPHABET: &str = "ABCDEFGHIJKL";
    TWO.chars()
        .filter_map(|ch| {
            if ch.is_whitespace() {
                None
            } else {
                ALPHABET
                    .chars()
                    .position(|candidate| candidate == ch)
                    .map(|index| u16::try_from(index).unwrap_or(0))
            }
        })
        .collect()
}

#[test]
fn real_two_detected_full_maps_reproduce_recorded_order_48_lower_bound() {
    let values = parse_two();
    let report = isomorph_map_scan(
        &values,
        12,
        DEFAULT_MIN_SPAN_LEN,
        DEFAULT_TRIM,
        DEFAULT_TOP_K,
        DEFAULT_NULL_TRIALS,
        DEFAULT_SEED,
    )
    .expect("scan two");
    assert!(report.significant, "{report:?}");
    let full_maps: Vec<Vec<usize>> = report
        .maps
        .iter()
        .filter_map(|map| map.permutation.clone())
        .collect();
    let closure = close_full_maps(&full_maps, 12, DEFAULT_CLOSURE_CAP).expect("closure");
    assert_eq!(closure.order, 48, "full_maps={full_maps:?}");
    assert_eq!(closure.element_order_histogram, expected_order_histogram());
    assert!(closure.transitive);
    assert_eq!(closure.point_stabilizer_order, 4);
    assert!(
        closure
            .block_systems
            .iter()
            .any(|system| has_mod3_blocks(&system.blocks)),
        "mod-3 residue block system missing: {:?}",
        closure.block_systems
    );
}
