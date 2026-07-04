//! Tests for equality-pattern span detection and trimmed column-map extraction.

use super::{
    DEFAULT_SEED, MapKind, PatternSpan, extract_column_map, find_pattern_spans, isomorph_map_scan,
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
