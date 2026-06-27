use super::{
    AlignedOccurrence, ChainingGraphConfig, ContextId, DEFAULT_CORE_LEN, DEFAULT_WINDOW_LEN,
    POSITIVE_CONTROL_MIN_MARGIN, UnionFind, catalogue_from_links, chain_links_for_pair,
    compute_graph, positive_control_fixture, positive_control_null_max, run_chaining_graph,
};
use crate::orders;
use crate::trigram::TrigramValue;
use std::collections::BTreeSet;

#[test]
fn chaining_graph_is_reproducible_for_fixed_seed() {
    let config = ChainingGraphConfig {
        seed: 17,
        trials: 4,
        ..ChainingGraphConfig::default()
    };
    let first = run_chaining_graph(config).unwrap();
    let second = run_chaining_graph(config).unwrap();
    assert_eq!(first, second);
}

#[test]
fn accepted_eye_stream_pin_matches_thread_oracle() {
    let grids = orders::corpus_grids().unwrap();
    let order = orders::accepted_honeycomb_order();
    let messages = orders::read_corpus_message_values(&grids, order).unwrap();
    let total = messages.iter().map(Vec::len).sum::<usize>();
    let distinct = messages
        .iter()
        .flat_map(|message| message.iter().copied())
        .collect::<BTreeSet<_>>();
    let adjacent_equal = messages
        .iter()
        .map(|message| {
            message
                .windows(2)
                .filter(|pair| {
                    pair.first()
                        .zip(pair.get(1))
                        .is_some_and(|(left, right)| left == right)
                })
                .count()
        })
        .sum::<usize>();
    assert_eq!(total, 1_036);
    assert_eq!(distinct.len(), 83);
    assert_eq!(adjacent_equal, 0);
    assert_eq!(order.name(), "standard36-u012-d012");
}

#[test]
fn wiki_gap_signature_occurrences_are_pinned() {
    let grids = orders::corpus_grids().unwrap();
    let messages =
        orders::read_corpus_message_values(&grids, orders::accepted_honeycomb_order()).unwrap();
    let graph = compute_graph(&messages, DEFAULT_WINDOW_LEN, DEFAULT_CORE_LEN).unwrap();
    let signature = [0, 0, 0, 0, 0, 3, 0, 7, 4, 0, 9];
    let mut occurrences = graph
        .contexts
        .iter()
        .flat_map(|context| [context.upper, context.lower])
        .filter(|occurrence| occurrence_signature(&messages, *occurrence) == signature)
        .collect::<Vec<_>>();
    occurrences.sort_unstable();
    occurrences.dedup();
    let located = occurrences
        .iter()
        .map(|occurrence| (occurrence.message, occurrence.start))
        .collect::<Vec<_>>();
    assert_eq!(located, vec![(1, 40), (1, 70), (2, 45), (2, 80)]);
    assert_eq!(
        display_columns(&messages, &[(1, 40), (2, 45), (1, 70)]),
        "3-Q/Q_?/-5)"
    );
}

#[test]
fn chain_links_reject_length_mismatch() {
    let upper_values = values(&[1, 2, 3]);
    let lower_values = values(&[1, 2]);
    let upper = AlignedOccurrence {
        message: 0,
        window: &upper_values,
        core_len: 3,
    };
    let lower = AlignedOccurrence {
        message: 1,
        window: &lower_values,
        core_len: 2,
    };
    assert!(chain_links_for_pair(ContextId::new(0), &upper, &lower).is_err());
}

#[test]
fn positive_control_recovers_non_commuting_fixture() {
    let fixture = positive_control_fixture(123, DEFAULT_WINDOW_LEN, DEFAULT_CORE_LEN).unwrap();
    let graph = compute_graph(&fixture.streams, DEFAULT_WINDOW_LEN, DEFAULT_CORE_LEN).unwrap();
    let null_max =
        positive_control_null_max(&fixture, 123, DEFAULT_WINDOW_LEN, DEFAULT_CORE_LEN).unwrap();
    assert!(
        graph.catalogue.total > null_max.saturating_add(POSITIVE_CONTROL_MIN_MARGIN),
        "real={} null_max={} required_margin={}",
        graph.catalogue.total,
        null_max,
        POSITIVE_CONTROL_MIN_MARGIN
    );
    assert!(graph.coverage.symbols_touched >= fixture.planted_symbols);
}

#[test]
fn commutative_fixture_has_no_conflicts() {
    let base = values(&[0, 1, 2, 3, 4]);
    let shifted = values(&[1, 2, 3, 4, 0]);
    let upper = AlignedOccurrence {
        message: 0,
        window: &base,
        core_len: base.len(),
    };
    let lower = AlignedOccurrence {
        message: 1,
        window: &shifted,
        core_len: shifted.len(),
    };
    let mut links = chain_links_for_pair(ContextId::new(0), &upper, &lower).unwrap();
    links.extend(chain_links_for_pair(ContextId::new(1), &upper, &lower).unwrap());
    let catalogue = catalogue_from_links(&links);
    assert_eq!(catalogue.total, 0);
}

#[test]
fn union_find_handles_components_and_out_of_range() {
    let mut union_find = UnionFind::new(4);
    assert_eq!(union_find.find(4), None);
    union_find.union(0, 1);
    union_find.union(1, 2);
    union_find.union(2, 9);
    let root_0 = union_find.find(0);
    assert_eq!(root_0, union_find.find(1));
    assert_eq!(root_0, union_find.find(2));
    assert_ne!(root_0, union_find.find(3));
}

fn occurrence_signature(
    messages: &[Vec<TrigramValue>],
    occurrence: super::OccurrenceMetadata,
) -> Vec<usize> {
    let window = messages
        .get(occurrence.message)
        .and_then(|message| message.windows(DEFAULT_WINDOW_LEN).nth(occurrence.start))
        .unwrap();
    gap_signature(window)
}

fn gap_signature(window: &[TrigramValue]) -> Vec<usize> {
    let mut previous = std::collections::BTreeMap::new();
    let mut signature = Vec::with_capacity(window.len());
    for (column, symbol) in window.iter().copied().enumerate() {
        let gap = previous
            .get(&symbol)
            .map_or(0, |last| column.abs_diff(*last));
        signature.push(gap);
        let _old = previous.insert(symbol, column);
    }
    signature
}

fn display_columns(messages: &[Vec<TrigramValue>], starts: &[(usize, usize)]) -> String {
    let mut rows = Vec::new();
    for (message, start) in starts {
        let mut row = String::new();
        for column in [4usize, 6, 9] {
            let value = messages
                .get(*message)
                .and_then(|values| values.get(start.saturating_add(column)))
                .copied()
                .unwrap();
            row.push(char::from_u32(u32::from(value.get()) + 32).unwrap());
        }
        rows.push(row);
    }
    rows.join("/")
}

fn values(raw: &[u8]) -> Vec<TrigramValue> {
    raw.iter()
        .copied()
        .map(|value| TrigramValue::new(value).unwrap())
        .collect()
}
