use super::{
    DihedralVerdict, SymbolicOrder, TransitivityConfig, candidate_group_orders,
    candidate_hidden_subgroup_sizes, run_transitivity,
};
use crate::analysis::chaining_graph::{
    ContextId, DEFAULT_CORE_LEN, DEFAULT_WINDOW_LEN, compute_graph,
};
use crate::analysis::orders;

#[test]
fn transitivity_is_reproducible_for_fixed_seed() {
    let config = TransitivityConfig {
        seed: 91,
        trials: 1,
    };
    let first = run_transitivity(config).unwrap();
    let second = run_transitivity(config).unwrap();
    assert_eq!(first, second);
}

#[test]
fn dihedral_verdict_reproduces_cited_conflict() {
    let config = TransitivityConfig {
        seed: 12,
        trials: 1,
    };
    let report = run_transitivity(config).unwrap();
    assert_eq!(report.verdict, DihedralVerdict::DihedralExcluded);
    assert_eq!(report.witnesses.len(), 1);

    let grids = orders::corpus_grids().unwrap();
    let messages =
        orders::read_corpus_message_values(&grids, orders::accepted_honeycomb_order()).unwrap();
    let graph = compute_graph(
        &messages,
        DEFAULT_WINDOW_LEN,
        DEFAULT_CORE_LEN,
        orders::READING_LAYER_ALPHABET_SIZE,
    )
    .unwrap();
    let (context_a, context_b) = super::wiki_contexts(&graph).unwrap();
    let witness = report.witnesses.first().unwrap();
    assert_eq!(witness.context_a, context_a);
    assert_eq!(witness.context_b, context_b);
    assert_eq!(witness.conflict.start.get(), 19);
    assert_eq!(display(witness.conflict.start), '3');
    assert_eq!(witness.conflict.ab_image.get(), 9);
    assert_eq!(display(witness.conflict.ab_image), ')');
    assert_eq!(witness.conflict.ba_image.get(), 63);
    assert_eq!(display(witness.conflict.ba_image), '_');
    assert!(!witness.conflict.robust);
    assert!(!witness.core_only);
    assert_eq!(report.core_only_witnesses, 0);
}

#[test]
fn cited_context_ids_are_distinct() {
    let grids = orders::corpus_grids().unwrap();
    let messages =
        orders::read_corpus_message_values(&grids, orders::accepted_honeycomb_order()).unwrap();
    let graph = compute_graph(
        &messages,
        DEFAULT_WINDOW_LEN,
        DEFAULT_CORE_LEN,
        orders::READING_LAYER_ALPHABET_SIZE,
    )
    .unwrap();
    let (context_a, context_b) = super::wiki_contexts(&graph).unwrap();
    assert_ne!(context_a, context_b);
    assert_ne!(context_a, ContextId::new(u32::MAX));
}

#[test]
fn six_transitive_group_orders_and_hidden_subgroup_sizes_are_encoded() {
    assert_eq!(
        candidate_group_orders(),
        vec![
            SymbolicOrder::Exact(83),
            SymbolicOrder::Exact(166),
            SymbolicOrder::Exact(3_403),
            SymbolicOrder::Exact(6_806),
            SymbolicOrder::Factorial83Over2,
            SymbolicOrder::Factorial83,
        ]
    );
    assert_eq!(
        candidate_hidden_subgroup_sizes(),
        vec![
            SymbolicOrder::Exact(1),
            SymbolicOrder::Exact(2),
            SymbolicOrder::Exact(41),
            SymbolicOrder::Exact(82),
            SymbolicOrder::Factorial82Over2,
            SymbolicOrder::Factorial82,
        ]
    );
}

fn display(value: crate::core::trigram::TrigramValue) -> char {
    char::from_u32(u32::from(value.get()) + 32).unwrap()
}
