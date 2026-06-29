//! Chain-link graph construction, conflict catalogue, and coverage for the
//! Thread 5 chaining-graph audit.
//!
//! Builds the broad window/shared-pivot gap-isomorph graph, tabulates the
//! observed non-commutativity (conflicts), and measures connected-component
//! coverage, split out of the battery body.

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::isomorph::PatternSignature;

use super::{
    AlignedOccurrence, ChainLink, ChainingConflict, ChainingGraphConfig, ChainingGraphError,
    ConflictCatalogue, ContextId, CoverageReport, LinkProvenance, SymbolValue, UnionFind,
    chain_links_for_pair,
};

pub(crate) fn compute_graph(
    message_values: &[Vec<SymbolValue>],
    window_len: usize,
    core_len: usize,
    alphabet_size: usize,
) -> Result<GraphComputation, ChainingGraphError> {
    let occurrences = collect_occurrences(message_values, window_len, core_len);
    let (links, contexts) = links_for_occurrences(&occurrences)?;
    let catalogue = catalogue_from_contexts(&links, &contexts);
    let coverage = coverage_from_links(&links, alphabet_size);
    Ok(GraphComputation {
        links,
        contexts,
        catalogue,
        coverage,
    })
}

#[cfg(test)]
pub(crate) fn catalogue_from_links(links: &[ChainLink]) -> ConflictCatalogue {
    let action = action_map(links);
    let contexts = action.keys().copied().collect::<Vec<_>>();
    let pairs = ordered_context_pairs(&contexts);
    catalogue_from_action_pairs(&action, &pairs)
}

fn catalogue_from_contexts(links: &[ChainLink], contexts: &[ContextMetadata]) -> ConflictCatalogue {
    let action = action_map(links);
    let pairs = stack_context_pairs(contexts);
    catalogue_from_action_pairs(&action, &pairs)
}

fn catalogue_from_action_pairs(
    action: &ActionMap,
    pairs: &[(ContextId, ContextId)],
) -> ConflictCatalogue {
    let mut conflicts = Vec::new();
    let mut seen = BTreeSet::new();
    let mut independent = 0usize;

    for (a, b) in pairs {
        let found = conflicts_for_context_pair(*a, *b, action, &mut seen);
        for conflict in found {
            if conflict.independent {
                independent = independent.saturating_add(1);
            }
            conflicts.push(conflict.conflict);
        }
    }

    conflicts.sort_by_key(|conflict| {
        (
            conflict.a,
            conflict.b,
            conflict.start,
            conflict.ab_image,
            conflict.ba_image,
        )
    });
    let total = conflicts.len();
    let fragile = conflicts.iter().filter(|conflict| !conflict.robust).count();
    ConflictCatalogue {
        conflicts,
        total,
        independent,
        fragile,
    }
}

fn ordered_context_pairs(contexts: &[ContextId]) -> Vec<(ContextId, ContextId)> {
    let mut pairs = Vec::new();
    for a in contexts {
        for b in contexts.iter().filter(|candidate| *candidate != a) {
            pairs.push((*a, *b));
        }
    }
    pairs
}

fn stack_context_pairs(contexts: &[ContextMetadata]) -> Vec<(ContextId, ContextId)> {
    let mut by_stack: BTreeMap<(PatternSignature, OccurrenceMetadata), Vec<ContextId>> =
        BTreeMap::new();
    for context in contexts {
        by_stack
            .entry((context.signature.clone(), context.upper))
            .or_default()
            .push(context.id);
    }

    let mut pairs = Vec::new();
    for ids in by_stack.values() {
        pairs.extend(ordered_context_pairs(ids));
    }
    pairs
}

pub(crate) fn coverage_from_links(links: &[ChainLink], alphabet_size: usize) -> CoverageReport {
    let broad = coverage_counts_from_links(links.iter(), alphabet_size);
    let core = coverage_counts_from_links(
        links.iter().filter(|link| link.provenance.in_repeated_core),
        alphabet_size,
    );

    CoverageReport {
        symbols_touched: broad.symbols_touched,
        largest_component: broad.largest_component,
        component_count: broad.component_count,
        core_supported_symbols: core.symbols_touched,
        core_largest_component: core.largest_component,
        core_supported_components: core.component_count,
        alphabet_size,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CoverageCounts {
    symbols_touched: usize,
    largest_component: usize,
    component_count: usize,
}

fn coverage_counts_from_links<'a>(
    links: impl Iterator<Item = &'a ChainLink>,
    alphabet_size: usize,
) -> CoverageCounts {
    let mut touched = BTreeSet::new();
    let mut union_find = UnionFind::new(alphabet_size);

    for link in links {
        let from = usize::from(link.from.get());
        let to = usize::from(link.to.get());
        if from < alphabet_size {
            let _inserted = touched.insert(from);
        }
        if to < alphabet_size {
            let _inserted = touched.insert(to);
        }
        union_find.union(from, to);
    }

    let mut component_sizes: BTreeMap<usize, usize> = BTreeMap::new();
    for symbol in &touched {
        if let Some(root) = union_find.find(*symbol) {
            let count = component_sizes.entry(root).or_default();
            *count = count.saturating_add(1);
        }
    }

    CoverageCounts {
        symbols_touched: touched.len(),
        largest_component: component_sizes.values().copied().max().unwrap_or_default(),
        component_count: component_sizes.len(),
    }
}

pub(crate) fn find_context(
    contexts: &[ContextMetadata],
    upper_message: usize,
    upper_start: usize,
    lower_message: usize,
    lower_start: usize,
) -> Option<ContextId> {
    contexts
        .iter()
        .find(|context| {
            context.upper.message == upper_message
                && context.upper.start == upper_start
                && context.lower.message == lower_message
                && context.lower.start == lower_start
        })
        .map(|context| context.id)
}

pub(super) fn validate_config(config: ChainingGraphConfig) -> Result<(), ChainingGraphError> {
    if config.trials == 0 {
        return Err(ChainingGraphError::ZeroTrials);
    }
    if config.window_len == 0 || config.core_len > config.window_len {
        return Err(ChainingGraphError::InvalidWindowConfig {
            window_len: config.window_len,
            core_len: config.core_len,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GraphComputation {
    pub(crate) links: Vec<ChainLink>,
    pub(crate) contexts: Vec<ContextMetadata>,
    pub(crate) catalogue: ConflictCatalogue,
    pub(crate) coverage: CoverageReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContextMetadata {
    pub(crate) id: ContextId,
    pub(crate) signature: PatternSignature,
    pub(crate) upper: OccurrenceMetadata,
    pub(crate) lower: OccurrenceMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OccurrenceMetadata {
    pub(crate) message: usize,
    pub(crate) start: usize,
    pub(crate) core_len: usize,
}

#[derive(Clone, Debug)]
struct Occurrence {
    metadata: OccurrenceMetadata,
    window: Vec<SymbolValue>,
}

fn collect_occurrences(
    message_values: &[Vec<SymbolValue>],
    window_len: usize,
    core_len: usize,
) -> BTreeMap<PatternSignature, Vec<Occurrence>> {
    let mut by_signature: BTreeMap<PatternSignature, Vec<Occurrence>> = BTreeMap::new();
    for (message, values) in message_values.iter().enumerate() {
        for (start, window) in values.windows(window_len).enumerate() {
            let signature = PatternSignature::from_window(window);
            if !signature.has_repeated_symbol() {
                continue;
            }
            by_signature
                .entry(signature.clone())
                .or_default()
                .push(Occurrence {
                    metadata: OccurrenceMetadata {
                        message,
                        start,
                        core_len,
                    },
                    window: window.to_vec(),
                });
        }
    }
    by_signature.retain(|_signature, occurrences| occurrences.len() >= 2);
    by_signature
}

/// Emit canonical-orientation contexts for repeated gap signatures.
///
/// Each unordered occurrence pair contributes exactly one directed context in
/// sorted occurrence order. The broad audit deliberately does not add reverse
/// orientations or alternate shared-pivot stacks, because doing so would widen
/// an already collision-prone gap-isomorph graph.
fn links_for_occurrences(
    occurrences: &BTreeMap<PatternSignature, Vec<Occurrence>>,
) -> Result<(Vec<ChainLink>, Vec<ContextMetadata>), ChainingGraphError> {
    let mut links = Vec::new();
    let mut contexts = Vec::new();
    for (signature, group) in occurrences {
        for (left_index, upper) in group.iter().enumerate() {
            for lower in group.iter().skip(left_index.saturating_add(1)) {
                let id = context_id(contexts.len())?;
                let upper_aligned = AlignedOccurrence {
                    message: upper.metadata.message,
                    window: &upper.window,
                    core_len: upper.metadata.core_len,
                };
                let lower_aligned = AlignedOccurrence {
                    message: lower.metadata.message,
                    window: &lower.window,
                    core_len: lower.metadata.core_len,
                };
                links.extend(chain_links_for_pair(id, &upper_aligned, &lower_aligned)?);
                contexts.push(ContextMetadata {
                    id,
                    signature: signature.clone(),
                    upper: upper.metadata,
                    lower: lower.metadata,
                });
            }
        }
    }
    Ok((links, contexts))
}

fn context_id(index: usize) -> Result<ContextId, ChainingGraphError> {
    let id = u32::try_from(index)
        .map_err(|_error| ChainingGraphError::ContextCountTooLarge { contexts: index })?;
    Ok(ContextId::new(id))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeKey {
    context: ContextId,
    from: SymbolValue,
    to: SymbolValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EdgeEvidence {
    key: EdgeKey,
    core_count: usize,
    first_provenance: LinkProvenance,
}

impl EdgeEvidence {
    pub(crate) const fn is_core_supported(self) -> bool {
        self.core_count > 0
    }
}

type ActionMap = BTreeMap<ContextId, BTreeMap<SymbolValue, Vec<EdgeEvidence>>>;

fn action_map(links: &[ChainLink]) -> ActionMap {
    let mut edges: BTreeMap<EdgeKey, (usize, LinkProvenance)> = BTreeMap::new();
    for link in links {
        let key = EdgeKey {
            context: link.context,
            from: link.from,
            to: link.to,
        };
        let entry = edges.entry(key).or_insert((0, link.provenance));
        if link.provenance.in_repeated_core {
            entry.0 = entry.0.saturating_add(1);
        }
        if link.provenance < entry.1 {
            entry.1 = link.provenance;
        }
    }

    let mut action: ActionMap = BTreeMap::new();
    for (key, (core_count, first_provenance)) in edges {
        action
            .entry(key.context)
            .or_default()
            .entry(key.from)
            .or_default()
            .push(EdgeEvidence {
                key,
                core_count,
                first_provenance,
            });
    }
    action
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ConflictKey {
    a: ContextId,
    b: ContextId,
    start: SymbolValue,
    ab_image: SymbolValue,
    ba_image: SymbolValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConflictSearchResult {
    conflict: ChainingConflict,
    independent: bool,
}

fn conflicts_for_context_pair(
    a: ContextId,
    b: ContextId,
    action: &ActionMap,
    seen: &mut BTreeSet<ConflictKey>,
) -> Vec<ConflictSearchResult> {
    let mut results = Vec::new();
    let Some(a_edges) = action.get(&a) else {
        return results;
    };
    let Some(b_edges) = action.get(&b) else {
        return results;
    };

    let starts = a_edges
        .keys()
        .filter(|start| b_edges.contains_key(start))
        .copied()
        .collect::<Vec<_>>();

    for start in starts {
        collect_start_conflicts(a, b, start, action, seen, &mut results);
    }
    results
}

fn collect_start_conflicts(
    a: ContextId,
    b: ContextId,
    start: SymbolValue,
    action: &ActionMap,
    seen: &mut BTreeSet<ConflictKey>,
    results: &mut Vec<ConflictSearchResult>,
) {
    let Some(a_first) = edges_for(action, a, start) else {
        return;
    };
    let Some(b_first) = edges_for(action, b, start) else {
        return;
    };

    for edge_a in a_first {
        if let Some(after_a) = edges_for(action, b, edge_a.key.to) {
            for edge_b in b_first {
                if let Some(after_b) = edges_for(action, a, edge_b.key.to) {
                    push_composed_conflicts(
                        ConflictPathInput {
                            a,
                            b,
                            start,
                            edge_a: *edge_a,
                            edge_b: *edge_b,
                            after_a,
                            after_b,
                        },
                        seen,
                        results,
                    );
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ConflictPathInput<'a> {
    a: ContextId,
    b: ContextId,
    start: SymbolValue,
    edge_a: EdgeEvidence,
    edge_b: EdgeEvidence,
    after_a: &'a [EdgeEvidence],
    after_b: &'a [EdgeEvidence],
}

fn push_composed_conflicts(
    input: ConflictPathInput<'_>,
    seen: &mut BTreeSet<ConflictKey>,
    results: &mut Vec<ConflictSearchResult>,
) {
    for edge_b_after_a in input.after_a {
        for edge_a_after_b in input.after_b {
            if edge_b_after_a.key.to == edge_a_after_b.key.to {
                continue;
            }
            let key = ConflictKey {
                a: input.a,
                b: input.b,
                start: input.start,
                ab_image: edge_b_after_a.key.to,
                ba_image: edge_a_after_b.key.to,
            };
            if !seen.insert(key) {
                continue;
            }
            let evidences = [input.edge_a, *edge_b_after_a, input.edge_b, *edge_a_after_b];
            results.push(ConflictSearchResult {
                conflict: ChainingConflict {
                    a: input.a,
                    b: input.b,
                    start: input.start,
                    ab_image: edge_b_after_a.key.to,
                    ba_image: edge_a_after_b.key.to,
                    robust: evidences
                        .iter()
                        .all(|evidence| evidence.is_core_supported()),
                },
                independent: independent_provenance(&evidences),
            });
        }
    }
}

fn edges_for(action: &ActionMap, context: ContextId, from: SymbolValue) -> Option<&[EdgeEvidence]> {
    action
        .get(&context)
        .and_then(|by_from| by_from.get(&from))
        .map(Vec::as_slice)
}

fn independent_provenance(evidences: &[EdgeEvidence; 4]) -> bool {
    let mut seen = BTreeSet::new();
    for evidence in evidences {
        if !seen.insert(evidence.first_provenance) {
            return false;
        }
    }
    true
}
