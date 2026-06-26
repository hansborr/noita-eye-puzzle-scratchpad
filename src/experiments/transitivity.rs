//! Thread 1B dihedral-transitivity audit for the Noita eye-glyph puzzle.
//!
//! This module encodes the conditional `D_166` exclusion described in
//! `eye-messages.wiki/Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher.md`
//! and the right-coset transitivity premise from
//! `eye-messages.wiki/Proof-that-GAK-is-transitive.md` and
//! `The-Transitivity-Restriction-(6-Groups-for-83).md`. It consumes the
//! chain-link primitive from [`crate::chaining_graph`] and stays strictly at the
//! ciphertext-equality / group-structure layer.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::chaining_graph::{
    ChainLink, ChainingConflict, ChainingGraphConfig, ChainingGraphError, ConflictCatalogue,
    ContextId, DEFAULT_CORE_LEN, DEFAULT_WINDOW_LEN, SymbolValue, compute_graph, find_context,
};
use crate::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::report::{self, Report};

/// Default deterministic seed for the transitivity audit.
pub const DEFAULT_SEED: u64 = 0x7472_616e_7369_7431;
/// Default matched-null trial count delegated to the chaining-graph gate.
pub const DEFAULT_TRIALS: usize = crate::chaining_graph::DEFAULT_TRIALS;

const WIKI_MSG1_MESSAGE: usize = 1;
const WIKI_MSG1_START: usize = 40;
const WIKI_MSG2_MESSAGE: usize = 2;
const WIKI_MSG2_START: usize = 45;
const WIKI_MSG3_MESSAGE: usize = 1;
const WIKI_MSG3_START: usize = 70;
const WIKI_GAP_SIGNATURE: [usize; DEFAULT_WINDOW_LEN] = [0, 0, 0, 0, 0, 3, 0, 7, 4, 0, 9];

/// Structural verdict on whether the eyes can be a dihedral (`D_166`) GAK cipher.
///
/// This constrains the candidate group set only; it is not a decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DihedralVerdict {
    /// Order-83 forcing and a commutativity conflict both fire.
    DihedralExcluded,
    /// Order-83 forcing fires but no conflict was found.
    ForcingWithoutConflict,
    /// The cited isomorph alignment was not located in the corpus.
    IsomorphNotLocated,
}

/// A single order-83-forcing-plus-conflict witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExclusionWitness {
    /// Context whose length-`>2` chain forces order 83.
    pub context_a: ContextId,
    /// Second context whose length-`>2` chain forces order 83.
    pub context_b: ContextId,
    /// Commutativity conflict that completes the contradiction.
    pub conflict: ChainingConflict,
    /// True when both forcing chains and the conflict use repeated-core columns.
    pub core_only: bool,
}

/// Configuration for the transitivity / dihedral audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitivityConfig {
    /// Explicit deterministic PRNG seed used by the delegated chaining-graph null.
    pub seed: u64,
    /// Number of delegated within-message shuffle trials.
    pub trials: usize,
}

impl Default for TransitivityConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
        }
    }
}

/// Error returned by the transitivity / dihedral audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitivityError {
    /// The verified corpus could not be reconstructed or read with the order.
    Grid(GridError),
    /// The delegated chaining-graph gate failed.
    ChainingGraph(ChainingGraphError),
    /// At least one delegated Monte-Carlo trial is required.
    ZeroTrials,
    /// A random draw bound did not fit the PRNG helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
}

impl From<GridError> for TransitivityError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<ChainingGraphError> for TransitivityError {
    fn from(value: ChainingGraphError) -> Self {
        Self::ChainingGraph(value)
    }
}

impl From<crate::null::RandomBoundError> for TransitivityError {
    fn from(error: crate::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl fmt::Display for TransitivityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ChainingGraph(chaining_error) => {
                write!(f, "delegated chaining-graph gate failed: {chaining_error}")
            }
            Self::ZeroTrials => write!(f, "at least one delegated Monte-Carlo trial is required"),
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "random draw bound {bound} is too large")
            }
        }
    }
}

impl std::error::Error for TransitivityError {}

/// Complete transitivity / dihedral report.
#[derive(Clone, Debug, PartialEq)]
pub struct TransitivityReport {
    /// Configuration used for the run.
    pub config: TransitivityConfig,
    /// Reading order used for the verified corpus.
    pub order: ReadingOrder,
    /// Structural dihedral verdict.
    pub verdict: DihedralVerdict,
    /// Order-83-forcing-plus-conflict witnesses.
    pub witnesses: Vec<ExclusionWitness>,
    /// Count of witnesses that are fully repeated-core-only.
    pub core_only_witnesses: usize,
    /// Conflict catalogue reused from the chaining-graph engine.
    pub catalogue: ConflictCatalogue,
}

impl Report for TransitivityReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Thread 1B transitivity / D166 audit");
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "delegated chaining-graph shuffle trials: {}",
            self.config.trials
        );
        report::appendln!(
            &mut out,
            "wiki pages under test: Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher.md, Proof-that-GAK-is-transitive.md, The-Transitivity-Restriction-(6-Groups-for-83).md"
        );
        report::appendln!(
            &mut out,
            "canonical-orientation caveat: each unordered occurrence pair contributes one sorted-order directed context; reverse orientations are not expanded."
        );
        report::appendln!(
            &mut out,
            "verdict: {}",
            format_dihedral_verdict(self.verdict)
        );
        report::appendln!(&mut out, "confidence: MEDIUM / conditional");
        report::appendln!(&mut out, "witnesses: {}", self.witnesses.len());
        report::appendln!(
            &mut out,
            "core-only witnesses: {} repeated-core-only",
            self.core_only_witnesses
        );
        report::appendln!(
            &mut out,
            "broad window-11/non-genuine catalogue: total={} distinct-column={} fragile={}",
            self.catalogue.total,
            self.catalogue.independent,
            self.catalogue.fragile
        );
        report::appendln!(
            &mut out,
            "D166 catalogue caveat: this broad gap-isomorph evidence is not additional genuine/core-supported D166 witness support; the verdict still rests on the cited triple, with core-only witnesses: {}.",
            self.core_only_witnesses
        );
        report::appendln!(
            &mut out,
            "Wave-1 comparability note: this Rust catalogue is window-11 + shared-pivot only and is not directly comparable to wave-1's L=10..15 broad survey or its genuine tier."
        );
        report::appendln!(&mut out);
        append_transitivity_witnesses(&mut out, self);
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "Assumptions A1-A5: the exclusion is conditional on same plaintext, perfect isomorphism, no allomorph crossing, the right-coset chaining action, and one single global configuration."
        );
        report::appendln!(
            &mut out,
            "HOLE 1: a single strategic typo at col6 or col9 of the cited triple dissolves that triple's contradiction; the within-triple second conflict reuses col6/col9 and does not remove it."
        );
        report::appendln!(
            &mut out,
            "HOLE 2: on the cited triple the commutativity conflict exists only via the over-extended col9; the repeated 9-core shows order-83 forcing but no conflict. Robust refutation requires a forcing-plus-conflict inside repeated-core columns, counted by core_only_witnesses."
        );
        report::appendln!(
            &mut out,
            "Interpretation: the verdict constrains the candidate group set only; it says nothing about recoverable plaintext. The eyes remain deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext."
        );
        report::appendln!(
            &mut out,
            "Multiplicity note: the conflict catalogue contains many ordered context-pair checks over the same corpus; the D166 exclusion is reported as conditional structural evidence, not as a settled decode."
        );
        out
    }
}

fn append_transitivity_witnesses(out: &mut String, report: &TransitivityReport) {
    if report.witnesses.is_empty() {
        report::appendln!(out, "witness detail: none");
        return;
    }
    report::appendln!(out, "witness detail (first 12)");
    for witness in report.witnesses.iter().take(12) {
        report::appendln!(
            out,
            "  {} then {} from {}: {} vs {} core_only={}",
            format_context_id(witness.context_a),
            format_context_id(witness.context_b),
            format_symbol(witness.conflict.start),
            format_symbol(witness.conflict.ab_image),
            format_symbol(witness.conflict.ba_image),
            witness.core_only
        );
    }
}

fn format_dihedral_verdict(verdict: DihedralVerdict) -> &'static str {
    match verdict {
        DihedralVerdict::DihedralExcluded => "D166 excluded conditionally",
        DihedralVerdict::ForcingWithoutConflict => "forcing without conflict",
        DihedralVerdict::IsomorphNotLocated => "cited isomorph not located",
    }
}

fn format_context_id(context: ContextId) -> String {
    format!("c{}", context.as_u32())
}

fn format_symbol(value: SymbolValue) -> String {
    let display = char::from_u32(u32::from(value.get()) + 32).unwrap_or('?');
    format!("{} ({display:?})", value.get())
}

/// Runs the transitivity / dihedral audit on the verified eye corpus.
///
/// # Errors
/// Returns [`TransitivityError`] when the corpus cannot be reconstructed, when
/// the accepted reading order is incompatible with a grid, when the delegated
/// chaining-graph null/control gate fails, or when the configuration is invalid.
pub fn run_transitivity(
    config: TransitivityConfig,
) -> Result<TransitivityReport, TransitivityError> {
    if config.trials == 0 {
        return Err(TransitivityError::ZeroTrials);
    }

    let chaining_config = ChainingGraphConfig {
        seed: config.seed,
        trials: config.trials,
        ..ChainingGraphConfig::default()
    };
    let chaining_report = crate::chaining_graph::run_chaining_graph(chaining_config)?;

    let grids = orders::corpus_grids()?;
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    let graph = compute_graph(&message_values, DEFAULT_WINDOW_LEN, DEFAULT_CORE_LEN)?;
    let witnesses = cited_exclusion_witnesses(&graph);
    let core_only_witnesses = witnesses.iter().filter(|witness| witness.core_only).count();
    let verdict = dihedral_verdict(&message_values, &graph, &witnesses);

    Ok(TransitivityReport {
        config,
        order,
        verdict,
        witnesses,
        core_only_witnesses,
        catalogue: chaining_report.catalogue,
    })
}

fn dihedral_verdict(
    message_values: &[Vec<SymbolValue>],
    graph: &crate::chaining_graph::GraphComputation,
    witnesses: &[ExclusionWitness],
) -> DihedralVerdict {
    if wiki_occurrences(message_values).len() < 4 || wiki_contexts(graph).is_none() {
        return DihedralVerdict::IsomorphNotLocated;
    }
    if !witnesses.is_empty() {
        return DihedralVerdict::DihedralExcluded;
    }
    DihedralVerdict::ForcingWithoutConflict
}

fn wiki_contexts(
    graph: &crate::chaining_graph::GraphComputation,
) -> Option<(ContextId, ContextId)> {
    let context_a = find_context(
        &graph.contexts,
        WIKI_MSG1_MESSAGE,
        WIKI_MSG1_START,
        WIKI_MSG2_MESSAGE,
        WIKI_MSG2_START,
    )?;
    let context_b = find_context(
        &graph.contexts,
        WIKI_MSG1_MESSAGE,
        WIKI_MSG1_START,
        WIKI_MSG3_MESSAGE,
        WIKI_MSG3_START,
    )?;
    Some((context_a, context_b))
}

fn wiki_occurrences(message_values: &[Vec<SymbolValue>]) -> Vec<(usize, usize)> {
    let mut occurrences = Vec::new();
    for (message, values) in message_values.iter().enumerate() {
        for (start, window) in values.windows(DEFAULT_WINDOW_LEN).enumerate() {
            if gap_signature(window).iter().copied().eq(WIKI_GAP_SIGNATURE) {
                occurrences.push((message, start));
            }
        }
    }
    occurrences
}

fn gap_signature(window: &[SymbolValue]) -> Vec<usize> {
    let mut previous: BTreeMap<SymbolValue, usize> = BTreeMap::new();
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

fn cited_exclusion_witnesses(
    graph: &crate::chaining_graph::GraphComputation,
) -> Vec<ExclusionWitness> {
    let Some((context_a, context_b)) = wiki_contexts(graph) else {
        return Vec::new();
    };
    if !context_has_order_forcing(&graph.links, context_a, false)
        || !context_has_order_forcing(&graph.links, context_b, false)
    {
        return Vec::new();
    }
    let core_forcing = context_has_order_forcing(&graph.links, context_a, true)
        && context_has_order_forcing(&graph.links, context_b, true);
    graph
        .catalogue
        .conflicts
        .iter()
        .filter(|conflict| conflict.a == context_a && conflict.b == context_b)
        .map(|conflict| ExclusionWitness {
            context_a,
            context_b,
            conflict: *conflict,
            core_only: core_forcing && conflict_has_core_only_path(&graph.links, conflict),
        })
        .collect()
}

fn context_has_order_forcing(links: &[ChainLink], context: ContextId, core_only: bool) -> bool {
    let by_context = links_by_context(links, core_only);
    context_has_length_three_chain(context, &by_context)
}

fn links_by_context(
    links: &[ChainLink],
    core_only: bool,
) -> BTreeMap<ContextId, BTreeMap<SymbolValue, BTreeSet<SymbolValue>>> {
    let mut by_context: BTreeMap<ContextId, BTreeMap<SymbolValue, BTreeSet<SymbolValue>>> =
        BTreeMap::new();
    for link in links {
        if core_only && !link.provenance.in_repeated_core {
            continue;
        }
        let _inserted = by_context
            .entry(link.context)
            .or_default()
            .entry(link.from)
            .or_default()
            .insert(link.to);
    }
    by_context
}

fn context_has_length_three_chain(
    context: ContextId,
    by_context: &BTreeMap<ContextId, BTreeMap<SymbolValue, BTreeSet<SymbolValue>>>,
) -> bool {
    let Some(edges) = by_context.get(&context) else {
        return false;
    };
    for (start, mids) in edges {
        for mid in mids {
            let Some(ends) = edges.get(mid) else {
                continue;
            };
            if ends
                .iter()
                .any(|end| end != start && end != mid && mid != start)
            {
                return true;
            }
        }
    }
    false
}

fn conflict_has_core_only_path(links: &[ChainLink], conflict: &ChainingConflict) -> bool {
    let by_context = links_by_context(links, true);
    let Some(a_start_edges) = edges_for(&by_context, conflict.a, conflict.start) else {
        return false;
    };
    let Some(b_start_edges) = edges_for(&by_context, conflict.b, conflict.start) else {
        return false;
    };

    for a_mid in a_start_edges {
        if reaches(&by_context, conflict.b, *a_mid, conflict.ab_image) {
            for b_mid in b_start_edges {
                if reaches(&by_context, conflict.a, *b_mid, conflict.ba_image) {
                    return true;
                }
            }
        }
    }
    false
}

fn reaches(
    by_context: &BTreeMap<ContextId, BTreeMap<SymbolValue, BTreeSet<SymbolValue>>>,
    context: ContextId,
    from: SymbolValue,
    to: SymbolValue,
) -> bool {
    edges_for(by_context, context, from).is_some_and(|targets| targets.contains(&to))
}

fn edges_for(
    by_context: &BTreeMap<ContextId, BTreeMap<SymbolValue, BTreeSet<SymbolValue>>>,
    context: ContextId,
    from: SymbolValue,
) -> Option<&BTreeSet<SymbolValue>> {
    by_context
        .get(&context)
        .and_then(|by_from| by_from.get(&from))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymbolicOrder {
    Exact(u128),
    Factorial82Over2,
    Factorial82,
    Factorial83Over2,
    Factorial83,
}

#[cfg(test)]
fn candidate_group_orders() -> Vec<SymbolicOrder> {
    vec![
        SymbolicOrder::Exact(83),
        SymbolicOrder::Exact(83 * 2),
        SymbolicOrder::Exact(83 * 41),
        SymbolicOrder::Exact(83 * 82),
        SymbolicOrder::Factorial83Over2,
        SymbolicOrder::Factorial83,
    ]
}

#[cfg(test)]
fn candidate_hidden_subgroup_sizes() -> Vec<SymbolicOrder> {
    // The wiki shorthand `{1,2,41,82,...}` hides the enormous stabilizers for
    // the `A_83` and `S_83` cases; keep those symbolic to avoid overflowing
    // ordinary integer types.
    vec![
        SymbolicOrder::Exact(1),
        SymbolicOrder::Exact(2),
        SymbolicOrder::Exact(41),
        SymbolicOrder::Exact(82),
        SymbolicOrder::Factorial82Over2,
        SymbolicOrder::Factorial82,
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        DihedralVerdict, SymbolicOrder, TransitivityConfig, candidate_group_orders,
        candidate_hidden_subgroup_sizes, run_transitivity,
    };
    use crate::chaining_graph::{ContextId, DEFAULT_CORE_LEN, DEFAULT_WINDOW_LEN, compute_graph};
    use crate::orders;

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
        let graph = compute_graph(&messages, DEFAULT_WINDOW_LEN, DEFAULT_CORE_LEN).unwrap();
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
        let graph = compute_graph(&messages, DEFAULT_WINDOW_LEN, DEFAULT_CORE_LEN).unwrap();
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

    fn display(value: crate::trigram::TrigramValue) -> char {
        char::from_u32(u32::from(value.get()) + 32).unwrap()
    }
}
