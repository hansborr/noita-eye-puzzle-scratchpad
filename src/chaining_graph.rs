//! Thread 5 graph-chaining audit for the Noita eye-glyph puzzle.
//!
//! This module tests the mapping-independent chaining claims documented in
//! `eye-messages.wiki/Graph-Chaining.md`, `Alphabet-Chaining.md`,
//! `Chaining-Conflicts.md`, and `Chaining-Conflict-Rates.md`. It works only
//! with reading-layer ciphertext symbol equality and the observed action of one
//! aligned isomorph occurrence on another. It does not attach meanings to
//! symbols.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::isomorph::PatternSignature;
use crate::null::{SplitMix64, fisher_yates, shuffled_permutation, stateless_splitmix};
use crate::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::trigram::TrigramValue;

/// Default deterministic Monte-Carlo seed for the chaining-graph audit.
pub const DEFAULT_SEED: u64 = 0x6368_6169_6e67_7266;
/// Default within-message shuffle trial count.
pub const DEFAULT_TRIALS: usize = 1_000;
/// Default isomorph window length used by the wiki D166 triple.
pub const DEFAULT_WINDOW_LEN: usize = 11;
/// Default repeated-core length; later columns are reported as extensions.
pub const DEFAULT_CORE_LEN: usize = 9;
/// Minimum conflict-count headroom required over the positive-control shuffle null.
pub const POSITIVE_CONTROL_MIN_MARGIN: usize = 4;

const POSITIVE_CONTROL_NULL_TRIALS: usize = 64;
const POSITIVE_CONTROL_MAX_DRAWS: u64 = 64;
const POSITIVE_CONTROL_STACKS: usize = 5;
const POSITIVE_CONTROL_STREAM_LEN: usize = 80;

/// An opaque identifier for a context (the transformation between two aligned
/// isomorph occurrences). Contexts are never resolved to a group element; only
/// their *action* (a set of chain links) is observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextId(u32);

impl ContextId {
    /// Return the stable numeric identifier for display or deterministic sorting.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Construct an opaque context identifier inside the crate.
    #[must_use]
    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }
}

/// A reading-layer ciphertext symbol value (0..=82).
pub type SymbolValue = crate::trigram::TrigramValue;

/// One observed `symbol -> symbol` mapping under a fixed context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainLink {
    /// The context whose action this link witnesses.
    pub context: ContextId,
    /// Source ciphertext symbol.
    pub from: SymbolValue,
    /// Image ciphertext symbol under the context's action.
    pub to: SymbolValue,
    /// Provenance of the aligned column this link was read from.
    pub provenance: LinkProvenance,
}

/// Where a chain link came from, so fragile columns can be audited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkProvenance {
    /// Index of the upper occurrence's message in the corpus.
    pub upper_message: usize,
    /// Index of the lower occurrence's message in the corpus.
    pub lower_message: usize,
    /// Aligned column within the isomorph window.
    pub column: usize,
    /// Whether this column lies inside the twice-repeated isomorph core.
    pub in_repeated_core: bool,
}

/// An aligned isomorph occurrence: a window into one message's value stream.
#[derive(Clone, Copy, Debug)]
pub struct AlignedOccurrence<'a> {
    /// Corpus message index this occurrence is read from.
    pub message: usize,
    /// The window's value slice.
    pub window: &'a [SymbolValue],
    /// Leading columns that belong to the repeated core.
    pub core_len: usize,
}

/// Build chain links from one aligned isomorph occurrence pair.
///
/// The two windows must be equal length and from the same equality-pattern
/// signature. Links are emitted for every aligned column in the supplied window;
/// columns at or beyond either occurrence's `core_len` are flagged as
/// over-extension links rather than being discarded.
///
/// # Errors
/// Returns [`ChainingGraphError::WindowLengthMismatch`] if the windows differ
/// in length.
pub fn chain_links_for_pair(
    context: ContextId,
    upper: &AlignedOccurrence<'_>,
    lower: &AlignedOccurrence<'_>,
) -> Result<Vec<ChainLink>, ChainingGraphError> {
    if upper.window.len() != lower.window.len() {
        return Err(ChainingGraphError::WindowLengthMismatch);
    }

    let mut links = Vec::with_capacity(upper.window.len());
    for (column, (from, to)) in upper.window.iter().zip(lower.window.iter()).enumerate() {
        links.push(ChainLink {
            context,
            from: *from,
            to: *to,
            provenance: LinkProvenance {
                upper_message: upper.message,
                lower_message: lower.message,
                column,
                in_repeated_core: column < upper.core_len && column < lower.core_len,
            },
        });
    }
    Ok(links)
}

/// A witnessed non-commutativity between two observed contexts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainingConflict {
    /// First context.
    pub a: ContextId,
    /// Second context.
    pub b: ContextId,
    /// Shared start symbol.
    pub start: SymbolValue,
    /// Image of `start` under `a` then `b`.
    pub ab_image: SymbolValue,
    /// Image of `start` under `b` then `a`.
    pub ba_image: SymbolValue,
    /// True when every link used by the conflict has repeated-core support.
    pub robust: bool,
}

/// Tabulated conflict evidence for observed graph-chaining non-commutativity.
#[derive(Clone, Debug, PartialEq)]
pub struct ConflictCatalogue {
    /// Every distinct conflict found.
    pub conflicts: Vec<ChainingConflict>,
    /// Total conflict count.
    pub total: usize,
    /// Count whose four composed links use distinct provenance columns.
    pub independent: usize,
    /// Count flagged fragile by over-extension provenance.
    pub fragile: usize,
}

/// Connected-component coverage of the chain-link graph over the 83 symbols.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageReport {
    /// Number of distinct symbols touched by at least one chain link.
    pub symbols_touched: usize,
    /// Size of the largest connected component.
    pub largest_component: usize,
    /// Number of connected components among touched symbols.
    pub component_count: usize,
    /// Number of distinct symbols touched by at least one repeated-core link.
    pub core_supported_symbols: usize,
    /// Size of the largest repeated-core-only connected component.
    pub core_largest_component: usize,
    /// Number of repeated-core-only connected components among touched symbols.
    pub core_supported_components: usize,
    /// Alphabet size used for the denominator.
    pub alphabet_size: usize,
}

/// Minimal union-find over `0..alphabet_size`.
#[derive(Clone, Debug)]
pub struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl UnionFind {
    /// Create a forest of `n` singletons.
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    /// Union the sets containing `x` and `y`; out-of-range indices are ignored.
    pub fn union(&mut self, x: usize, y: usize) {
        let (Some(root_x), Some(root_y)) = (self.find(x), self.find(y)) else {
            return;
        };
        if root_x == root_y {
            return;
        }

        let rank_x = self.rank.get(root_x).copied().unwrap_or_default();
        let rank_y = self.rank.get(root_y).copied().unwrap_or_default();
        match rank_x.cmp(&rank_y) {
            Ordering::Less => {
                if let Some(parent) = self.parent.get_mut(root_x) {
                    *parent = root_y;
                }
            }
            Ordering::Greater => {
                if let Some(parent) = self.parent.get_mut(root_y) {
                    *parent = root_x;
                }
            }
            Ordering::Equal => {
                if let Some(parent) = self.parent.get_mut(root_y) {
                    *parent = root_x;
                }
                if let Some(rank) = self.rank.get_mut(root_x) {
                    *rank = rank.saturating_add(1);
                }
            }
        }
    }

    /// Representative of `x`'s set. Returns `None` for out-of-range indices.
    pub fn find(&mut self, x: usize) -> Option<usize> {
        if x >= self.parent.len() {
            return None;
        }
        let root = self.find_root(x)?;
        self.compress_path(x, root)?;
        Some(root)
    }

    fn find_root(&self, x: usize) -> Option<usize> {
        let mut root = x;
        loop {
            let parent = self.parent.get(root).copied()?;
            if parent == root {
                return Some(root);
            }
            root = parent;
        }
    }

    fn compress_path(&mut self, x: usize, root: usize) -> Option<()> {
        let mut node = x;
        loop {
            let parent = self.parent.get(node).copied()?;
            if parent == root {
                return Some(());
            }
            if let Some(slot) = self.parent.get_mut(node) {
                *slot = root;
            }
            node = parent;
        }
    }
}

/// Configuration for the chaining-graph audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainingGraphConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of within-message shuffle trials.
    pub trials: usize,
    /// Isomorph window length to align.
    pub window_len: usize,
    /// Leading columns counted as the repeated core.
    pub core_len: usize,
}

impl Default for ChainingGraphConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
            window_len: DEFAULT_WINDOW_LEN,
            core_len: DEFAULT_CORE_LEN,
        }
    }
}

/// Error returned by the chaining-graph audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainingGraphError {
    /// The verified corpus could not be reconstructed or read with the order.
    Grid(GridError),
    /// At least one Monte-Carlo trial is required.
    ZeroTrials,
    /// A shuffle or permutation bound did not fit the PRNG helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// Aligned windows had different lengths.
    WindowLengthMismatch,
    /// Configured isomorph window/core lengths were invalid.
    InvalidWindowConfig {
        /// Requested isomorph window length.
        window_len: usize,
        /// Requested repeated-core length.
        core_len: usize,
    },
    /// More context pairs were generated than [`ContextId`] can represent.
    ContextCountTooLarge {
        /// Number of context pairs requested.
        contexts: usize,
    },
    /// A generated control symbol could not be represented as a trigram value.
    ControlSymbolOutOfRange {
        /// Offending numeric value.
        value: usize,
    },
    /// The non-commutative positive control did not recover the planted signal.
    PositiveControlFailed {
        /// Recovered conflict count.
        conflicts: usize,
        /// Largest conflict count seen in the matched shuffle null.
        null_max_conflicts: usize,
        /// Required strict conflict margin over the shuffle-null maximum.
        required_margin: usize,
        /// Expected number of touched symbols.
        expected_symbols: usize,
        /// Observed number of touched symbols.
        observed_symbols: usize,
    },
    /// The configured trial count was too large for add-one calibration.
    TrialCountTooLarge,
}

impl From<GridError> for ChainingGraphError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<crate::null::RandomBoundError> for ChainingGraphError {
    fn from(error: crate::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

/// Monte-Carlo band for one integer statistic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NullStatisticBand {
    /// Number of shuffle trials sampled.
    pub trials: usize,
    /// Mean sampled value.
    pub mean: f64,
    /// Lower pointwise 95% percentile edge.
    pub q025: usize,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: usize,
    /// Largest sampled value.
    pub max: usize,
}

/// Real-vs-null comparison for one chaining-graph statistic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NullStatistic {
    /// Real statistic value.
    pub real: usize,
    /// Shuffle-null distribution band.
    pub band: NullStatisticBand,
    /// Number of shuffles at least as extreme as the real value.
    pub empirical_p_count: usize,
    /// Add-one Monte-Carlo p-value.
    pub empirical_p: f64,
}

/// Matched within-message shuffle null for conflicts and coverage.
#[derive(Clone, Debug, PartialEq)]
pub struct ConflictCoverageNull {
    /// Total conflict-count upper-tail comparison.
    pub total_conflicts: NullStatistic,
    /// Independent conflict-count upper-tail comparison.
    pub independent_conflicts: NullStatistic,
    /// Touched-symbol coverage upper-tail comparison.
    pub symbols_touched: NullStatistic,
    /// Largest-component coverage upper-tail comparison.
    pub largest_component: NullStatistic,
    /// Component-count lower-tail comparison.
    pub component_count: NullStatistic,
}

/// Synthetic non-commutative GAK positive-control outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositiveControlOutcome {
    /// Number of conflicts recovered from the planted fixture.
    pub conflicts: usize,
    /// Expected touched-symbol count in the planted fixture.
    pub planted_symbols: usize,
    /// Observed touched-symbol count in the recovered graph.
    pub observed_symbols: usize,
    /// Largest conflict count seen in the control shuffle null.
    pub null_max_conflicts: usize,
    /// Observed conflict-count headroom over the control shuffle null.
    pub conflict_margin: usize,
    /// Required strict conflict-count headroom over the control shuffle null.
    pub required_margin: usize,
    /// Whether the positive control recovered the planted signal.
    pub passed: bool,
}

/// Complete chaining-graph report for the accepted eye stream.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainingGraphReport {
    /// Configuration used for the run.
    pub config: ChainingGraphConfig,
    /// Reading order used for the real and shuffled streams.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Conflict catalogue for the real corpus.
    pub catalogue: ConflictCatalogue,
    /// Connected-component coverage for the real corpus.
    pub coverage: CoverageReport,
    /// Matched within-message shuffle null.
    pub null: ConflictCoverageNull,
    /// Synthetic non-commutative GAK positive-control result.
    pub positive_control: PositiveControlOutcome,
}

/// Runs the chaining-graph audit on the verified eye corpus.
///
/// # Errors
/// Returns [`ChainingGraphError`] when the corpus cannot be reconstructed, when
/// the accepted reading order is incompatible with a grid, when the
/// configuration is invalid, or when the synthetic positive control fails.
pub fn run_chaining_graph(
    config: ChainingGraphConfig,
) -> Result<ChainingGraphReport, ChainingGraphError> {
    validate_config(config)?;
    let grids = orders::corpus_grids()?;
    let keys: Vec<&'static str> = grids
        .iter()
        .map(crate::orders::GlyphGrid::message_key)
        .collect();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    let computation = compute_graph(&message_values, config.window_len, config.core_len)?;
    let null = run_shuffle_null(config, &message_values, &computation)?;
    let positive_control = run_positive_control(config.seed, config.window_len, config.core_len)?;
    let message_lengths = keys
        .iter()
        .copied()
        .zip(message_values.iter().map(Vec::len))
        .collect();

    Ok(ChainingGraphReport {
        config,
        order,
        message_lengths,
        catalogue: computation.catalogue,
        coverage: computation.coverage,
        null,
        positive_control,
    })
}

pub(crate) fn compute_graph(
    message_values: &[Vec<SymbolValue>],
    window_len: usize,
    core_len: usize,
) -> Result<GraphComputation, ChainingGraphError> {
    let occurrences = collect_occurrences(message_values, window_len, core_len);
    let (links, contexts) = links_for_occurrences(&occurrences)?;
    let catalogue = catalogue_from_contexts(&links, &contexts);
    let coverage = coverage_from_links(&links, orders::READING_LAYER_ALPHABET_SIZE);
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

fn validate_config(config: ChainingGraphConfig) -> Result<(), ChainingGraphError> {
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

fn run_shuffle_null(
    config: ChainingGraphConfig,
    message_values: &[Vec<SymbolValue>],
    real: &GraphComputation,
) -> Result<ConflictCoverageNull, ChainingGraphError> {
    let mut rng = SplitMix64::new(config.seed);
    let mut samples = NullSamples::default();
    for _trial in 0..config.trials {
        let shuffled = shuffled_messages(message_values, &mut rng)?;
        let graph = compute_graph(&shuffled, config.window_len, config.core_len)?;
        samples.push(&graph.catalogue, &graph.coverage);
    }
    samples.into_null(real, config.trials)
}

fn shuffled_messages(
    message_values: &[Vec<SymbolValue>],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<SymbolValue>>, ChainingGraphError> {
    let mut shuffled = message_values.to_vec();
    for values in &mut shuffled {
        fisher_yates(values, rng)?;
    }
    Ok(shuffled)
}

#[derive(Default)]
struct NullSamples {
    total_conflicts: Vec<usize>,
    independent_conflicts: Vec<usize>,
    symbols_touched: Vec<usize>,
    largest_component: Vec<usize>,
    component_count: Vec<usize>,
}

impl NullSamples {
    fn push(&mut self, catalogue: &ConflictCatalogue, coverage: &CoverageReport) {
        self.total_conflicts.push(catalogue.total);
        self.independent_conflicts.push(catalogue.independent);
        self.symbols_touched.push(coverage.symbols_touched);
        self.largest_component.push(coverage.largest_component);
        self.component_count.push(coverage.component_count);
    }

    fn into_null(
        self,
        real: &GraphComputation,
        trials: usize,
    ) -> Result<ConflictCoverageNull, ChainingGraphError> {
        Ok(ConflictCoverageNull {
            total_conflicts: upper_tail_stat(real.catalogue.total, &self.total_conflicts, trials)?,
            independent_conflicts: upper_tail_stat(
                real.catalogue.independent,
                &self.independent_conflicts,
                trials,
            )?,
            symbols_touched: upper_tail_stat(
                real.coverage.symbols_touched,
                &self.symbols_touched,
                trials,
            )?,
            largest_component: upper_tail_stat(
                real.coverage.largest_component,
                &self.largest_component,
                trials,
            )?,
            component_count: lower_tail_stat(
                real.coverage.component_count,
                &self.component_count,
                trials,
            )?,
        })
    }
}

fn upper_tail_stat(
    real: usize,
    samples: &[usize],
    trials: usize,
) -> Result<NullStatistic, ChainingGraphError> {
    let empirical_p_count = samples.iter().filter(|sample| **sample >= real).count();
    Ok(NullStatistic {
        real,
        band: null_band(samples),
        empirical_p_count,
        empirical_p: add_one_p_value(empirical_p_count, trials)?,
    })
}

fn lower_tail_stat(
    real: usize,
    samples: &[usize],
    trials: usize,
) -> Result<NullStatistic, ChainingGraphError> {
    let empirical_p_count = samples.iter().filter(|sample| **sample <= real).count();
    Ok(NullStatistic {
        real,
        band: null_band(samples),
        empirical_p_count,
        empirical_p: add_one_p_value(empirical_p_count, trials)?,
    })
}

fn null_band(samples: &[usize]) -> NullStatisticBand {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    NullStatisticBand {
        trials: samples.len(),
        mean: mean(samples),
        q025: quantile_from_sorted(&sorted, 25, 1_000),
        median: median(&sorted),
        q975: quantile_from_sorted(&sorted, 975, 1_000),
        max: sorted.last().copied().unwrap_or_default(),
    }
}

fn add_one_p_value(count: usize, trials: usize) -> Result<f64, ChainingGraphError> {
    let numerator = count
        .checked_add(1)
        .ok_or(ChainingGraphError::TrialCountTooLarge)?;
    let denominator = trials
        .checked_add(1)
        .ok_or(ChainingGraphError::TrialCountTooLarge)?;
    Ok(numerator as f64 / denominator as f64)
}

fn mean(samples: &[usize]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.iter().sum::<usize>() as f64 / samples.len() as f64
}

fn median(sorted: &[usize]) -> f64 {
    let len = sorted.len();
    if len == 0 {
        return 0.0;
    }
    let middle = len / 2;
    if len.is_multiple_of(2) {
        match (
            sorted.get(middle.saturating_sub(1)).copied(),
            sorted.get(middle).copied(),
        ) {
            (Some(left), Some(right)) => f64::midpoint(left as f64, right as f64),
            _ => 0.0,
        }
    } else {
        sorted
            .get(middle)
            .copied()
            .map_or(0.0, |value| value as f64)
    }
}

fn quantile_from_sorted(sorted: &[usize], numerator: usize, denominator: usize) -> usize {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or_default()
}

fn scaled_quantile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 || denominator == 0 {
        return 0;
    }
    len.saturating_sub(1).saturating_mul(numerator) / denominator
}

fn run_positive_control(
    seed: u64,
    window_len: usize,
    core_len: usize,
) -> Result<PositiveControlOutcome, ChainingGraphError> {
    let fixture = positive_control_fixture(seed, window_len, core_len)?;
    let graph = compute_graph(&fixture.streams, window_len, core_len)?;
    let null_max_conflicts = positive_control_null_max(&fixture, seed, window_len, core_len)?;
    let conflict_margin = graph.catalogue.total.saturating_sub(null_max_conflicts);
    let passed = graph.catalogue.total
        > null_max_conflicts.saturating_add(POSITIVE_CONTROL_MIN_MARGIN)
        && graph.coverage.symbols_touched >= fixture.planted_symbols;
    if !passed {
        return Err(ChainingGraphError::PositiveControlFailed {
            conflicts: graph.catalogue.total,
            null_max_conflicts,
            required_margin: POSITIVE_CONTROL_MIN_MARGIN,
            expected_symbols: fixture.planted_symbols,
            observed_symbols: graph.coverage.symbols_touched,
        });
    }
    Ok(PositiveControlOutcome {
        conflicts: graph.catalogue.total,
        planted_symbols: fixture.planted_symbols,
        observed_symbols: graph.coverage.symbols_touched,
        null_max_conflicts,
        conflict_margin,
        required_margin: POSITIVE_CONTROL_MIN_MARGIN,
        passed,
    })
}

#[derive(Clone, Debug)]
struct PositiveControlFixture {
    streams: Vec<Vec<SymbolValue>>,
    planted_symbols: usize,
}

#[derive(Clone, Debug)]
struct PositiveControlBase {
    stream: Vec<SymbolValue>,
    planted_windows: Vec<Vec<SymbolValue>>,
}

fn positive_control_fixture(
    seed: u64,
    window_len: usize,
    core_len: usize,
) -> Result<PositiveControlFixture, ChainingGraphError> {
    if window_len < 4 || core_len > window_len {
        return Err(ChainingGraphError::InvalidWindowConfig {
            window_len,
            core_len,
        });
    }

    let (a, b) = non_commuting_permutations(seed)?;
    let base = positive_control_base_stream(&a, &b, window_len)?;
    let a_stream = apply_permutation_window(&a, &base.stream)?;
    let b_stream = apply_permutation_window(&b, &base.stream)?;
    let planted_symbols = planted_symbol_count_from_windows(&base.planted_windows, &a, &b)?;
    Ok(PositiveControlFixture {
        streams: vec![base.stream, a_stream, b_stream],
        planted_symbols,
    })
}

fn positive_control_base_stream(
    a: &[usize],
    b: &[usize],
    window_len: usize,
) -> Result<PositiveControlBase, ChainingGraphError> {
    let stack_count = POSITIVE_CONTROL_STACKS.min(window_len.saturating_sub(3));
    if stack_count == 0 {
        return Err(positive_control_failure(0, 0, 0, 0));
    }

    let mut used = BTreeSet::new();
    let mut stream = Vec::new();
    let mut planted_windows = Vec::with_capacity(stack_count);
    for stack_index in 0..stack_count {
        if !stream.is_empty() {
            append_control_filler(&mut stream, &mut used, 1)?;
        }
        let Some(start) = next_non_commuting_start(a, b, &used) else {
            return Err(positive_control_failure(0, 0, 0, 0));
        };
        let duplicate_gap = 3usize.saturating_add(stack_index);
        let window =
            positive_control_base_window(a, b, start, window_len, duplicate_gap, &mut used)?;
        stream.extend(window.iter().copied());
        planted_windows.push(window);
    }

    while stream.len() < POSITIVE_CONTROL_STREAM_LEN {
        append_control_filler(&mut stream, &mut used, 1)?;
    }

    Ok(PositiveControlBase {
        stream,
        planted_windows,
    })
}

fn positive_control_null_max(
    fixture: &PositiveControlFixture,
    seed: u64,
    window_len: usize,
    core_len: usize,
) -> Result<usize, ChainingGraphError> {
    let mut rng = SplitMix64::new(stateless_splitmix(seed ^ 0x7063_6e75_6c6c_0001));
    let mut max_conflicts = 0usize;
    for _trial in 0..POSITIVE_CONTROL_NULL_TRIALS {
        let shuffled = shuffled_messages(&fixture.streams, &mut rng)?;
        let graph = compute_graph(&shuffled, window_len, core_len)?;
        max_conflicts = max_conflicts.max(graph.catalogue.total);
    }
    Ok(max_conflicts)
}

fn non_commuting_permutations(seed: u64) -> Result<(Vec<usize>, Vec<usize>), ChainingGraphError> {
    for attempt in 0_u64..POSITIVE_CONTROL_MAX_DRAWS {
        let mut rng_a = SplitMix64::new(stateless_splitmix(seed ^ 0x7063_7472_6c61_0000 ^ attempt));
        let mut rng_b = SplitMix64::new(stateless_splitmix(seed ^ 0x7063_7472_6c62_0000 ^ attempt));
        let a = shuffled_permutation(orders::READING_LAYER_ALPHABET_SIZE, &mut rng_a)?;
        let b = shuffled_permutation(orders::READING_LAYER_ALPHABET_SIZE, &mut rng_b)?;
        if first_non_commuting_start(&a, &b).is_some() {
            return Ok((a, b));
        }
    }
    Err(positive_control_failure(0, 0, 0, 0))
}

fn first_non_commuting_start(a: &[usize], b: &[usize]) -> Option<usize> {
    (0..a.len().min(b.len())).find(|start| non_commutes_at(a, b, *start))
}

fn next_non_commuting_start(a: &[usize], b: &[usize], used: &BTreeSet<usize>) -> Option<usize> {
    for start in 0..a.len().min(b.len()) {
        let Some(a_start) = a.get(start).copied() else {
            continue;
        };
        let Some(b_start) = b.get(start).copied() else {
            continue;
        };
        if start == a_start || start == b_start || a_start == b_start {
            continue;
        }
        if used.contains(&start) || used.contains(&a_start) || used.contains(&b_start) {
            continue;
        }
        if non_commutes_at(a, b, start) {
            return Some(start);
        }
    }
    None
}

fn non_commutes_at(a: &[usize], b: &[usize], start: usize) -> bool {
    let Some(a_start) = a.get(start).copied() else {
        return false;
    };
    let Some(b_start) = b.get(start).copied() else {
        return false;
    };
    let Some(ab) = b.get(a_start).copied() else {
        return false;
    };
    let Some(ba) = a.get(b_start).copied() else {
        return false;
    };
    ab != ba
}

fn positive_control_base_window(
    a: &[usize],
    b: &[usize],
    start: usize,
    window_len: usize,
    duplicate_gap: usize,
    used: &mut BTreeSet<usize>,
) -> Result<Vec<SymbolValue>, ChainingGraphError> {
    let Some(a_start) = a.get(start).copied() else {
        return Err(positive_control_failure(0, 0, 0, 0));
    };
    let Some(b_start) = b.get(start).copied() else {
        return Err(positive_control_failure(0, 0, 0, 0));
    };

    let mut selected = BTreeSet::new();
    for value in [start, a_start, b_start] {
        if used.contains(&value) || !selected.insert(value) {
            return Err(positive_control_failure(0, 0, 0, 0));
        }
    }

    let mut slots = vec![None; window_len];
    set_control_window_slot(&mut slots, 0, start)?;
    set_control_window_slot(&mut slots, 1, a_start)?;
    set_control_window_slot(&mut slots, 2, b_start)?;
    set_control_window_slot(&mut slots, duplicate_gap, start)?;

    for slot in &mut slots {
        if slot.is_some() {
            continue;
        }
        let Some(value) = next_unused_control_symbol(used, &selected) else {
            return Err(positive_control_failure(0, 0, 0, 0));
        };
        let _inserted = selected.insert(value);
        *slot = Some(value);
    }

    for value in &selected {
        let _inserted = used.insert(*value);
    }

    slots
        .into_iter()
        .map(|value| {
            value
                .ok_or_else(|| positive_control_failure(0, 0, 0, 0))
                .and_then(symbol_from_usize)
        })
        .collect()
}

fn set_control_window_slot(
    slots: &mut [Option<usize>],
    column: usize,
    value: usize,
) -> Result<(), ChainingGraphError> {
    let Some(slot) = slots.get_mut(column) else {
        return Err(positive_control_failure(0, 0, 0, 0));
    };
    if slot.is_some() {
        return Err(positive_control_failure(0, 0, 0, 0));
    }
    *slot = Some(value);
    Ok(())
}

fn append_control_filler(
    stream: &mut Vec<SymbolValue>,
    used: &mut BTreeSet<usize>,
    count: usize,
) -> Result<(), ChainingGraphError> {
    let selected = BTreeSet::new();
    for _item in 0..count {
        let Some(value) = next_unused_control_symbol(used, &selected) else {
            return Err(positive_control_failure(0, 0, 0, 0));
        };
        let _inserted = used.insert(value);
        stream.push(symbol_from_usize(value)?);
    }
    Ok(())
}

fn next_unused_control_symbol(used: &BTreeSet<usize>, selected: &BTreeSet<usize>) -> Option<usize> {
    (0..orders::READING_LAYER_ALPHABET_SIZE)
        .find(|value| !used.contains(value) && !selected.contains(value))
}

fn apply_permutation_window(
    permutation: &[usize],
    window: &[SymbolValue],
) -> Result<Vec<SymbolValue>, ChainingGraphError> {
    let mut output = Vec::with_capacity(window.len());
    for symbol in window {
        let index = usize::from(symbol.get());
        let Some(image) = permutation.get(index).copied() else {
            return Err(ChainingGraphError::ControlSymbolOutOfRange { value: index });
        };
        output.push(symbol_from_usize(image)?);
    }
    Ok(output)
}

fn symbol_from_usize(value: usize) -> Result<SymbolValue, ChainingGraphError> {
    let raw = u8::try_from(value)
        .map_err(|_error| ChainingGraphError::ControlSymbolOutOfRange { value })?;
    TrigramValue::new(raw).map_err(|bad| ChainingGraphError::ControlSymbolOutOfRange {
        value: usize::from(bad),
    })
}

fn planted_symbol_count_from_windows(
    windows: &[Vec<SymbolValue>],
    a: &[usize],
    b: &[usize],
) -> Result<usize, ChainingGraphError> {
    let mut symbols = BTreeSet::new();
    for window in windows {
        for symbol in window {
            let index = usize::from(symbol.get());
            let Some(a_image) = a.get(index).copied() else {
                return Err(ChainingGraphError::ControlSymbolOutOfRange { value: index });
            };
            let Some(b_image) = b.get(index).copied() else {
                return Err(ChainingGraphError::ControlSymbolOutOfRange { value: index });
            };
            let _inserted = symbols.insert(*symbol);
            let _inserted = symbols.insert(symbol_from_usize(a_image)?);
            let _inserted = symbols.insert(symbol_from_usize(b_image)?);
        }
    }
    Ok(symbols.len())
}

fn positive_control_failure(
    conflicts: usize,
    null_max_conflicts: usize,
    expected_symbols: usize,
    observed_symbols: usize,
) -> ChainingGraphError {
    ChainingGraphError::PositiveControlFailed {
        conflicts,
        null_max_conflicts,
        required_margin: POSITIVE_CONTROL_MIN_MARGIN,
        expected_symbols,
        observed_symbols,
    }
}

#[cfg(test)]
mod tests {
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
}
