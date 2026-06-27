//! Thread 5 graph-chaining audit for the Noita eye-glyph puzzle.
//!
//! This module tests the mapping-independent chaining claims documented in
//! `eye-messages.wiki/Graph-Chaining.md`, `Alphabet-Chaining.md`,
//! `Chaining-Conflicts.md`, and `Chaining-Conflict-Rates.md`. It works only
//! with reading-layer ciphertext symbol equality and the observed action of one
//! aligned isomorph occurrence on another. It does not attach meanings to
//! symbols.

use std::cmp::Ordering;
use std::fmt;

use crate::analysis::orders::{self, GridError, ReadingOrder, read_corpus_message_values};

mod graph;
mod nulls;
mod report;
#[cfg(test)]
mod tests;

use graph::validate_config;
pub(crate) use graph::{GraphComputation, compute_graph, find_context};
#[cfg(test)]
use graph::{OccurrenceMetadata, catalogue_from_links};
#[cfg(test)]
use nulls::{positive_control_fixture, positive_control_null_max};
use nulls::{run_positive_control, run_shuffle_null};

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
pub type SymbolValue = crate::core::trigram::TrigramValue;

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
}

impl From<GridError> for ChainingGraphError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for ChainingGraphError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl fmt::Display for ChainingGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => write!(f, "at least one Monte-Carlo trial is required"),
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "random draw bound {bound} is too large")
            }
            Self::WindowLengthMismatch => {
                write!(f, "aligned isomorph windows had different lengths")
            }
            Self::InvalidWindowConfig {
                window_len,
                core_len,
            } => write!(
                f,
                "invalid isomorph window/core configuration: window {window_len}, core {core_len}"
            ),
            Self::ContextCountTooLarge { contexts } => write!(
                f,
                "generated {contexts} contexts, more than the ContextId range can represent"
            ),
            Self::ControlSymbolOutOfRange { value } => {
                write!(
                    f,
                    "positive-control symbol {value} is outside the reading-layer range"
                )
            }
            Self::PositiveControlFailed {
                conflicts,
                null_max_conflicts,
                required_margin,
                expected_symbols,
                observed_symbols,
            } => write!(
                f,
                "positive control failed: real conflicts {conflicts}, null max {null_max_conflicts}, required margin {required_margin}, expected {expected_symbols} touched symbols, observed {observed_symbols}"
            ),
        }
    }
}

impl std::error::Error for ChainingGraphError {}

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
        .map(crate::analysis::orders::GlyphGrid::message_key)
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
