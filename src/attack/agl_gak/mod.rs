//! Thread 2 AGL(1,83)-GAK stress test.
//!
//! This module tests only mapping-independent structure: ciphertext-symbol
//! equality, accepted reading-layer streams, and the AGL point-stabilizer group
//! model. It does not assign symbols to plaintext meanings.

use std::fmt;

use crate::analysis::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::ciphers::{self, AglMultiplierSubgroup};
use crate::core::trigram::TrigramValue;
use crate::nulls::perseus::{self, PerseusError, SharedRunRole};

mod groups;
mod report;
mod robustness;
#[cfg(test)]
mod tests;

use groups::{
    agreement_check, distinct_symbols_in_run, fixed_point_enumeration, forward_simulation,
    message_index, positive_controls, predecessor_differs, stream_at, subgroups_to_run,
    validate_positive_controls,
};
pub use robustness::{
    AglGakRobustnessBreak, AglGakRobustnessBreakReason, AglGakRobustnessSummary,
    AglGakTranscriptionFootprint, AglGakTranscriptionRobustness,
};

/// Default deterministic seed for the AGL-GAK stress-test controls.
pub const DEFAULT_SEED: u64 = 0x6167_6c5f_6761_6b00;
/// Default number of forward-simulation null trials per subgroup.
pub const DEFAULT_NULL_TRIALS: usize = 2_000_000;

const AGREEMENT_CHECKS: usize = 40_000;
const ALPHABET_SIZE: usize = ciphers::EYE_READING_ALPHABET_SIZE;
const CONTROL_FIXED_POINT: usize = 42;

/// Which parts of the AGL-GAK stress test to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AglGakMode {
    /// Run the structural feasibility/exclusion test only.
    FeasibilityOnly,
    /// Request the bounded fit phase after feasibility.
    FeasibilityAndFit,
}

/// Configuration for the AGL-GAK stress test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AglGakConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of forward-simulation null trials per subgroup.
    pub null_trials: usize,
    /// Requested mode.
    pub mode: AglGakMode,
    /// Preferred subgroup ordering for the report; both AGL variants are run.
    pub subgroup: AglMultiplierSubgroup,
}

impl Default for AglGakConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            null_trials: DEFAULT_NULL_TRIALS,
            mode: AglGakMode::FeasibilityOnly,
            subgroup: AglMultiplierSubgroup::Full,
        }
    }
}

/// Error returned by the AGL-GAK stress test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AglGakError {
    /// The verified corpus could not be reconstructed or read.
    Grid(GridError),
    /// An AGL-GAK cipher primitive failed validation.
    Cipher(ciphers::CipherError),
    /// A deterministic random draw failed.
    Random(crate::nulls::null::RandomBoundError),
    /// Shared-run reconstruction failed.
    Perseus(PerseusError),
    /// At least one forward-simulation trial is required.
    ZeroTrials,
    /// A required positive or negative control failed.
    PositiveControlFailed {
        /// Name of the failing control.
        which: &'static str,
    },
    /// A corpus message unexpectedly had no first reading-layer symbol.
    EmptyMessage {
        /// Message key.
        message_key: &'static str,
    },
    /// A reading-layer value exceeded the accepted 83-symbol alphabet.
    ValueOutsideAlphabet {
        /// Message key.
        message_key: &'static str,
        /// Offending value.
        value: usize,
    },
    /// A reconstructed shared run exceeded a message boundary.
    SharedRunOutOfBounds {
        /// Message key.
        message_key: &'static str,
        /// Zero-based shared-run start offset.
        start: usize,
        /// Shared-run length.
        len: usize,
    },
    /// An internal invariant failed.
    InternalInvariant {
        /// Human-readable context.
        context: &'static str,
    },
}

impl From<GridError> for AglGakError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<ciphers::CipherError> for AglGakError {
    fn from(value: ciphers::CipherError) -> Self {
        Self::Cipher(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for AglGakError {
    fn from(value: crate::nulls::null::RandomBoundError) -> Self {
        Self::Random(value)
    }
}

impl From<PerseusError> for AglGakError {
    fn from(value: PerseusError) -> Self {
        Self::Perseus(value)
    }
}

impl fmt::Display for AglGakError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(error) => write!(f, "grid/order error: {error:?}"),
            Self::Cipher(error) => write!(f, "AGL-GAK cipher error: {error}"),
            Self::Random(error) => write!(f, "random draw bound {} is too large", error.bound),
            Self::Perseus(error) => write!(f, "shared-run reconstruction error: {error:?}"),
            Self::ZeroTrials => write!(f, "at least one forward-simulation trial is required"),
            Self::PositiveControlFailed { which } => write!(f, "positive control failed: {which}"),
            Self::EmptyMessage { message_key } => {
                write!(f, "message {message_key} has no reading-layer symbols")
            }
            Self::ValueOutsideAlphabet { message_key, value } => write!(
                f,
                "message {message_key} value {value} is outside the 83-symbol alphabet"
            ),
            Self::SharedRunOutOfBounds {
                message_key,
                start,
                len,
            } => write!(
                f,
                "shared run {message_key}@{start}+{len} exceeds the message boundary"
            ),
            Self::InternalInvariant { context } => {
                write!(f, "internal AGL-GAK invariant failed: {context}")
            }
        }
    }
}

impl std::error::Error for AglGakError {}

/// One observed shared run used by the AGL obstruction test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AglGakSharedRun {
    /// Left message key.
    pub left_key: &'static str,
    /// Right message key.
    pub right_key: &'static str,
    /// Zero-based start offset in both aligned messages.
    pub start: usize,
    /// Run length in reading-layer symbols.
    pub len: usize,
    /// Distinct ciphertext symbols in the shared run.
    pub distinct_symbols: usize,
    /// Whether the run contains at least two different symbols.
    pub varying: bool,
    /// Whether the immediately preceding symbols differ.
    pub differing_predecessor: bool,
    /// Perseus shared-run role that selected this run.
    pub role: SharedRunRole,
}

/// All-message shared prefix used as the tightest obstruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AglGakGlobalPrefix {
    /// Zero-based start offset.
    pub start: usize,
    /// Prefix length in reading-layer symbols.
    pub len: usize,
    /// Shared ciphertext values in order.
    pub values: Vec<usize>,
    /// Number of distinct ciphertext values in the prefix.
    pub distinct_symbols: usize,
}

/// The first varying shared run that excludes AGL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AglGakObstruction {
    /// Left message key.
    pub left_key: &'static str,
    /// Right message key.
    pub right_key: &'static str,
    /// Zero-based start offset of the shared run.
    pub start: usize,
    /// Shared-run length.
    pub len: usize,
    /// Distinct symbols in the shared run.
    pub distinct_symbols: usize,
    /// Preceding symbol from the left message.
    pub left_predecessor: usize,
    /// Preceding symbol from the right message.
    pub right_predecessor: usize,
}

/// Exhaustive fixed-point enumeration summary for one AGL subgroup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AglGakFixedPointEnumeration {
    /// Number of differing-discrepancy elements enumerated.
    pub discrepancies: usize,
    /// Number of differing discrepancies that fix at least two points.
    pub fixing_at_least_two_points: usize,
    /// Maximum number of fixed points among differing discrepancies.
    pub max_fixed_points: usize,
}

/// Algebraic agreement-rule spot-check summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AglGakAgreementCheck {
    /// Candidate configurations checked.
    pub checks: usize,
    /// Mismatches between agreement and fixed-point predicates.
    pub violations: usize,
}

/// Forward-simulation null summary for one AGL subgroup.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AglGakForwardSimulation {
    /// Number of simulated differing-start/shared-key trials.
    pub trials: usize,
    /// Count of varying shared runs found.
    pub varying_shared_runs: usize,
    /// Add-one upper-tail p-value for the observed zero count.
    pub add_one_p_value: f64,
}

/// Positive-control summary for one AGL subgroup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AglGakPositiveControls {
    /// A synthetic constant shared run was accepted as AGL-consistent.
    pub constant_shared_run_ok: bool,
    /// A pure-translation discrepancy was rejected.
    pub pure_translation_rejected_ok: bool,
    /// Recovered fixed point for the constant-run control.
    pub recovered_fixed_point: Option<usize>,
}

/// Structural verdict for one AGL subgroup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AglGakVerdict {
    /// The subgroup is structurally excluded by the varying shared-run argument.
    Excluded,
    /// The subgroup was not excluded by this structural test.
    NotExcluded,
}

/// Result for one AGL multiplier subgroup.
#[derive(Clone, Debug, PartialEq)]
pub struct AglGakSubgroupReport {
    /// Multiplier subgroup under test.
    pub subgroup: AglMultiplierSubgroup,
    /// Structural verdict for this subgroup.
    pub verdict: AglGakVerdict,
    /// First observed obstruction, if excluded.
    pub obstruction: Option<AglGakObstruction>,
    /// Exhaustive fixed-point enumeration.
    pub fixed_points: AglGakFixedPointEnumeration,
    /// Algebraic agreement-rule spot-check.
    pub agreement_check: AglGakAgreementCheck,
    /// Forward-simulation null result.
    pub forward_simulation: AglGakForwardSimulation,
    /// Positive-control result.
    pub positive_controls: AglGakPositiveControls,
    /// Whether a bounded fit phase was requested.
    pub fit_attempted: bool,
    /// Whether any structural AGL fit was found.
    pub fit_found: bool,
}

/// Complete AGL-GAK stress-test report.
#[derive(Clone, Debug, PartialEq)]
pub struct AglGakReport {
    /// Configuration used for the run.
    pub config: AglGakConfig,
    /// Accepted reading order used for the real stream.
    pub order: ReadingOrder,
    /// First reading-layer symbol for each corpus message.
    pub message_first_symbols: Vec<(&'static str, usize)>,
    /// Lengths of selected shared-run anchors from the Perseus partition.
    pub shared_run_lengths: Vec<usize>,
    /// All-message shared prefix, when reconstructed.
    pub global_prefix: Option<AglGakGlobalPrefix>,
    /// Selected shared runs tested for the varying-run obstruction.
    pub shared_runs: Vec<AglGakSharedRun>,
    /// Per-subgroup results; both `C83:C82` and `C83:C41` are included.
    pub subgroup_reports: Vec<AglGakSubgroupReport>,
    /// Whether every constant-run positive control passed.
    pub positive_control_feasible_ok: bool,
    /// Whether every pure-translation negative control passed.
    pub positive_control_infeasible_ok: bool,
    /// Source-layer perturbation sensitivity for the load-bearing prefix region.
    pub transcription_robustness: AglGakTranscriptionRobustness,
}

/// Runs the AGL-GAK structural stress test.
///
/// # Errors
/// Returns [`AglGakError`] on corpus/grid failure, shared-run reconstruction
/// failure, invalid control construction, invalid configuration, random-draw
/// failure, or a failing positive control.
pub fn run_agl_gak(config: AglGakConfig) -> Result<AglGakReport, AglGakError> {
    if config.null_trials == 0 {
        return Err(AglGakError::ZeroTrials);
    }
    let grids = orders::corpus_grids()?;
    let keys = grids
        .iter()
        .map(crate::analysis::orders::GlyphGrid::message_key)
        .collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    let streams = checked_streams(&keys, &message_values)?;
    let first_symbols = first_symbols(&keys, &streams)?;
    let partition = perseus::build_shared_partition(&keys, &message_values)?;
    let shared_runs = selected_shared_runs(&keys, &streams, &partition)?;
    let global_prefix = global_prefix(&partition);
    let shared_run_lengths = partition
        .selected_pair_runs
        .iter()
        .map(|run| run.len)
        .collect::<Vec<_>>();
    let obstruction = first_obstruction(&keys, &streams, &shared_runs, global_prefix.as_ref())?;
    let mut subgroup_reports = Vec::new();
    for subgroup in subgroups_to_run(config.subgroup) {
        subgroup_reports.push(run_subgroup(config, subgroup, obstruction.clone())?);
    }
    let positive_control_feasible_ok = subgroup_reports
        .iter()
        .all(|report| report.positive_controls.constant_shared_run_ok);
    let positive_control_infeasible_ok = subgroup_reports
        .iter()
        .all(|report| report.positive_controls.pure_translation_rejected_ok);
    let transcription_robustness = robustness::certify_transcription_robustness()?;

    Ok(AglGakReport {
        config,
        order,
        message_first_symbols: first_symbols,
        shared_run_lengths,
        global_prefix,
        shared_runs,
        subgroup_reports,
        positive_control_feasible_ok,
        positive_control_infeasible_ok,
        transcription_robustness,
    })
}

fn checked_streams(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<Vec<Vec<usize>>, AglGakError> {
    let mut streams = Vec::with_capacity(message_values.len());
    for (message_key, values) in keys.iter().copied().zip(message_values) {
        let mut stream = Vec::with_capacity(values.len());
        for value in values {
            let raw = usize::from(value.get());
            if raw >= ALPHABET_SIZE {
                return Err(AglGakError::ValueOutsideAlphabet {
                    message_key,
                    value: raw,
                });
            }
            stream.push(raw);
        }
        streams.push(stream);
    }
    Ok(streams)
}

fn first_symbols(
    keys: &[&'static str],
    streams: &[Vec<usize>],
) -> Result<Vec<(&'static str, usize)>, AglGakError> {
    let mut symbols = Vec::with_capacity(streams.len());
    for (message_key, stream) in keys.iter().copied().zip(streams) {
        let Some(first) = stream.first().copied() else {
            return Err(AglGakError::EmptyMessage { message_key });
        };
        symbols.push((message_key, first));
    }
    Ok(symbols)
}

fn selected_shared_runs(
    keys: &[&'static str],
    streams: &[Vec<usize>],
    partition: &perseus::SharedPartition,
) -> Result<Vec<AglGakSharedRun>, AglGakError> {
    let mut runs = Vec::new();
    for run in &partition.selected_pair_runs {
        let left_index = message_index(keys, run.left_key)?;
        let right_index = message_index(keys, run.right_key)?;
        let left_stream = stream_at(streams, left_index, run.left_key)?;
        let right_stream = stream_at(streams, right_index, run.right_key)?;
        let distinct_symbols =
            distinct_symbols_in_run(left_stream, run.left_key, run.start, run.len)?;
        let differing_predecessor = predecessor_differs(left_stream, right_stream, run.start);
        runs.push(AglGakSharedRun {
            left_key: run.left_key,
            right_key: run.right_key,
            start: run.start,
            len: run.len,
            distinct_symbols,
            varying: distinct_symbols >= 2,
            differing_predecessor,
            role: run.role,
        });
    }
    Ok(runs)
}

fn global_prefix(partition: &perseus::SharedPartition) -> Option<AglGakGlobalPrefix> {
    let prefix = partition.global_prefix.as_ref()?;
    let mut sorted = prefix
        .values
        .iter()
        .copied()
        .map(usize::from)
        .collect::<Vec<_>>();
    sorted.sort_unstable();
    sorted.dedup();
    Some(AglGakGlobalPrefix {
        start: prefix.start,
        len: prefix.len,
        values: prefix.values.iter().copied().map(usize::from).collect(),
        distinct_symbols: sorted.len(),
    })
}

fn first_obstruction(
    keys: &[&'static str],
    streams: &[Vec<usize>],
    runs: &[AglGakSharedRun],
    prefix: Option<&AglGakGlobalPrefix>,
) -> Result<Option<AglGakObstruction>, AglGakError> {
    // The empirical note (thread-2-empirical.md:63-66) identifies the all-nine
    // global prefix (66, 5) as the *tightest* clinching instance: a varying run
    // of length >= 2 shared by all nine messages immediately after their nine
    // distinct first symbols. When it qualifies, prefer it over the longer
    // pairwise runs so the verdict rests on the tightest clinching evidence.
    if let Some(obstruction) = global_prefix_obstruction(keys, streams, prefix)? {
        return Ok(Some(obstruction));
    }
    let Some(run) = runs
        .iter()
        .filter(|run| run.differing_predecessor && run.varying)
        .max_by_key(|run| run.len)
    else {
        return Ok(None);
    };
    let predecessor = run
        .start
        .checked_sub(1)
        .ok_or(AglGakError::InternalInvariant {
            context: "obstruction predecessor offset",
        })?;
    let left_index = message_index(keys, run.left_key)?;
    let right_index = message_index(keys, run.right_key)?;
    let left_stream = stream_at(streams, left_index, run.left_key)?;
    let right_stream = stream_at(streams, right_index, run.right_key)?;
    let Some(left_predecessor) = left_stream.get(predecessor).copied() else {
        return Err(AglGakError::SharedRunOutOfBounds {
            message_key: run.left_key,
            start: predecessor,
            len: 1,
        });
    };
    let Some(right_predecessor) = right_stream.get(predecessor).copied() else {
        return Err(AglGakError::SharedRunOutOfBounds {
            message_key: run.right_key,
            start: predecessor,
            len: 1,
        });
    };
    Ok(Some(AglGakObstruction {
        left_key: run.left_key,
        right_key: run.right_key,
        start: run.start,
        len: run.len,
        distinct_symbols: run.distinct_symbols,
        left_predecessor,
        right_predecessor,
    }))
}

/// Builds an obstruction from the all-nine global shared prefix when it is a
/// varying run of length >= 2 immediately after distinct first symbols.
///
/// The prefix is shared by *all* messages, so any two of them with differing
/// predecessors witness the same clinching feature; the first such pair labels
/// the obstruction. Returns `Ok(None)` if no prefix qualifies (so callers fall
/// back to the pairwise runs).
fn global_prefix_obstruction(
    keys: &[&'static str],
    streams: &[Vec<usize>],
    prefix: Option<&AglGakGlobalPrefix>,
) -> Result<Option<AglGakObstruction>, AglGakError> {
    let Some(prefix) = prefix else {
        return Ok(None);
    };
    if prefix.len < 2 || prefix.distinct_symbols < 2 {
        return Ok(None);
    }
    let Some(predecessor) = prefix.start.checked_sub(1) else {
        return Ok(None);
    };
    // Find the first message pair whose predecessor symbols differ. All nine
    // first symbols are distinct for the eyes, so this is the "distinct first
    // symbols" precondition the note's tightest instance requires.
    for (left_index, left_key) in keys.iter().copied().enumerate() {
        let left_stream = stream_at(streams, left_index, left_key)?;
        let Some(left_predecessor) = left_stream.get(predecessor).copied() else {
            continue;
        };
        for (right_offset, right_key) in keys.iter().copied().enumerate().skip(left_index + 1) {
            let right_stream = stream_at(streams, right_offset, right_key)?;
            let Some(right_predecessor) = right_stream.get(predecessor).copied() else {
                continue;
            };
            if left_predecessor != right_predecessor {
                return Ok(Some(AglGakObstruction {
                    left_key,
                    right_key,
                    start: prefix.start,
                    len: prefix.len,
                    distinct_symbols: prefix.distinct_symbols,
                    left_predecessor,
                    right_predecessor,
                }));
            }
        }
    }
    Ok(None)
}

fn run_subgroup(
    config: AglGakConfig,
    subgroup: AglMultiplierSubgroup,
    obstruction: Option<AglGakObstruction>,
) -> Result<AglGakSubgroupReport, AglGakError> {
    let fixed_points = fixed_point_enumeration(subgroup);
    let agreement_check = agreement_check(config.seed, subgroup)?;
    let forward_simulation = forward_simulation(config.seed, config.null_trials, subgroup)?;
    let positive_controls = positive_controls(subgroup)?;
    validate_positive_controls(subgroup, positive_controls)?;
    let excluded = obstruction.is_some()
        && fixed_points.fixing_at_least_two_points == 0
        && forward_simulation.varying_shared_runs == 0;
    Ok(AglGakSubgroupReport {
        subgroup,
        verdict: if excluded {
            AglGakVerdict::Excluded
        } else {
            AglGakVerdict::NotExcluded
        },
        obstruction,
        fixed_points,
        agreement_check,
        forward_simulation,
        positive_controls,
        fit_attempted: matches!(config.mode, AglGakMode::FeasibilityAndFit),
        fit_found: false,
    })
}
