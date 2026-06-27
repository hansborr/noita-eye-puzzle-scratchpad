//! Thread 2 AGL(1,83)-GAK stress test.
//!
//! This module tests only mapping-independent structure: ciphertext-symbol
//! equality, accepted reading-layer streams, and the AGL point-stabilizer group
//! model. It does not assign symbols to plaintext meanings.

use std::fmt;

use crate::analysis::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::ciphers::{
    self, AglMultiplierSubgroup, agl_apply, agl_compose, agl_coset_symbol, agl_inverse,
    mul_inverse_mod, quadratic_residues_mod, sub_mod,
};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{SplitMix64, add_one_p_value, mix_seed, random_index_below};
use crate::nulls::perseus::{self, PerseusError, SharedRunRole};
use crate::report::{self, Report};

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
}

impl Report for AglGakReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Thread 2 AGL(1,83)-GAK stress test");
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "forward-simulation trials per subgroup: {}",
            self.config.null_trials
        );
        report::appendln!(
            &mut out,
            "subgroups: C83:C82 and C83:C41 (preferred display order starts with {})",
            format_agl_subgroup(self.config.subgroup)
        );
        report::appendln!(
            &mut out,
            "mode: {}",
            match self.config.mode {
                AglGakMode::FeasibilityOnly => "feasibility-only",
                AglGakMode::FeasibilityAndFit => "feasibility+fit requested",
            }
        );
        report::appendln!(
            &mut out,
            "wiki pages under test: Affine-General-Linear-Group-(AGL).md; The-Transitivity-Restriction-(6-Groups-for-83).md; Message-Starts.md; Shared-Sections.md; Isomorphic-Cipher-Hierarchy.md"
        );
        report::appendln!(&mut out);
        append_agl_gak_observed(&mut out, self);
        report::appendln!(&mut out);
        append_agl_gak_subgroups(&mut out, self);
        report::appendln!(&mut out);
        append_agl_gak_interpretation(&mut out, self);
        out
    }
}

fn append_agl_gak_observed(out: &mut String, report: &AglGakReport) {
    report::appendln!(out, "observed mapping-independent structure");
    report::appendln!(
        out,
        "  first symbols: {}",
        report
            .message_first_symbols
            .iter()
            .map(|(key, value)| format!("{key}:{value}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    match &report.global_prefix {
        Some(prefix) => report::appendln!(
            out,
            "  all-message shared prefix: start {} len {} values {} distinct {}/{}",
            prefix.start,
            prefix.len,
            report::format_usize_values(&prefix.values),
            prefix.distinct_symbols,
            prefix.len
        ),
        None => report::appendln!(out, "  all-message shared prefix: none"),
    }
    report::appendln!(
        out,
        "  selected shared-run lengths: {}",
        report::format_usize_values(&report.shared_run_lengths)
    );
    report::appendln!(out, "  selected varying-run anchors:");
    for run in report
        .shared_runs
        .iter()
        .filter(|run| run.differing_predecessor && run.varying)
    {
        report::appendln!(
            out,
            "    {}/{} start {} len {} distinct {}/{} role {}",
            run.left_key,
            run.right_key,
            run.start,
            run.len,
            run.distinct_symbols,
            run.len,
            run.role.label()
        );
    }
}

fn append_agl_gak_subgroups(out: &mut String, report: &AglGakReport) {
    report::appendln!(out, "subgroup verdicts");
    // The "fixed>=2/universe" denominator is the exhaustive differing-discrepancy
    // universe size (6724 for C83:C82, 3362 for C83:C41); naming it makes clear the
    // exclusion is exhaustive over that universe rather than sampled.
    report::appendln!(
        out,
        "  {:<8} {:<9} {:>12} {:>16} {:>17} {:>14} {:<12}",
        "group",
        "verdict",
        "agreement",
        "forward",
        "fixed>=2/universe",
        "max fixed",
        "controls"
    );
    for subgroup in &report.subgroup_reports {
        report::appendln!(
            out,
            "  {:<8} {:<9} {:>5}/{:<6} {:>7}/{:<8} {:>7}/{:<9} {:>14} {:<12}",
            format_agl_subgroup(subgroup.subgroup),
            format_agl_verdict(subgroup.verdict),
            subgroup.agreement_check.violations,
            subgroup.agreement_check.checks,
            subgroup.forward_simulation.varying_shared_runs,
            subgroup.forward_simulation.trials,
            subgroup.fixed_points.fixing_at_least_two_points,
            subgroup.fixed_points.discrepancies,
            subgroup.fixed_points.max_fixed_points,
            format_agl_controls(subgroup.positive_controls)
        );
        if let Some(obstruction) = &subgroup.obstruction {
            report::appendln!(
                out,
                "    obstruction: {}/{} start {} len {} distinct {}/{} after predecessors {} vs {}",
                obstruction.left_key,
                obstruction.right_key,
                obstruction.start,
                obstruction.len,
                obstruction.distinct_symbols,
                obstruction.len,
                obstruction.left_predecessor,
                obstruction.right_predecessor
            );
        }
        report::appendln!(
            out,
            "    forward add-one p for a varying shared run: {}",
            report::format_probability(subgroup.forward_simulation.add_one_p_value)
        );
        if subgroup.fit_attempted {
            report::appendln!(
                out,
                "    fit: requested, but no fit is retained after the exhaustive structural exclusion"
            );
        }
    }
}

fn append_agl_gak_interpretation(out: &mut String, report: &AglGakReport) {
    let all_excluded = report
        .subgroup_reports
        .iter()
        .all(|subgroup| subgroup.verdict == AglGakVerdict::Excluded);
    if all_excluded {
        report::appendln!(
            out,
            "Interpretation: AGL(1,83)-GAK is rigorously excluded for both C83:C82 and C83:C41 under the verified right-multiplication / left-coset model. The wiki's tentative message-start exclusion was over-conceded / weaker than needed: the rigorous kill is the varying-shared-run mechanism. After a differing start, an affine discrepancy can fix at most one point, so any AGL shared run must be constant; the eyes' shared runs vary."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: this run did not exclude every requested AGL subgroup. Treat any structural fit as a hypothesis to kill with held-out isomorphs, not as a decode."
        );
    }
    report::appendln!(
        out,
        "Claim ceiling: this excludes one candidate group family and narrows the transitive GAK candidate set toward {{A83, S83}}, with D166 conditional elsewhere. It says nothing about recoverable plaintext; the eyes remain deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext. Scope: this excludes the point-stabilizer AGL-GAK family (output = moved reference point, single shared running key); it does not speak to non-GAK affine constructions or a non-point-stabilizer hidden subgroup."
    );
    report::appendln!(
        out,
        "Multiplicity note: both AGL multiplier variants are tested, and the repeated tails reported here are structural/exhaustive checks rather than language-scoring claims."
    );
}

fn format_agl_subgroup(subgroup: AglMultiplierSubgroup) -> &'static str {
    match subgroup {
        AglMultiplierSubgroup::Full => "C83:C82",
        AglMultiplierSubgroup::QuadraticResidues => "C83:C41",
    }
}

fn format_agl_verdict(verdict: AglGakVerdict) -> &'static str {
    match verdict {
        AglGakVerdict::Excluded => "excluded",
        AglGakVerdict::NotExcluded => "open",
    }
}

fn format_agl_controls(controls: AglGakPositiveControls) -> &'static str {
    match (
        controls.constant_shared_run_ok,
        controls.pure_translation_rejected_ok,
    ) {
        (true, true) => "ok",
        (false, true) => "const-fail",
        (true, false) => "pure-fail",
        (false, false) => "failed",
    }
}

/// Runs the AGL-GAK structural stress test.
///
/// # Errors
/// Returns [`AglGakError`] on corpus/grid failure, shared-run reconstruction
/// failure, invalid control construction, invalid configuration, random-draw
/// failure, or a failing positive control.
pub fn run_agl_gak(config: AglGakConfig) -> Result<AglGakReport, AglGakError> {
    validate_config(config)?;
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
    })
}

fn validate_config(config: AglGakConfig) -> Result<(), AglGakError> {
    if config.null_trials == 0 {
        return Err(AglGakError::ZeroTrials);
    }
    Ok(())
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

fn validate_positive_controls(
    subgroup: AglMultiplierSubgroup,
    controls: AglGakPositiveControls,
) -> Result<(), AglGakError> {
    if !controls.constant_shared_run_ok {
        return Err(AglGakError::PositiveControlFailed {
            which: subgroup_control_name(subgroup, "constant shared run"),
        });
    }
    if !controls.pure_translation_rejected_ok {
        return Err(AglGakError::PositiveControlFailed {
            which: subgroup_control_name(subgroup, "pure translation"),
        });
    }
    Ok(())
}

fn fixed_point_enumeration(subgroup: AglMultiplierSubgroup) -> AglGakFixedPointEnumeration {
    let mut discrepancies = 0usize;
    let mut fixing_at_least_two_points = 0usize;
    let mut max_fixed_points = 0usize;
    for multiplier in subgroup_multipliers(subgroup) {
        for translation in 1..ALPHABET_SIZE {
            discrepancies += 1;
            let fixed = fixed_point_count((multiplier, translation));
            if fixed >= 2 {
                fixing_at_least_two_points += 1;
            }
            max_fixed_points = max_fixed_points.max(fixed);
        }
    }
    AglGakFixedPointEnumeration {
        discrepancies,
        fixing_at_least_two_points,
        max_fixed_points,
    }
}

fn agreement_check(
    seed: u64,
    subgroup: AglMultiplierSubgroup,
) -> Result<AglGakAgreementCheck, AglGakError> {
    let multipliers = subgroup_multipliers(subgroup);
    let mut rng = SplitMix64::new(mix_seed(seed, subgroup_tag(subgroup) ^ 0x6167_7265_6500));
    let mut violations = 0usize;
    for _trial in 0..AGREEMENT_CHECKS {
        let discrepancy = random_differing_discrepancy(&multipliers, &mut rng)?;
        let context = random_group_element(&multipliers, &mut rng)?;
        let point = agl_coset_symbol(context, 0, ALPHABET_SIZE);
        let agreement = point
            == agl_coset_symbol(
                agl_compose(discrepancy, context, ALPHABET_SIZE),
                0,
                ALPHABET_SIZE,
            );
        let fixes = agl_apply(discrepancy, point, ALPHABET_SIZE) == point;
        if agreement != fixes {
            violations += 1;
        }
    }
    Ok(AglGakAgreementCheck {
        checks: AGREEMENT_CHECKS,
        violations,
    })
}

fn forward_simulation(
    seed: u64,
    trials: usize,
    subgroup: AglMultiplierSubgroup,
) -> Result<AglGakForwardSimulation, AglGakError> {
    let multipliers = subgroup_multipliers(subgroup);
    let mut rng = SplitMix64::new(mix_seed(
        seed,
        subgroup_tag(subgroup) ^ 0x6677_645f_7369_6d00,
    ));
    let mut varying_shared_runs = 0usize;
    for _trial in 0..trials {
        let discrepancy = random_differing_discrepancy(&multipliers, &mut rng)?;
        if simulated_varying_shared_run(discrepancy, &multipliers, &mut rng)? {
            varying_shared_runs += 1;
        }
    }
    Ok(AglGakForwardSimulation {
        trials,
        varying_shared_runs,
        add_one_p_value: add_one_p_value(varying_shared_runs, trials),
    })
}

fn simulated_varying_shared_run(
    discrepancy: (usize, usize),
    multipliers: &[usize],
    rng: &mut SplitMix64,
) -> Result<bool, AglGakError> {
    // Collect the agreed-prefix values BEFORE the break, then test whether that
    // shared prefix (of length >= 2) varies. The empirical note
    // (thread-2-empirical.md:96) defines the sampled event as "varying shared
    // runs of length >= 2"; counting only a full-length-3 varying agreement
    // would silently lean on the very theorem this enumeration is meant to
    // corroborate (a varying length-2 agreement is algebraically impossible, so
    // a length-2 prefix that breaks at step 3 must be registered for the null to
    // match the note's definition rather than assume the result).
    let mut context = (1, 0);
    let mut shared_values = Vec::with_capacity(3);
    for _step in 0..3 {
        let element = random_group_element(multipliers, rng)?;
        context = agl_compose(context, element, ALPHABET_SIZE);
        let left = agl_coset_symbol(context, 0, ALPHABET_SIZE);
        let right = agl_coset_symbol(
            agl_compose(discrepancy, context, ALPHABET_SIZE),
            0,
            ALPHABET_SIZE,
        );
        if left != right {
            break;
        }
        shared_values.push(left);
    }
    Ok(shared_values.len() >= 2 && run_is_varying(&shared_values))
}

fn positive_controls(
    subgroup: AglMultiplierSubgroup,
) -> Result<AglGakPositiveControls, AglGakError> {
    let multiplier = control_multiplier(subgroup)?;
    let fixed_point = CONTROL_FIXED_POINT;
    let translation = sub_mod(
        fixed_point,
        (multiplier * fixed_point) % ALPHABET_SIZE,
        ALPHABET_SIZE,
    );
    let discrepancy = (multiplier, translation);
    let recovered_fixed_point = fixed_point_of(discrepancy);
    let constant_shared_run_ok = recovered_fixed_point == Some(fixed_point)
        && constant_control_forward(discrepancy, fixed_point);
    let pure_translation_rejected_ok = pure_translation_has_no_agreement(subgroup);
    Ok(AglGakPositiveControls {
        constant_shared_run_ok,
        pure_translation_rejected_ok,
        recovered_fixed_point,
    })
}

fn constant_control_forward(discrepancy: (usize, usize), fixed_point: usize) -> bool {
    let Some(inverse) = agl_inverse(discrepancy, ALPHABET_SIZE) else {
        return false;
    };
    if agl_compose(discrepancy, inverse, ALPHABET_SIZE) != (1, 0) {
        return false;
    }
    let mut context = (1, 0);
    let mut values = Vec::new();
    for step in 0..6 {
        let element = if step == 0 { (1, fixed_point) } else { (1, 0) };
        context = agl_compose(context, element, ALPHABET_SIZE);
        let left = agl_coset_symbol(context, 0, ALPHABET_SIZE);
        let right = agl_coset_symbol(
            agl_compose(discrepancy, context, ALPHABET_SIZE),
            0,
            ALPHABET_SIZE,
        );
        if left != right {
            return false;
        }
        values.push(left);
    }
    values.iter().all(|&value| value == fixed_point)
}

fn pure_translation_has_no_agreement(subgroup: AglMultiplierSubgroup) -> bool {
    let discrepancy = (1, 1);
    for context in group_elements(subgroup) {
        let left = agl_coset_symbol(context, 0, ALPHABET_SIZE);
        let right = agl_coset_symbol(
            agl_compose(discrepancy, context, ALPHABET_SIZE),
            0,
            ALPHABET_SIZE,
        );
        if left == right {
            return false;
        }
    }
    fixed_point_of(discrepancy).is_none()
}

fn fixed_point_count(element: (usize, usize)) -> usize {
    (0..ALPHABET_SIZE)
        .filter(|&point| agl_apply(element, point, ALPHABET_SIZE) == point)
        .count()
}

fn fixed_point_of(element: (usize, usize)) -> Option<usize> {
    let denom = sub_mod(1, element.0, ALPHABET_SIZE);
    if denom == 0 {
        return None;
    }
    let inv = mul_inverse_mod(denom, ALPHABET_SIZE)?;
    Some(((element.1 % ALPHABET_SIZE) * inv) % ALPHABET_SIZE)
}

fn subgroup_multipliers(subgroup: AglMultiplierSubgroup) -> Vec<usize> {
    match subgroup {
        AglMultiplierSubgroup::Full => (1..ALPHABET_SIZE).collect(),
        AglMultiplierSubgroup::QuadraticResidues => quadratic_residues_mod(ALPHABET_SIZE),
    }
}

fn group_elements(subgroup: AglMultiplierSubgroup) -> Vec<(usize, usize)> {
    let mut elements = Vec::new();
    for multiplier in subgroup_multipliers(subgroup) {
        for translation in 0..ALPHABET_SIZE {
            elements.push((multiplier, translation));
        }
    }
    elements
}

fn random_differing_discrepancy(
    multipliers: &[usize],
    rng: &mut SplitMix64,
) -> Result<(usize, usize), AglGakError> {
    let multiplier = random_multiplier(multipliers, rng)?;
    let translation = random_index_below(ALPHABET_SIZE - 1, rng)? + 1;
    Ok((multiplier, translation))
}

fn random_group_element(
    multipliers: &[usize],
    rng: &mut SplitMix64,
) -> Result<(usize, usize), AglGakError> {
    Ok((
        random_multiplier(multipliers, rng)?,
        random_index_below(ALPHABET_SIZE, rng)?,
    ))
}

fn random_multiplier(multipliers: &[usize], rng: &mut SplitMix64) -> Result<usize, AglGakError> {
    let index = random_index_below(multipliers.len(), rng)?;
    multipliers
        .get(index)
        .copied()
        .ok_or(AglGakError::InternalInvariant {
            context: "AGL random multiplier lookup",
        })
}

fn control_multiplier(subgroup: AglMultiplierSubgroup) -> Result<usize, AglGakError> {
    subgroup_multipliers(subgroup)
        .into_iter()
        .find(|&multiplier| multiplier != 1)
        .ok_or(AglGakError::InternalInvariant {
            context: "AGL control multiplier",
        })
}

fn distinct_symbols_in_run(
    stream: &[usize],
    message_key: &'static str,
    start: usize,
    len: usize,
) -> Result<usize, AglGakError> {
    let mut values = Vec::new();
    for value in stream.iter().skip(start).take(len) {
        values.push(*value);
    }
    if values.len() != len {
        return Err(AglGakError::SharedRunOutOfBounds {
            message_key,
            start,
            len,
        });
    }
    values.sort_unstable();
    values.dedup();
    Ok(values.len())
}

fn predecessor_differs(left: &[usize], right: &[usize], start: usize) -> bool {
    let Some(predecessor) = start.checked_sub(1) else {
        return false;
    };
    match (left.get(predecessor), right.get(predecessor)) {
        (Some(left_value), Some(right_value)) => left_value != right_value,
        _ => false,
    }
}

fn run_is_varying(values: &[usize]) -> bool {
    let Some(first) = values.first() else {
        return false;
    };
    values.iter().any(|value| value != first)
}

fn message_index(keys: &[&'static str], key: &'static str) -> Result<usize, AglGakError> {
    keys.iter()
        .position(|candidate| *candidate == key)
        .ok_or(AglGakError::InternalInvariant {
            context: "AGL message key lookup",
        })
}

fn stream_at<'a>(
    streams: &'a [Vec<usize>],
    index: usize,
    message_key: &'static str,
) -> Result<&'a [usize], AglGakError> {
    streams
        .get(index)
        .map(Vec::as_slice)
        .ok_or(AglGakError::EmptyMessage { message_key })
}

fn subgroups_to_run(preferred: AglMultiplierSubgroup) -> Vec<AglMultiplierSubgroup> {
    match preferred {
        AglMultiplierSubgroup::Full => vec![
            AglMultiplierSubgroup::Full,
            AglMultiplierSubgroup::QuadraticResidues,
        ],
        AglMultiplierSubgroup::QuadraticResidues => vec![
            AglMultiplierSubgroup::QuadraticResidues,
            AglMultiplierSubgroup::Full,
        ],
    }
}

const fn subgroup_tag(subgroup: AglMultiplierSubgroup) -> u64 {
    match subgroup {
        AglMultiplierSubgroup::Full => 0x6338_325f_6675_6c6c,
        AglMultiplierSubgroup::QuadraticResidues => 0x6334_315f_7172_0000,
    }
}

fn subgroup_control_name(subgroup: AglMultiplierSubgroup, control: &'static str) -> &'static str {
    match (subgroup, control) {
        (AglMultiplierSubgroup::Full, "constant shared run") => "C83:C82 constant shared run",
        (AglMultiplierSubgroup::Full, "pure translation") => "C83:C82 pure translation",
        (AglMultiplierSubgroup::QuadraticResidues, "constant shared run") => {
            "C83:C41 constant shared run"
        }
        (AglMultiplierSubgroup::QuadraticResidues, "pure translation") => {
            "C83:C41 pure translation"
        }
        _ => "unknown AGL-GAK control",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        AglGakConfig, AglGakMode, AglGakVerdict, AglMultiplierSubgroup, DEFAULT_SEED,
        fixed_point_enumeration, run_agl_gak,
    };

    #[test]
    fn run_agl_gak_is_deterministic() {
        let config = AglGakConfig {
            seed: DEFAULT_SEED,
            null_trials: 257,
            mode: AglGakMode::FeasibilityOnly,
            subgroup: AglMultiplierSubgroup::Full,
        };
        assert_eq!(run_agl_gak(config).unwrap(), run_agl_gak(config).unwrap());
    }

    #[test]
    fn eye_pins_match_verified_streams() {
        let config = AglGakConfig {
            null_trials: 257,
            ..AglGakConfig::default()
        };
        let report = run_agl_gak(config).unwrap();
        let first_values = report
            .message_first_symbols
            .iter()
            .map(|(_key, value)| *value)
            .collect::<Vec<_>>();
        assert_eq!(first_values, vec![50, 80, 36, 76, 63, 34, 27, 77, 33]);
        let distinct_starts = first_values.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(distinct_starts.len(), 9);
        assert!(report.shared_run_lengths.contains(&24));
        assert!(report.shared_run_lengths.contains(&20));
        let prefix = report.global_prefix.unwrap();
        assert_eq!(prefix.start, 1);
        assert_eq!(prefix.len, 2);
        assert_eq!(prefix.values, vec![66, 5]);
        assert_eq!(prefix.distinct_symbols, 2);
    }

    #[test]
    fn fixed_point_enumeration_counts_reproduce() {
        let full = fixed_point_enumeration(AglMultiplierSubgroup::Full);
        assert_eq!(full.discrepancies, 6_724);
        assert_eq!(full.fixing_at_least_two_points, 0);
        assert_eq!(full.max_fixed_points, 1);

        let qr = fixed_point_enumeration(AglMultiplierSubgroup::QuadraticResidues);
        assert_eq!(qr.discrepancies, 3_362);
        assert_eq!(qr.fixing_at_least_two_points, 0);
        assert_eq!(qr.max_fixed_points, 1);
    }

    #[test]
    fn positive_controls_fire_and_eyes_are_excluded() {
        let config = AglGakConfig {
            null_trials: 257,
            ..AglGakConfig::default()
        };
        let report = run_agl_gak(config).unwrap();
        assert!(report.positive_control_feasible_ok);
        assert!(report.positive_control_infeasible_ok);
        for subgroup in &report.subgroup_reports {
            assert_eq!(subgroup.verdict, AglGakVerdict::Excluded);
            assert_eq!(subgroup.agreement_check.violations, 0);
            assert_eq!(subgroup.forward_simulation.varying_shared_runs, 0);
            assert_eq!(subgroup.positive_controls.recovered_fixed_point, Some(42));
        }
    }
}
