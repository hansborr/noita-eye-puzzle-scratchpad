//! Command-line entry point for the Noita eye-puzzle toolkit.
//!
//! This is intentionally a thin wrapper over the library so that all logic
//! stays testable in [`noita_eye_puzzle`]. `clap` owns argument parsing and
//! usage text; domain analysis and report rendering live in the library.

use std::io::{self, Read};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use noita_eye_puzzle::{
    agl_gak, chaining, chaining_graph, cipher_attack, ciphers, codec, conditional_structure,
    controls, corpus, dof_null, gak_attack,
    glyph::{Alphabet, Sequence},
    grouping, honeycomb, ingest, isomorph_null, keystream, language, modular_diff, null, orders,
    orientation_homogeneity, perfect_isomorphism, periodicity, perseus, pipeline_null,
    pyry_conditions, quadgram,
    report::{self, Report},
    solve, transitivity, tree_residual, zero_adjacency_null,
};

const DEFAULT_NULL_SEED: u64 = 0x6e6f_6974_612d_6579;
const DEFAULT_NULL_TRIALS: usize = 1_000;
const DEFAULT_DOF_NULL_SEED: u64 = 0x646f_666e_756c_6c00;
const DEFAULT_DOF_NULL_TRIALS: usize = 1_000;
const DEFAULT_SOLVE_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DEFAULT_CANDIDATES_DIR: &str = "research/gak-threads/candidates";
const DEFAULT_SOLVE_RESTARTS: usize = 6;
const DEFAULT_SOLVE_ITERATIONS: usize = 8_000;

#[derive(Debug, Parser)]
#[command(
    name = "noita-eye",
    about = "Noita eye-glyph puzzle toolkit",
    after_help = "Digit 5 is treated as a row delimiter and ignored for glyph statistics."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Frequency, entropy, and `IoC` for rendered digits 0-4.
    Stats(StatsArgs),
    /// Run analysis on the verified nine-message corpus.
    Demo,
    /// Audit reading orders and Experiment 4 flatness.
    Orders,
    /// Thread 2 AGL(1,83)-GAK structural stress test.
    #[command(name = "agl-gak")]
    AglGak(AglGakArgs),
    /// Thread 4 synthetic GAK-attack / GCTAK decisive gate (synthetic-only).
    #[command(name = "gak-attack")]
    GakAttack(GakAttackArgs),
    /// Thread 4 EYES Step 3: point the matured attack at the REAL eye corpus.
    /// Held-out + Thread-3 gated; expected outcome is NO surviving candidate; the
    /// decode remains BLOCKED. Writes a mandatory candidate record.
    #[command(name = "gak-attack-eyes", alias = "gak-eyes")]
    GakAttackEyes(GakAttackEyesArgs),
    /// Monte-Carlo null over random grids plus standard36 orders.
    #[command(name = "nulltest")]
    Nulltest(NullArgs),
    /// Calibrated adaptive null over traversal/grouping/statistic `DoF`.
    #[command(name = "dofnull")]
    Dofnull(DofNullArgs),
    /// Experiment 5A period/lag/Kasiski battery.
    Periodicity(PeriodicityArgs),
    /// Honeycomb 2D lattice-structure null.
    Honeycomb(HoneycombArgs),
    /// Base-7 pipeline null plus input-randomness control.
    #[command(name = "pipelinenull")]
    Pipelinenull(NullArgs),
    /// Experiment 8 base-N grouping plus state-count estimate.
    Grouping,
    /// Cross-message orientation-frequency homogeneity null.
    Homogeneity(HomogeneityArgs),
    /// Experiment 7A real isomorphs vs within-message shuffle null.
    #[command(name = "isomorphnull")]
    Isomorphnull(IsomorphNullArgs),
    /// Experiment 7B alphabet-chaining structural control.
    Chaining(ChainingArgs),
    /// Thread 5 graph-chaining conflict and coverage audit.
    #[command(name = "chaining-graph")]
    ChainingGraph(ChainingGraphArgs),
    /// Modular-difference family fingerprint.
    #[command(name = "moddiff")]
    Moddiff(ModularDiffArgs),
    /// Experiment 7C Perseus shared-region recurrence null.
    Perseus(PerseusArgs),
    /// Thread 3 perfect-isomorphism / allomorph-consistency scan.
    #[command(name = "perfectiso", alias = "perfect-isomorphism")]
    Perfectiso(PerfectIsomorphismArgs),
    /// Experiment 7D zero adjacency vs within-message multiset shuffle null.
    #[command(name = "zeroadjnull", alias = "zero-adjacency-null")]
    Zeroadjnull(ZeroAdjacencyNullArgs),
    /// Tree-residual cross-tail n-gram null.
    #[command(name = "treeresidual", alias = "tree-residual")]
    Treeresidual(TreeResidualArgs),
    /// Thread 1B transitivity and conditional D166 audit.
    #[command(alias = "dihedral")]
    Transitivity(TransitivityArgs),
    /// First-order transition matrix and successor-graph shuffle null.
    Conditional(ConditionalArgs),
    /// Experiment 12 candidate-cipher language-scoring null harness.
    #[command(name = "cipherattack")]
    Cipherattack(CipherAttackArgs),
    /// Pyry's Conditions structural falsification harness.
    #[command(name = "pyry", alias = "pyryconditions", alias = "pyry-conditions")]
    Pyry(PyryConditionsArgs),
    /// Experiment 11 positive controls.
    Controls(ControlsArgs),
    /// Search and score solve hypotheses; candidates are HYPOTHESES, not decodes.
    Solve(SolveArgs),
    /// Crack a polyalphabetic keystream cipher (Vigenere/Beaufort/autokey) on a
    /// practice letter-puzzle. HONEST-NEGATIVE is the expected outcome on the
    /// non-periodic puzzles; any survivor is a HYPOTHESIS, never a decode.
    #[command(name = "keystream")]
    Keystream(KeystreamArgs),
}

#[derive(Debug, Args)]
struct StatsArgs {
    /// Rendered orientation sequence (digits 0-4, optional delimiter 5).
    /// Optional: omit to read from --input-file or stdin.
    sequence: Option<String>,
    /// Read the ciphertext from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    input_file: Option<std::path::PathBuf>,
    /// Treat the input as accepted honeycomb reading-layer values (0-82, the
    /// alphabet solve consumes) rather than rendered orientation digits.
    #[arg(long = "honeycomb")]
    honeycomb: bool,
    /// Treat the input as a general cipher alphabet (these chars, in order, are
    /// the cipher symbols; e.g. ABCDEFGHIJKLMNOPQRSTUVWXYZ for a letter puzzle).
    /// Spaces/punctuation (`. , ? ! #`, newline) pass through as transparent
    /// symbols. For the practice corpus, not the eyes; conflicts with
    /// --honeycomb.
    #[arg(long = "alphabet", conflicts_with = "honeycomb")]
    alphabet: Option<String>,
}

#[derive(Clone, Debug, Args)]
struct SolveArgs {
    /// Ciphertext sequence. Optional: omit to read from --input-file or stdin.
    ciphertext: Option<String>,
    /// Read the ciphertext from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "ciphertext")]
    input_file: Option<std::path::PathBuf>,
    /// Read the ciphertext from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["ciphertext", "input_file"])]
    stdin: bool,
    /// Treat the input as accepted honeycomb reading-layer values (0-82).
    #[arg(long = "honeycomb", conflicts_with = "alphabet")]
    honeycomb: bool,
    /// Cipher alphabet chars, in order. Defaults to A-Z for letter puzzles.
    #[arg(long = "alphabet", conflicts_with = "honeycomb")]
    alphabet: Option<String>,
    /// Cipher family to enumerate. Repeat to include more than one.
    #[arg(long = "family", value_enum)]
    family: Vec<SolveFamilyArg>,
    /// Deterministic seed for the matched-null control.
    #[arg(long, default_value_t = solve::DEFAULT_SEED)]
    seed: u64,
    /// Number of matched-null shuffles.
    #[arg(long = "null-trials", default_value_t = solve::DEFAULT_NULL_TRIALS)]
    null_trials: usize,
    /// Hill-climb / anneal the symbol->letter mapping (Phase 2) instead of
    /// scoring the fixed declared mappings.
    #[arg(long = "mapping-search")]
    mapping_search: bool,
    /// Mapping-search random restarts (only with --mapping-search).
    #[arg(long, default_value_t = DEFAULT_SOLVE_RESTARTS)]
    restarts: usize,
    /// Mapping-search proposals per restart (only with --mapping-search).
    #[arg(long, default_value_t = DEFAULT_SOLVE_ITERATIONS)]
    iterations: usize,
    /// Annealing start temperature (only with --mapping-search); 0 = pure
    /// hill-climb (accept only non-worsening proposals).
    #[arg(long = "anneal-temp", default_value_t = 0.0)]
    anneal_temp: f64,
    /// Directory for the machine-written candidate record (a labelled
    /// HYPOTHESIS, never a decode). Auto-logged after every run.
    #[arg(long = "candidates-dir", default_value = DEFAULT_CANDIDATES_DIR)]
    candidates_dir: std::path::PathBuf,
    /// Stable label for the candidate-record filename (no wall clock).
    #[arg(long, default_value = "cli")]
    label: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SolveFamilyArg {
    /// No-key passthrough cipher.
    Identity,
    /// Exhaustive Caesar shifts over the parsed alphabet.
    Caesar,
    /// Small synthetic transposition candidates.
    Transposition,
}

#[derive(Clone, Debug, Args)]
struct KeystreamArgs {
    /// Built-in practice letter-puzzle to crack.
    #[arg(long, value_enum, conflicts_with_all = ["input_file", "stdin"])]
    puzzle: Option<KeystreamPuzzleArg>,
    /// Read the ciphertext (letters only; other characters dropped) from a file.
    #[arg(long = "input-file", conflicts_with = "stdin")]
    input_file: Option<std::path::PathBuf>,
    /// Read the ciphertext from stdin.
    #[arg(long, conflicts_with = "input_file")]
    stdin: bool,
    /// Cipher family to search. Repeat to include more than one; default = all.
    #[arg(long = "family", value_enum)]
    family: Vec<KeystreamFamilyArg>,
    /// Smallest key length searched (used unless --key-len is given).
    #[arg(long = "min-key-len", default_value_t = 1)]
    min_key_len: usize,
    /// Largest key length searched (used unless --key-len is given).
    #[arg(long = "max-key-len", default_value_t = 20)]
    max_key_len: usize,
    /// Search a single fixed key length (overrides --min-key-len/--max-key-len).
    #[arg(long = "key-len")]
    key_len: Option<usize>,
    /// Alphabet size N.
    #[arg(long = "alphabet-size", default_value_t = keystream::DEFAULT_ALPHABET_SIZE)]
    alphabet_size: usize,
    /// Annealed-search random restarts.
    #[arg(long, default_value_t = keystream::DEFAULT_RESTARTS)]
    restarts: usize,
    /// Annealing iterations per restart.
    #[arg(long, default_value_t = keystream::DEFAULT_ITERATIONS)]
    iterations: usize,
    /// Annealing start temperature; 0 = pure hill-climb.
    #[arg(long = "anneal-temp", default_value_t = keystream::DEFAULT_ANNEAL_TEMP)]
    anneal_temp: f64,
    /// Deterministic seed for the search and the matched null.
    #[arg(long, default_value_t = keystream::DEFAULT_SEED)]
    seed: u64,
    /// Number of random-key null trials for the reported DIAGNOSTIC (not the gate).
    #[arg(long = "null-trials", default_value_t = keystream::DEFAULT_NULL_TRIALS)]
    null_trials: usize,
    /// Number of matched-null trials (reruns of the search on shuffled
    /// ciphertext) — the survival gate. 0 disables survival.
    #[arg(long = "matched-null-trials", default_value_t = keystream::DEFAULT_MATCHED_NULL_TRIALS)]
    matched_null_trials: usize,
    /// Directory for any surviving candidate's record (a labelled HYPOTHESIS).
    #[arg(long = "candidates-dir", default_value = DEFAULT_CANDIDATES_DIR)]
    candidates_dir: std::path::PathBuf,
    /// Stable label for candidate-record filenames (defaults to the puzzle name).
    #[arg(long)]
    label: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum KeystreamPuzzleArg {
    /// Practice puzzle `three`.
    Three,
    /// Practice puzzle `four`.
    Four,
    /// Practice puzzle `five`.
    Five,
    /// Practice puzzle `seven`.
    Seven,
}

impl From<KeystreamPuzzleArg> for keystream::PracticePuzzle {
    fn from(arg: KeystreamPuzzleArg) -> Self {
        match arg {
            KeystreamPuzzleArg::Three => Self::Three,
            KeystreamPuzzleArg::Four => Self::Four,
            KeystreamPuzzleArg::Five => Self::Five,
            KeystreamPuzzleArg::Seven => Self::Seven,
        }
    }
}

impl KeystreamPuzzleArg {
    /// Stable lowercase label used for the default candidate-record filename.
    const fn label(self) -> &'static str {
        match self {
            Self::Three => "three",
            Self::Four => "four",
            Self::Five => "five",
            Self::Seven => "seven",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum KeystreamFamilyArg {
    /// Periodic additive keystream.
    Vigenere,
    /// Periodic subtractive involution.
    Beaufort,
    /// Autokey whose keystream is primer ++ plaintext.
    #[value(name = "autokey-pt")]
    AutokeyPt,
    /// Autokey whose keystream is primer ++ ciphertext.
    #[value(name = "autokey-ct")]
    AutokeyCt,
}

impl From<KeystreamFamilyArg> for keystream::KeystreamFamily {
    fn from(arg: KeystreamFamilyArg) -> Self {
        match arg {
            KeystreamFamilyArg::Vigenere => Self::Vigenere,
            KeystreamFamilyArg::Beaufort => Self::Beaufort,
            KeystreamFamilyArg::AutokeyPt => Self::PlaintextAutokey,
            KeystreamFamilyArg::AutokeyCt => Self::CiphertextAutokey,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct AglGakArgs {
    #[arg(long, default_value_t = agl_gak::DEFAULT_SEED)]
    seed: u64,
    #[arg(long = "null-trials", default_value_t = agl_gak::DEFAULT_NULL_TRIALS)]
    null_trials: usize,
    /// Run Part B bounded fit as well as Part A feasibility.
    #[arg(long, default_value_t = false)]
    fit: bool,
    /// Display the order-41 quadratic-residue subgroup first.
    #[arg(long, default_value_t = false)]
    quadratic_residues: bool,
}

impl From<AglGakArgs> for agl_gak::AglGakConfig {
    fn from(args: AglGakArgs) -> Self {
        Self {
            seed: args.seed,
            null_trials: args.null_trials,
            mode: if args.fit {
                agl_gak::AglGakMode::FeasibilityAndFit
            } else {
                agl_gak::AglGakMode::FeasibilityOnly
            },
            subgroup: if args.quadratic_residues {
                ciphers::AglMultiplierSubgroup::QuadraticResidues
            } else {
                ciphers::AglMultiplierSubgroup::Full
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct GakAttackArgs {
    /// Deterministic master seed for the synthetic fixture matrix.
    #[arg(long, default_value_t = gak_attack::DEFAULT_SEED)]
    seed: u64,
    /// Number of distinct independent seeds drawn per group kind.
    #[arg(long = "seeds-per-kind", default_value_t = gak_attack::DEFAULT_SEEDS_PER_KIND)]
    seeds_per_kind: usize,
    /// Cyclic-group order `m` used by the commutative fixtures.
    #[arg(long = "cyclic-order", default_value_t = gak_attack::DEFAULT_CYCLIC_ORDER)]
    cyclic_order: usize,
    /// Dihedral half-order `k` (`D_2k` has order `2k`, `k >= 3`).
    #[arg(long = "dihedral-half-order", default_value_t = gak_attack::DEFAULT_DIHEDRAL_HALF_ORDER)]
    dihedral_half_order: usize,
    /// Number of distinct plaintext letters (group generators) per fixture
    /// (minimum `2`).
    #[arg(long = "letters", default_value_t = gak_attack::DEFAULT_NUM_PT_LETTERS)]
    num_pt_letters: usize,
    /// Number of repeated phrases in the generated plaintext template.
    #[arg(long = "phrase-repeats", default_value_t = gak_attack::DEFAULT_PHRASE_REPEATS)]
    phrase_repeats: usize,
    /// Length in letters of each repeated phrase.
    #[arg(long = "phrase-len", default_value_t = gak_attack::DEFAULT_PHRASE_LEN)]
    phrase_len: usize,
    /// TENTATIVE small-support radius (`<=k` transpositions). REJECTED for the
    /// decisive GCTAK gate, which runs unconstrained (radius `0`) by construction;
    /// any nonzero value errors out. The small-support prior is exercised only by
    /// the deck / marginalization validation sweeps. `0` is the unconstrained gate
    /// regime (the only accepted value here).
    #[arg(long = "small-support-radius", default_value_t = gak_attack::DEFAULT_SMALL_SUPPORT_RADIUS)]
    small_support_radius: usize,
}

impl From<GakAttackArgs> for gak_attack::GakAttackConfig {
    fn from(args: GakAttackArgs) -> Self {
        Self {
            seed: args.seed,
            seeds_per_kind: args.seeds_per_kind,
            cyclic_order: args.cyclic_order,
            dihedral_half_order: args.dihedral_half_order,
            num_pt_letters: args.num_pt_letters,
            phrase_repeats: args.phrase_repeats,
            phrase_len: args.phrase_len,
            small_support_radius: args.small_support_radius,
        }
    }
}

#[derive(Clone, Debug, Args)]
struct GakAttackEyesArgs {
    /// Deterministic seed for the matched within-message shuffle null and the
    /// stable (clock-free) candidate-record label.
    #[arg(long, default_value_t = gak_attack::EYES_DEFAULT_SEED)]
    seed: u64,
    /// Matched within-message shuffle-null trials for the held-out gate.
    #[arg(long = "trials", default_value_t = gak_attack::EYES_DEFAULT_TRIALS)]
    trials: usize,
    /// Disclosed beam-width label recorded in the candidate-record filename/header;
    /// does NOT affect the eyes held-out scoring (the eyes run performs no per-column
    /// marginalization).
    #[arg(long = "beam-width", default_value_t = gak_attack::EYES_DEFAULT_BEAM_WIDTH)]
    beam_width: usize,
    /// Directory under which the mandatory candidate record is written.
    #[arg(
        long = "candidates-dir",
        default_value = gak_attack::EYES_DEFAULT_CANDIDATES_DIR
    )]
    candidates_dir: std::path::PathBuf,
}

impl From<GakAttackEyesArgs> for gak_attack::EyesAttackConfig {
    fn from(args: GakAttackEyesArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            beam_width: args.beam_width,
            candidates_dir: args.candidates_dir,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct NullArgs {
    #[arg(long, default_value_t = DEFAULT_NULL_SEED)]
    seed: u64,
    #[arg(long, default_value_t = DEFAULT_NULL_TRIALS)]
    trials: usize,
}

impl From<NullArgs> for null::NullConfig {
    fn from(args: NullArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct DofNullArgs {
    #[arg(long, default_value_t = DEFAULT_DOF_NULL_SEED)]
    seed: u64,
    #[arg(long, default_value_t = DEFAULT_DOF_NULL_TRIALS)]
    trials: usize,
    #[arg(long = "calib-trials")]
    calibration_trials: Option<usize>,
}

impl From<DofNullArgs> for dof_null::DofNullConfig {
    fn from(args: DofNullArgs) -> Self {
        Self {
            seed: args.seed,
            calibration_trials: args.calibration_trials.unwrap_or(args.trials),
            trials: args.trials,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct PeriodicityArgs {
    #[arg(long, default_value_t = periodicity::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = periodicity::DEFAULT_TRIALS)]
    trials: usize,
    #[arg(long = "max-period", default_value_t = periodicity::DEFAULT_MAX_PERIOD)]
    max_period: usize,
    #[arg(long = "max-lag", default_value_t = periodicity::DEFAULT_MAX_LAG)]
    max_lag: usize,
    #[arg(long = "min-ngram", default_value_t = periodicity::DEFAULT_MIN_NGRAM)]
    min_ngram: usize,
    #[arg(long = "max-ngram", default_value_t = periodicity::DEFAULT_MAX_NGRAM)]
    max_ngram: usize,
}

impl From<PeriodicityArgs> for periodicity::PeriodicityConfig {
    fn from(args: PeriodicityArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            max_period: args.max_period,
            max_lag: args.max_lag,
            min_ngram: args.min_ngram,
            max_ngram: args.max_ngram,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct HoneycombArgs {
    #[arg(long, default_value_t = honeycomb::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = honeycomb::DEFAULT_TRIALS)]
    trials: usize,
}

impl From<HoneycombArgs> for honeycomb::HoneycombConfig {
    fn from(args: HoneycombArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct IsomorphNullArgs {
    #[arg(long, default_value_t = isomorph_null::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = isomorph_null::DEFAULT_TRIALS)]
    trials: usize,
}

impl From<IsomorphNullArgs> for isomorph_null::IsomorphNullConfig {
    fn from(args: IsomorphNullArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct ChainingArgs {
    #[arg(long, default_value_t = chaining::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = chaining::DEFAULT_TRIALS)]
    trials: usize,
    #[arg(long = "min-period", default_value_t = chaining::DEFAULT_MIN_PERIOD)]
    min_period: usize,
    #[arg(long = "max-period", default_value_t = chaining::DEFAULT_MAX_PERIOD)]
    max_period: usize,
}

impl From<ChainingArgs> for chaining::ChainingConfig {
    fn from(args: ChainingArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            min_period: args.min_period,
            max_period: args.max_period,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct ChainingGraphArgs {
    #[arg(long, default_value_t = chaining_graph::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = chaining_graph::DEFAULT_TRIALS)]
    trials: usize,
}

impl From<ChainingGraphArgs> for chaining_graph::ChainingGraphConfig {
    fn from(args: ChainingGraphArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct ModularDiffArgs {
    #[arg(long, default_value_t = modular_diff::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = modular_diff::DEFAULT_TRIALS)]
    trials: usize,
    #[arg(long = "max-period", default_value_t = modular_diff::DEFAULT_MAX_PERIOD)]
    max_period: usize,
    #[arg(long = "max-lag", default_value_t = modular_diff::DEFAULT_MAX_LAG)]
    max_lag: usize,
}

impl From<ModularDiffArgs> for modular_diff::ModularDiffConfig {
    fn from(args: ModularDiffArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            max_period: args.max_period,
            max_lag: args.max_lag,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct PerseusArgs {
    #[arg(long, default_value_t = perseus::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = perseus::DEFAULT_TRIALS)]
    trials: usize,
}

impl From<PerseusArgs> for perseus::PerseusConfig {
    fn from(args: PerseusArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct PerfectIsomorphismArgs {
    #[arg(long, default_value_t = perfect_isomorphism::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = perfect_isomorphism::DEFAULT_TRIALS)]
    trials: usize,
    #[arg(long = "min-window", default_value_t = perfect_isomorphism::DEFAULT_MIN_WINDOW)]
    min_window: usize,
    #[arg(long = "max-window", default_value_t = perfect_isomorphism::DEFAULT_MAX_WINDOW)]
    max_window: usize,
}

impl From<PerfectIsomorphismArgs> for perfect_isomorphism::PerfectIsomorphismConfig {
    fn from(args: PerfectIsomorphismArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            min_window: args.min_window,
            max_window: args.max_window,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct HomogeneityArgs {
    #[arg(long, default_value_t = orientation_homogeneity::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = orientation_homogeneity::DEFAULT_TRIALS_PER_SEED)]
    trials: usize,
    #[arg(long, default_value_t = orientation_homogeneity::DEFAULT_SEED_COUNT)]
    seeds: usize,
}

impl From<HomogeneityArgs> for orientation_homogeneity::OrientationHomogeneityConfig {
    fn from(args: HomogeneityArgs) -> Self {
        Self {
            seed: args.seed,
            trials_per_seed: args.trials,
            seed_count: args.seeds,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct ZeroAdjacencyNullArgs {
    #[arg(long, default_value_t = zero_adjacency_null::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = zero_adjacency_null::DEFAULT_TRIALS_PER_SEED)]
    trials: usize,
    #[arg(long, default_value_t = zero_adjacency_null::DEFAULT_SEED_COUNT)]
    seeds: usize,
}

impl From<ZeroAdjacencyNullArgs> for zero_adjacency_null::ZeroAdjacencyNullConfig {
    fn from(args: ZeroAdjacencyNullArgs) -> Self {
        Self {
            seed: args.seed,
            trials_per_seed: args.trials,
            seed_count: args.seeds,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct TreeResidualArgs {
    #[arg(long, default_value_t = tree_residual::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = tree_residual::DEFAULT_TRIALS)]
    trials: usize,
    #[arg(long = "seed-count", default_value_t = tree_residual::DEFAULT_SEED_COUNT)]
    seed_count: usize,
}

impl From<TreeResidualArgs> for tree_residual::TreeResidualConfig {
    fn from(args: TreeResidualArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
            seed_count: args.seed_count,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct TransitivityArgs {
    #[arg(long, default_value_t = transitivity::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = transitivity::DEFAULT_TRIALS)]
    trials: usize,
}

impl From<TransitivityArgs> for transitivity::TransitivityConfig {
    fn from(args: TransitivityArgs) -> Self {
        Self {
            seed: args.seed,
            trials: args.trials,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct ConditionalArgs {
    #[arg(long, default_value_t = conditional_structure::DEFAULT_SEED)]
    seed: u64,
    #[arg(long = "seeds", default_value_t = conditional_structure::DEFAULT_SEED_COUNT)]
    seed_count: usize,
    #[arg(
        long = "trials-per-seed",
        default_value_t = conditional_structure::DEFAULT_TRIALS_PER_SEED
    )]
    trials_per_seed: usize,
}

impl From<ConditionalArgs> for conditional_structure::ConditionalStructureConfig {
    fn from(args: ConditionalArgs) -> Self {
        Self {
            seed: args.seed,
            seed_count: args.seed_count,
            trials_per_seed: args.trials_per_seed,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct CipherAttackArgs {
    #[arg(long, default_value_t = cipher_attack::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = cipher_attack::DEFAULT_SAMPLES)]
    samples: usize,
    #[arg(long = "null-trials", default_value_t = cipher_attack::DEFAULT_NULL_TRIALS)]
    null_trials: usize,
    #[arg(
        long = "max-vigenere-period",
        default_value_t = cipher_attack::DEFAULT_VIGENERE_MAX_PERIOD
    )]
    vigenere_max_period: usize,
}

impl From<CipherAttackArgs> for cipher_attack::CipherAttackConfig {
    fn from(args: CipherAttackArgs) -> Self {
        Self {
            seed: args.seed,
            samples: args.samples,
            null_trials: args.null_trials,
            vigenere_max_period: args.vigenere_max_period,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct PyryConditionsArgs {
    #[arg(long, default_value_t = pyry_conditions::DEFAULT_SEED)]
    seed: u64,
    #[arg(long = "draws", default_value_t = pyry_conditions::DEFAULT_FIXTURE_DRAWS)]
    fixture_draws: usize,
}

impl From<PyryConditionsArgs> for pyry_conditions::PyryConditionsConfig {
    fn from(args: PyryConditionsArgs) -> Self {
        Self {
            seed: args.seed,
            fixture_draws: args.fixture_draws,
        }
    }
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct ControlsArgs {
    #[arg(long)]
    seed: Option<u64>,
    #[command(subcommand)]
    target: Option<ControlTarget>,
}

#[derive(Debug, Subcommand)]
enum ControlTarget {
    /// Experiment 11 monoalphabetic positive control.
    Monoalphabetic(MonoalphabeticControlArgs),
    /// Experiment 11 isomorph/polyalphabetic positive control.
    #[command(alias = "polyalphabetic")]
    Isomorph(IsomorphControlArgs),
}

#[derive(Clone, Copy, Debug, Args)]
struct MonoalphabeticControlArgs {
    #[arg(long, default_value_t = controls::DEFAULT_MONOALPHABETIC_SEED)]
    seed: u64,
}

impl From<MonoalphabeticControlArgs> for controls::MonoalphabeticControlConfig {
    fn from(args: MonoalphabeticControlArgs) -> Self {
        Self { seed: args.seed }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct IsomorphControlArgs {
    #[arg(long, default_value_t = controls::DEFAULT_ISOMORPH_SEED)]
    seed: u64,
}

impl From<IsomorphControlArgs> for controls::IsomorphControlConfig {
    fn from(args: IsomorphControlArgs) -> Self {
        Self { seed: args.seed }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Stats(args) => run_stats(&args),
        Command::Demo => run_demo(),
        Command::Orders => run_orders(),
        Command::AglGak(args) => run_agl_gak(args.into()),
        Command::GakAttack(args) => run_gak_attack(args.into()),
        Command::GakAttackEyes(args) => run_gak_attack_eyes(args.into()),
        Command::Nulltest(args) => run_nulltest(args.into()),
        Command::Dofnull(args) => run_dofnull(args.into()),
        Command::Periodicity(args) => run_periodicity(args.into()),
        Command::Honeycomb(args) => run_honeycomb(args.into()),
        Command::Pipelinenull(args) => run_pipelinenull(args.into()),
        Command::Grouping => run_grouping(),
        Command::Homogeneity(args) => run_homogeneity(args.into()),
        Command::Isomorphnull(args) => run_isomorphnull(args.into()),
        Command::Chaining(args) => run_chaining(args.into()),
        Command::ChainingGraph(args) => run_chaining_graph(args.into()),
        Command::Moddiff(args) => run_moddiff(args.into()),
        Command::Perseus(args) => run_perseus(args.into()),
        Command::Perfectiso(args) => run_perfectiso(args.into()),
        Command::Zeroadjnull(args) => run_zeroadjnull(args.into()),
        Command::Treeresidual(args) => run_treeresidual(args.into()),
        Command::Transitivity(args) => run_transitivity(args.into()),
        Command::Conditional(args) => run_conditional(args.into()),
        Command::Cipherattack(args) => run_cipherattack(args.into()),
        Command::Pyry(args) => run_pyry(args.into()),
        Command::Controls(args) => run_controls(args),
        Command::Solve(args) => run_solve(&args),
        Command::Keystream(args) => run_keystream(&args),
    }
}

fn run_demo() -> ExitCode {
    match corpus::combined_sequence() {
        Ok(seq) => {
            print!(
                "{}",
                report::render_sequence_report("verified eye corpus", &seq)
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run_nulltest(config: null::NullConfig) -> ExitCode {
    let report = match null::run_standard36_null(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("null test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_agl_gak(config: agl_gak::AglGakConfig) -> ExitCode {
    let report = match agl_gak::run_agl_gak(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("AGL-GAK error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_gak_attack(config: gak_attack::GakAttackConfig) -> ExitCode {
    let report = match gak_attack::run_gak_attack(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("GAK-attack error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_gak_attack_eyes(config: gak_attack::EyesAttackConfig) -> ExitCode {
    let report = match gak_attack::run_gak_attack_eyes(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("GAK-attack eyes error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_dofnull(config: dof_null::DofNullConfig) -> ExitCode {
    let report = match dof_null::run_dof_null(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("DoF null error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_periodicity(config: periodicity::PeriodicityConfig) -> ExitCode {
    let report = match periodicity::run_periodicity(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("periodicity error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_honeycomb(config: honeycomb::HoneycombConfig) -> ExitCode {
    let report = match honeycomb::run_honeycomb(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("honeycomb lattice error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_pipelinenull(config: null::NullConfig) -> ExitCode {
    let pipeline_report = match pipeline_null::run_pipeline_null(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("pipeline null error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let input_report = match pipeline_null::input_randomness_report(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("input-randomness control error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", pipeline_report.render());
    println!();
    print!("{}", input_report.render());
    ExitCode::SUCCESS
}

fn run_grouping() -> ExitCode {
    let report = match grouping::run_experiment8() {
        Ok(report) => report,
        Err(error) => {
            eprintln!("grouping error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_homogeneity(config: orientation_homogeneity::OrientationHomogeneityConfig) -> ExitCode {
    let report = match orientation_homogeneity::run_orientation_homogeneity(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("orientation homogeneity error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_isomorphnull(config: isomorph_null::IsomorphNullConfig) -> ExitCode {
    let report = match isomorph_null::run_isomorph_null(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("isomorph null error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_chaining(config: chaining::ChainingConfig) -> ExitCode {
    let report = match chaining::run_chaining(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("chaining error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_chaining_graph(config: chaining_graph::ChainingGraphConfig) -> ExitCode {
    let report = match chaining_graph::run_chaining_graph(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("chaining-graph error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_moddiff(config: modular_diff::ModularDiffConfig) -> ExitCode {
    let report = match modular_diff::run_modular_diff(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("modular-difference error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_perseus(config: perseus::PerseusConfig) -> ExitCode {
    let report = match perseus::run_perseus(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("Perseus recurrence error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_perfectiso(config: perfect_isomorphism::PerfectIsomorphismConfig) -> ExitCode {
    let report = match perfect_isomorphism::run_perfect_isomorphism(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("perfect-isomorphism error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_zeroadjnull(config: zero_adjacency_null::ZeroAdjacencyNullConfig) -> ExitCode {
    let report = match zero_adjacency_null::run_zero_adjacency_null(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("zero-adjacency null error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_treeresidual(config: tree_residual::TreeResidualConfig) -> ExitCode {
    let report = match tree_residual::run_tree_residual(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("tree-residual null error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_transitivity(config: transitivity::TransitivityConfig) -> ExitCode {
    let report = match transitivity::run_transitivity(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("transitivity error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_conditional(config: conditional_structure::ConditionalStructureConfig) -> ExitCode {
    let report = match conditional_structure::run_conditional_structure(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("conditional structure error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_cipherattack(config: cipher_attack::CipherAttackConfig) -> ExitCode {
    let report = match cipher_attack::run_cipher_attack(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("cipher attack error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_pyry(config: pyry_conditions::PyryConditionsConfig) -> ExitCode {
    let report = match pyry_conditions::run_pyry_conditions(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("Pyry's Conditions error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_controls(args: ControlsArgs) -> ExitCode {
    let ControlsArgs { seed, target } = args;
    match target {
        Some(ControlTarget::Monoalphabetic(config)) => run_monoalphabetic_control(config.into()),
        Some(ControlTarget::Isomorph(config)) => run_isomorph_control(config.into()),
        None => {
            let config = controls::MonoalphabeticControlConfig {
                seed: seed.unwrap_or(controls::DEFAULT_MONOALPHABETIC_SEED),
            };
            run_monoalphabetic_control(config)
        }
    }
}

fn run_monoalphabetic_control(config: controls::MonoalphabeticControlConfig) -> ExitCode {
    let report = match controls::run_monoalphabetic_control(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("monoalphabetic control failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_isomorph_control(config: controls::IsomorphControlConfig) -> ExitCode {
    let report = match controls::run_isomorph_control(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("isomorph control failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report.render());
    ExitCode::SUCCESS
}

fn run_orders() -> ExitCode {
    let grids = match orders::corpus_grids() {
        Ok(grids) => grids,
        Err(error) => {
            eprintln!("grid reconstruction error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    let summary = orders::summarize_grids(&grids);
    let stats = match orders::audit_order_stats(&grids) {
        Ok(stats) => stats,
        Err(error) => {
            eprintln!("order audit error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    let flatness = match orders::audit_order_flatness_stats(&grids) {
        Ok(flatness) => flatness,
        Err(error) => {
            eprintln!("order flatness error: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    print!(
        "{}",
        report::render_orders_report(&summary, &stats, &flatness)
    );
    ExitCode::SUCCESS
}

#[derive(Debug)]
enum CliSequenceError {
    InvalidAlphabet(char),
    Ingest(ingest::IngestError),
}

impl std::fmt::Display for CliSequenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAlphabet(ch) => {
                write!(
                    f,
                    "invalid --alphabet: repeated or unrepresentable character {ch:?}"
                )
            }
            Self::Ingest(error) => write!(f, "{error}"),
        }
    }
}

fn resolve_input_text(
    sequence: Option<&str>,
    input_file: Option<&std::path::PathBuf>,
    stdin: bool,
) -> Result<String, io::Error> {
    match (sequence, input_file, stdin) {
        (Some(text), _, _) => Ok(text.to_owned()),
        (None, Some(path), _) => std::fs::read_to_string(path),
        (None, None, true | false) => {
            let mut text = String::new();
            let _bytes_read = io::stdin().read_to_string(&mut text)?;
            Ok(text)
        }
    }
}

fn parse_cli_sequence(
    text: &str,
    alphabet_spec: Option<&str>,
    honeycomb: bool,
) -> Result<ingest::ParsedSequence, CliSequenceError> {
    let transparent = ingest::TransparentSet::default();
    let alphabet;
    let layer = match alphabet_spec {
        Some(spec) => match Alphabet::from_chars(spec) {
            Ok(built) => {
                alphabet = built;
                ingest::SequenceLayer::CipherAlphabet {
                    alphabet: &alphabet,
                    transparent: &transparent,
                }
            }
            Err(c) => {
                return Err(CliSequenceError::InvalidAlphabet(c));
            }
        },
        None if honeycomb => ingest::SequenceLayer::HoneycombReading,
        None => ingest::SequenceLayer::RenderedOrientation,
    };
    ingest::parse_sequence(text, layer).map_err(CliSequenceError::Ingest)
}

fn run_stats(args: &StatsArgs) -> ExitCode {
    let text = match resolve_input_text(args.sequence.as_deref(), args.input_file.as_ref(), false) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return ExitCode::FAILURE;
        }
    };
    let rendered_layer = args.alphabet.is_none() && !args.honeycomb;

    match parse_cli_sequence(&text, args.alphabet.as_deref(), args.honeycomb) {
        Ok(parsed) => {
            let seq = Sequence {
                glyphs: parsed.glyphs,
            };
            print!("{}", report::render_sequence_report("input", &seq));
            ExitCode::SUCCESS
        }
        // Behavior-preserving: the pre-refactor rendered parser returned an empty
        // `Sequence` for empty / all-whitespace / all-delimiter input (e.g.
        // `stats 555`, `stats ""`), which `print_report` renders as a clean
        // 0-glyph report (entropy/IoC 0.0000, no frequencies, exit 0). The
        // library's `parse_sequence` still signals `Empty` for the solve
        // pipeline (brief 04); `stats` keeps the old report only for the rendered
        // layer (the honeycomb / cipher-alphabet paths are new, so their `Empty`
        // surfaces as an error).
        Err(CliSequenceError::Ingest(ingest::IngestError::Empty)) if rendered_layer => {
            print!(
                "{}",
                report::render_sequence_report("input", &Sequence { glyphs: Vec::new() })
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run_solve(args: &SolveArgs) -> ExitCode {
    let text = match resolve_input_text(
        args.ciphertext.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
    ) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return ExitCode::FAILURE;
        }
    };
    let alphabet_spec = args
        .alphabet
        .as_deref()
        .or((!args.honeycomb).then_some(DEFAULT_SOLVE_ALPHABET));
    let parsed = match parse_cli_sequence(&text, alphabet_spec, args.honeycomb) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let english = match language::english_model() {
        Ok(model) => model,
        Err(error) => {
            eprintln!("English model error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let finnish = match language::finnish_model() {
        Ok(model) => model,
        Err(error) => {
            eprintln!("Finnish model error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let cipher_alphabet_size = solve_alphabet_size(args, alphabet_spec, &parsed);
    let mappings = solve_mapping_strategy(args, cipher_alphabet_size, english.alphabet().len());
    let request = solve::SolveRequest {
        ciphertext: &parsed.glyphs,
        // Transparent (pass-through) symbols recorded at ingest — e.g. puzzle
        // `six`'s preserved spaces — reinserted into each candidate's rendered
        // text at codec-aware spots; empty (a strict no-op) for inputs without
        // any (the eyes, the default letter path).
        transparent: &parsed.transparent,
        space: solve::HypothesisSpace {
            families: solve_families(cipher_alphabet_size, &args.family),
            // Phase 1 default: Identity codec (the eyes' 83-symbol alphabet already
            // spans the 29-letter language; small-alphabet widening codecs land via
            // the library CodecStrategy as later phases wire CLI controls).
            codec: codec::CodecStrategy::Fixed(vec![codec::AnyCodec::Identity]),
            mappings,
            language: solve::LanguageChoice::Both,
            cipher_alphabet_size,
            seed: args.seed,
            null_trials: args.null_trials,
        },
        english: &english,
        finnish: &finnish,
    };

    let candidates = match solve::solve(&request) {
        Ok(candidates) => candidates,
        Err(error) => {
            eprintln!("solve error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_solve_report(&candidates);

    // Auto-log: persist the verbatim claim ceiling, all three gates, and both
    // language scores as a labelled HYPOTHESIS (the eyes honest-negative record
    // included). This is load-bearing claim discipline, not just stdout.
    match solve::log_solve_run(
        &args.candidates_dir,
        &args.label,
        args.seed,
        cipher_alphabet_size,
        &candidates,
        &english,
        &finnish,
    ) {
        Ok(path) => {
            println!("record: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to write candidate record: {error}");
            ExitCode::FAILURE
        }
    }
}

fn solve_mapping_strategy(
    args: &SolveArgs,
    cipher_alphabet_size: usize,
    language_alphabet_size: usize,
) -> solve::MappingStrategy {
    if args.mapping_search {
        solve::MappingStrategy::Search(solve::MappingSearch {
            restarts: args.restarts,
            iterations: args.iterations,
            anneal: (args.anneal_temp > 0.0).then_some(solve::AnnealSchedule {
                start_temperature: args.anneal_temp,
                end_temperature: 0.0,
            }),
            seed: args.seed,
        })
    } else {
        solve::MappingStrategy::Fixed(solve_mappings(cipher_alphabet_size, language_alphabet_size))
    }
}

fn solve_alphabet_size(
    args: &SolveArgs,
    alphabet_spec: Option<&str>,
    parsed: &ingest::ParsedSequence,
) -> usize {
    if args.honeycomb {
        return ciphers::EYE_READING_ALPHABET_SIZE;
    }
    if let Some(spec) = alphabet_spec {
        return spec.chars().count();
    }
    parsed
        .glyphs
        .iter()
        .map(|glyph| usize::from(glyph.0) + 1)
        .max()
        .unwrap_or(0)
}

fn solve_families(
    cipher_alphabet_size: usize,
    requested: &[SolveFamilyArg],
) -> Vec<solve::CipherFamilySpec> {
    let selected = if requested.is_empty() {
        vec![SolveFamilyArg::Identity, SolveFamilyArg::Caesar]
    } else {
        requested.to_vec()
    };
    let mut families = Vec::new();
    for family in selected {
        match family {
            SolveFamilyArg::Identity => families.push(solve::CipherFamilySpec {
                label: "identity".to_owned(),
                ciphers: vec![ciphers::AnyCipher::Identity],
            }),
            SolveFamilyArg::Caesar => families.push(solve::CipherFamilySpec {
                label: "Caesar".to_owned(),
                ciphers: caesar_family(cipher_alphabet_size),
            }),
            SolveFamilyArg::Transposition => families.push(solve::CipherFamilySpec {
                label: "transposition".to_owned(),
                ciphers: transposition_family(cipher_alphabet_size),
            }),
        }
    }
    families
}

fn caesar_family(cipher_alphabet_size: usize) -> Vec<ciphers::AnyCipher> {
    (0..cipher_alphabet_size)
        .filter_map(
            |shift| match ciphers::CaesarKey::new(cipher_alphabet_size, shift) {
                Ok(key) => Some(ciphers::AnyCipher::Caesar(key)),
                Err(_error) => None,
            },
        )
        .collect()
}

fn transposition_family(cipher_alphabet_size: usize) -> Vec<ciphers::AnyCipher> {
    let max_period = cipher_alphabet_size.clamp(2, 6);
    (2..=max_period)
        .filter_map(|period| {
            let permutation = (0..period).rev().collect::<Vec<_>>();
            match ciphers::TranspositionKey::new(period, permutation) {
                Ok(key) => Some(ciphers::AnyCipher::Transposition(key)),
                Err(_error) => None,
            }
        })
        .collect()
}

fn solve_mappings(
    cipher_alphabet_size: usize,
    language_alphabet_size: usize,
) -> Vec<solve::Mapping> {
    if cipher_alphabet_size <= language_alphabet_size {
        vec![solve::Mapping::identity(cipher_alphabet_size)]
    } else {
        vec![solve::Mapping::from_table(
            (0..cipher_alphabet_size)
                .map(|symbol| symbol % language_alphabet_size)
                .collect(),
        )]
    }
}

fn print_solve_report(candidates: &[solve::Candidate]) {
    println!("Solve candidates: HYPOTHESIS, not decode");
    println!("candidates: {}", candidates.len());
    let Some(top) = candidates.first() else {
        println!("no candidate survived the cipher-layer round-trip gate");
        return;
    };
    println!("top:");
    println!("  cipher: {}", top.cipher.name());
    println!("  language: {:?}", top.language);
    println!("  crypto_round_trip_ok: {}", top.crypto_round_trip_ok);
    println!("  score: {:.6}", top.score);
    println!("  heldout_mapping_score: {:.6}", top.heldout_mapping_score);
    println!("  null_mean: {:.6}", top.null_mean);
    println!("  beats_null: {}", top.beats_null);
    println!(
        "  rendered_text: {}",
        display_prefix(&top.rendered_text, 120)
    );
}

fn display_prefix(text: &str, max_chars: usize) -> String {
    let mut rendered = text.chars().take(max_chars).collect::<String>();
    if text.chars().count() > max_chars {
        rendered.push_str("...");
    }
    rendered
}

fn run_keystream(args: &KeystreamArgs) -> ExitCode {
    let ciphertext = match keystream_ciphertext(args) {
        Ok(ciphertext) => ciphertext,
        Err(code) => return code,
    };
    if ciphertext.is_empty() {
        eprintln!("no cipher letters in input");
        return ExitCode::FAILURE;
    }
    let model = match quadgram::QuadgramModel::english() {
        Ok(model) => model,
        Err(error) => {
            eprintln!("quadgram model error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let families: Vec<keystream::KeystreamFamily> = if args.family.is_empty() {
        keystream::KeystreamFamily::all().to_vec()
    } else {
        args.family.iter().map(|family| (*family).into()).collect()
    };
    let key_lengths: Vec<usize> = if let Some(fixed) = args.key_len {
        vec![fixed.max(1)]
    } else {
        let lo = args.min_key_len.max(1);
        let hi = args.max_key_len.max(lo);
        (lo..=hi).collect()
    };
    let cfg = keystream::KeystreamSearchConfig {
        alphabet_size: args.alphabet_size.max(1),
        restarts: args.restarts,
        iterations: args.iterations,
        anneal_temp: args.anneal_temp,
        seed: args.seed,
        null_trials: args.null_trials,
        matched_null_trials: args.matched_null_trials,
    };

    let mut candidates = Vec::new();
    for &family in &families {
        for &key_len in &key_lengths {
            candidates.push(keystream::crack_with_model(
                &ciphertext,
                family,
                key_len,
                &cfg,
                &model,
            ));
        }
    }

    print_keystream_table(&candidates);
    print_keystream_best(&candidates);

    let label = args
        .label
        .clone()
        .or_else(|| args.puzzle.map(|puzzle| puzzle.label().to_owned()))
        .unwrap_or_else(|| "input".to_owned());
    emit_keystream_verdict(&candidates, &args.candidates_dir, &label, args.seed)
}

fn keystream_ciphertext(args: &KeystreamArgs) -> Result<Vec<u8>, ExitCode> {
    if let Some(puzzle) = args.puzzle {
        return Ok(keystream::normalize_puzzle(
            keystream::practice_puzzle_text(puzzle.into()),
        ));
    }
    match resolve_input_text(None, args.input_file.as_ref(), args.stdin) {
        Ok(text) => Ok(keystream::normalize_puzzle(&text)),
        Err(error) => {
            eprintln!("failed to read input: {error}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn print_keystream_table(candidates: &[keystream::KeystreamCandidate]) {
    println!("Keystream candidates: HYPOTHESIS, not decode");
    println!(
        "survives requires BOTH nulls: matched_z (search-overfitting gate) AND null_z (ct-autokey key-independence-leak gate)"
    );
    println!(
        "{:11} {:>3} {:>10} {:>12} {:>10} {:>8} {:>10} {:>8}",
        "family", "L", "best", "matched_mean", "matched_z", "null_z", "round_trip", "survives"
    );
    for candidate in candidates {
        println!(
            "{:11} {:>3} {:>10.4} {:>12.4} {:>10.2} {:>8.2} {:>10} {:>8}",
            candidate.family.name(),
            candidate.key_len,
            candidate.best_score,
            candidate.matched_mean,
            candidate.matched_z,
            candidate.z,
            candidate.round_trip_ok,
            candidate.survives,
        );
    }
}

fn print_keystream_best(candidates: &[keystream::KeystreamCandidate]) {
    // Rank by matched_z (the survival statistic), survivors first.
    let best = candidates
        .iter()
        .filter(|candidate| candidate.survives)
        .max_by(|left, right| left.matched_z.total_cmp(&right.matched_z))
        .or_else(|| {
            candidates
                .iter()
                .max_by(|left, right| left.matched_z.total_cmp(&right.matched_z))
        });
    let Some(best) = best else {
        return;
    };
    println!(
        "best (highest matched_z{}):",
        if best.survives {
            ", surviving"
        } else {
            ", non-surviving"
        }
    );
    println!(
        "  family: {}  key-len: {}",
        best.family.name(),
        best.key_len
    );
    println!("  key: {:?}", best.key);
    println!(
        "  matched_z: {:.4}  matched_margin: {:.4}  matched_mean: {:.4}",
        best.matched_z,
        best.best_score - best.matched_mean,
        best.matched_mean,
    );
    println!(
        "  random-key null_z (ct-autokey-leak gate): {:.4}  null_mean: {:.4}",
        best.z, best.null_mean,
    );
    println!(
        "  decrypt: {}",
        display_prefix(&best.render_plaintext(), 120)
    );
}

fn emit_keystream_verdict(
    candidates: &[keystream::KeystreamCandidate],
    candidates_dir: &std::path::Path,
    label: &str,
    seed: u64,
) -> ExitCode {
    let survivors: Vec<&keystream::KeystreamCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.survives)
        .collect();
    if survivors.is_empty() {
        println!(
            "HONEST-NEGATIVE: no (family, key length) candidate cleared the round-trip + matched-null + random-key-null (each z>={:.0} AND margin>={:.0} nat) + held-out gates. A clean honest negative is a SUCCESS, not an error.",
            keystream::Z_THRESHOLD,
            keystream::MIN_NAT_MARGIN,
        );
        return ExitCode::SUCCESS;
    }
    for candidate in survivors {
        println!(
            "HYPOTHESIS (not a confirmed decode; cleared BOTH null gates): family={} key-len={} matched_z={:.2} null_z={:.2}",
            candidate.family.name(),
            candidate.key_len,
            candidate.matched_z,
            candidate.z,
        );
        println!("  full decrypt: {}", candidate.render_plaintext());
        match keystream::write_keystream_record(candidates_dir, label, seed, candidate) {
            Ok(path) => println!("  record: {}", path.display()),
            Err(error) => {
                eprintln!("failed to write candidate record: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
