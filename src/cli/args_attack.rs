//! Argument structs for the practice-puzzle / attack subcommands (stats, solve,
//! keystream, ragbaby, profile, AGL-GAK, GAK-attack) plus their `From`
//! conversions into the library config types.

use clap::{Args, Subcommand, ValueEnum};
use noita_eye_puzzle::{
    analysis::translate_isomorph,
    attack::{agl_gak, gak_attack, keystream, ragbaby, solve},
    ciphers,
};

use super::shared::parse_seed;

const DEFAULT_CANDIDATES_DIR: &str = "research/gak-threads/candidates";
const DEFAULT_SOLVE_RESTARTS: usize = 6;
const DEFAULT_SOLVE_ITERATIONS: usize = 8_000;

#[derive(Debug, Args)]
pub(crate) struct StatsArgs {
    /// Rendered orientation sequence (digits 0-4, optional delimiter 5).
    /// Optional: omit to read from --input-file or stdin.
    pub(crate) sequence: Option<String>,
    /// Read the ciphertext from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Treat the input as accepted honeycomb reading-layer values (0-82, the
    /// alphabet solve consumes) rather than rendered orientation digits.
    #[arg(long = "honeycomb")]
    pub(crate) honeycomb: bool,
    /// Treat the input as a general cipher alphabet (these chars, in order, are
    /// the cipher symbols; e.g. ABCDEFGHIJKLMNOPQRSTUVWXYZ for a letter puzzle).
    /// Spaces/punctuation (`. , ? ! #`, newline) pass through as transparent
    /// symbols. For the practice corpus, not the eyes; conflicts with
    /// --honeycomb.
    #[arg(long = "alphabet", conflicts_with = "honeycomb")]
    pub(crate) alphabet: Option<String>,
}

#[derive(Clone, Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "CLI flag struct: stdin/honeycomb/mapping-search/codec-search are independent user toggles, not a packed state machine"
)]
pub(crate) struct SolveArgs {
    /// Ciphertext sequence. Optional: omit to read from --input-file or stdin.
    pub(crate) ciphertext: Option<String>,
    /// Read the ciphertext from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "ciphertext")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the ciphertext from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["ciphertext", "input_file"])]
    pub(crate) stdin: bool,
    /// Treat the input as accepted honeycomb reading-layer values (0-82).
    #[arg(long = "honeycomb", conflicts_with = "alphabet")]
    pub(crate) honeycomb: bool,
    /// Cipher alphabet chars, in order. Defaults to A-Z for letter puzzles.
    #[arg(long = "alphabet", conflicts_with = "honeycomb")]
    pub(crate) alphabet: Option<String>,
    /// Cipher family to enumerate. Repeat to include more than one.
    #[arg(long = "family", value_enum)]
    pub(crate) family: Vec<SolveFamilyArg>,
    /// Deterministic seed for the matched-null control. Accepts decimal or a
    /// `0x`-prefixed hex value, so the `--seed 0x{:016x}` form printed in a
    /// record's Provenance section is itself copy-pasteable (the D2 guarantee).
    #[arg(long, default_value_t = solve::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Number of matched-null shuffles.
    #[arg(long = "null-trials", default_value_t = solve::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Fixed codec between the decrypted cipher symbols and the symbol->letter
    /// mapping (ignored when --codec-search is set). `identity` is the
    /// behavior-preserving default (cipher alphabet already spans the language,
    /// e.g. the 83-symbol eyes); `honeycomb` is the canonical base-5 trigram
    /// grouping.
    #[arg(long = "codec", value_enum, default_value_t = SolveCodecArg::Identity)]
    pub(crate) codec: SolveCodecArg,
    /// Enumerate codec parameters (grouping `group_len`, both digit orders, delta)
    /// and run the mapping strategy on each transduced stream, flipping the codec
    /// stage from Fixed to Search (parallel to --mapping-search). Widens a small
    /// cipher alphabet (5/6/12 symbols) enough to host 26-29-letter language.
    /// Implies --mapping-search: a widened (`base^group_len`) alphabet has no fixed
    /// mapping, so this auto-enables the mapping search over the codec's output.
    #[arg(long = "codec-search")]
    pub(crate) codec_search: bool,
    /// Hill-climb / anneal the symbol->letter mapping (Phase 2) instead of
    /// scoring the fixed declared mappings.
    #[arg(long = "mapping-search")]
    pub(crate) mapping_search: bool,
    /// Mapping-search random restarts (only with --mapping-search).
    #[arg(long, default_value_t = DEFAULT_SOLVE_RESTARTS)]
    pub(crate) restarts: usize,
    /// Mapping-search proposals per restart (only with --mapping-search).
    #[arg(long, default_value_t = DEFAULT_SOLVE_ITERATIONS)]
    pub(crate) iterations: usize,
    /// Annealing start temperature (only with --mapping-search); 0 = pure
    /// hill-climb (accept only non-worsening proposals).
    #[arg(long = "anneal-temp", default_value_t = 0.0)]
    pub(crate) anneal_temp: f64,
    /// Directory for the machine-written candidate record (a labelled
    /// hypothesis, never a decode). Auto-logged after every run.
    #[arg(long = "candidates-dir", default_value = DEFAULT_CANDIDATES_DIR)]
    pub(crate) candidates_dir: std::path::PathBuf,
    /// Stable label for the candidate-record filename (no wall clock).
    #[arg(long, default_value = "cli")]
    pub(crate) label: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum SolveFamilyArg {
    /// No-key passthrough cipher.
    Identity,
    /// Exhaustive Caesar shifts over the parsed alphabet.
    Caesar,
    /// Small synthetic transposition candidates.
    Transposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum SolveCodecArg {
    /// Pass-through codec: output alphabet == cipher alphabet (the eyes' codec).
    Identity,
    /// The eye honeycomb base-5 trigram grouping (`FixedGrouping{3,5,Msb,3}`).
    Honeycomb,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct KeystreamArgs {
    /// Built-in practice letter-puzzle to crack.
    #[arg(long, value_enum, conflicts_with_all = ["input_file", "stdin"])]
    pub(crate) puzzle: Option<KeystreamPuzzleArg>,
    /// Read the ciphertext (letters only; other characters dropped) from a file.
    #[arg(long = "input-file", conflicts_with = "stdin")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the ciphertext from stdin.
    #[arg(long, conflicts_with = "input_file")]
    pub(crate) stdin: bool,
    /// Cipher family to search. Repeat to include more than one; default = all.
    #[arg(long = "family", value_enum)]
    pub(crate) family: Vec<KeystreamFamilyArg>,
    /// Smallest key length searched (used unless --key-len is given).
    #[arg(long = "min-key-len", default_value_t = 1)]
    pub(crate) min_key_len: usize,
    /// Largest key length searched (used unless --key-len is given).
    #[arg(long = "max-key-len", default_value_t = 20)]
    pub(crate) max_key_len: usize,
    /// Search a single fixed key length (overrides --min-key-len/--max-key-len).
    #[arg(long = "key-len")]
    pub(crate) key_len: Option<usize>,
    /// Alphabet size N.
    #[arg(long = "alphabet-size", default_value_t = keystream::DEFAULT_ALPHABET_SIZE)]
    pub(crate) alphabet_size: usize,
    /// Annealed-search random restarts.
    #[arg(long, default_value_t = keystream::DEFAULT_RESTARTS)]
    pub(crate) restarts: usize,
    /// Annealing iterations per restart.
    #[arg(long, default_value_t = keystream::DEFAULT_ITERATIONS)]
    pub(crate) iterations: usize,
    /// Annealing start temperature; 0 = pure hill-climb.
    #[arg(long = "anneal-temp", default_value_t = keystream::DEFAULT_ANNEAL_TEMP)]
    pub(crate) anneal_temp: f64,
    /// Deterministic seed for the search and the matched null.
    #[arg(long, default_value_t = keystream::DEFAULT_SEED)]
    pub(crate) seed: u64,
    /// Number of random-key null trials for the reported diagnostic (not the gate).
    #[arg(long = "null-trials", default_value_t = keystream::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Number of matched-null trials (reruns of the search on shuffled
    /// ciphertext) — the survival gate. 0 disables survival.
    #[arg(long = "matched-null-trials", default_value_t = keystream::DEFAULT_MATCHED_NULL_TRIALS)]
    pub(crate) matched_null_trials: usize,
    /// Directory for any surviving candidate's record (a labelled hypothesis).
    #[arg(long = "candidates-dir", default_value = DEFAULT_CANDIDATES_DIR)]
    pub(crate) candidates_dir: std::path::PathBuf,
    /// Stable label for candidate-record filenames (defaults to the puzzle name).
    #[arg(long)]
    pub(crate) label: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum KeystreamPuzzleArg {
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
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Three => "three",
            Self::Four => "four",
            Self::Five => "five",
            Self::Seven => "seven",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum KeystreamFamilyArg {
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

#[derive(Clone, Debug, Args)]
pub(crate) struct RagbabyArgs {
    /// Built-in practice letter-puzzle to crack (raw text; word structure kept).
    #[arg(long, value_enum, conflicts_with_all = ["input_file", "stdin"])]
    pub(crate) puzzle: Option<KeystreamPuzzleArg>,
    /// Read raw puzzle text (word structure preserved) from a file.
    #[arg(long = "input-file", conflicts_with = "stdin")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read raw puzzle text from stdin.
    #[arg(long, conflicts_with = "input_file")]
    pub(crate) stdin: bool,
    /// Alphabet bases to sweep (24 drops J,V; 25 drops J; 26 keeps A-Z).
    #[arg(long, value_delimiter = ',', default_value = "24,25,26")]
    pub(crate) bases: Vec<usize>,
    /// Numbering conventions to sweep. Repeat or comma-separate; default = all.
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) numbering: Vec<RagbabyNumberingArg>,
    /// Shift sign(s) to search.
    #[arg(long, value_enum, default_value_t = RagbabySignArg::Both)]
    pub(crate) sign: RagbabySignArg,
    /// Annealed-search random restarts.
    #[arg(long, default_value_t = ragbaby::DEFAULT_RESTARTS)]
    pub(crate) restarts: usize,
    /// Simulated-annealing iterations per restart.
    #[arg(long, default_value_t = ragbaby::DEFAULT_ITERATIONS)]
    pub(crate) iterations: usize,
    /// Basin-hopping perturbation rounds per restart.
    #[arg(long = "basin-hops", default_value_t = ragbaby::DEFAULT_BASIN_HOPS)]
    pub(crate) basin_hops: usize,
    /// Matched-null trials (reruns of the search on shuffled letters) — the
    /// survival gate. 0 disables survival.
    #[arg(long = "matched-null-trials", default_value_t = ragbaby::DEFAULT_MATCHED_NULL_TRIALS)]
    pub(crate) matched_null_trials: usize,
    /// Random-keyed-alphabet null trials for the reported diagnostic.
    #[arg(long = "null-trials", default_value_t = ragbaby::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Deterministic seed for the search and both nulls.
    #[arg(long, default_value_t = ragbaby::DEFAULT_SEED)]
    pub(crate) seed: u64,
    /// Run the planted-recovery positive control (length sweep) instead of
    /// attacking a puzzle.
    #[arg(long)]
    pub(crate) control: bool,
    /// Plaintext letter-lengths to sweep in `--control`.
    #[arg(long = "control-lengths", value_delimiter = ',', default_value = "274")]
    pub(crate) control_lengths: Vec<usize>,
    /// Planted-recovery trials per `(length, base)` cell in `--control`.
    #[arg(long = "control-trials", default_value_t = ragbaby::DEFAULT_CONTROL_TRIALS)]
    pub(crate) control_trials: usize,
    /// Directory for any surviving candidate's record (a labelled hypothesis).
    #[arg(long = "candidates-dir", default_value = DEFAULT_CANDIDATES_DIR)]
    pub(crate) candidates_dir: std::path::PathBuf,
    /// Stable label for candidate-record filenames (defaults to the puzzle name).
    #[arg(long)]
    pub(crate) label: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum RagbabyNumberingArg {
    /// Standard ACA numbering (`N = w + (k - 1)`).
    Std,
    /// Per-word numbering (`1, 2, 3, …` within each word).
    Perword,
    /// Continuous numbering across the whole text.
    Continuous,
}

impl From<RagbabyNumberingArg> for ragbaby::Numbering {
    fn from(arg: RagbabyNumberingArg) -> Self {
        match arg {
            RagbabyNumberingArg::Std => Self::Std,
            RagbabyNumberingArg::Perword => Self::PerWord,
            RagbabyNumberingArg::Continuous => Self::Continuous,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum RagbabySignArg {
    /// Search both `+1` and `-1`.
    Both,
    /// Search `+1` only.
    Plus,
    /// Search `-1` only.
    Minus,
}

impl RagbabySignArg {
    pub(crate) fn signs(self) -> Vec<ragbaby::Sign> {
        match self {
            Self::Both => vec![ragbaby::Sign::Plus, ragbaby::Sign::Minus],
            Self::Plus => vec![ragbaby::Sign::Plus],
            Self::Minus => vec![ragbaby::Sign::Minus],
        }
    }
}

#[derive(Clone, Debug, Args)]
pub(crate) struct ProfileArgs {
    /// Built-in practice letter-puzzle to profile.
    #[arg(long, value_enum, conflicts_with = "input_file")]
    pub(crate) puzzle: Option<KeystreamPuzzleArg>,
    /// Read raw puzzle text from this file instead of a built-in puzzle (falls
    /// back to stdin when neither is given).
    #[arg(long = "input-file")]
    pub(crate) input_file: Option<std::path::PathBuf>,
}

#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct AglGakArgs {
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
pub(crate) struct GakAttackArgs {
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
    /// Tentative small-support radius (`<=k` transpositions). Rejected for the
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
pub(crate) struct GakAttackEyesArgs {
    /// Deterministic seed for the matched within-message shuffle null and the
    /// stable (clock-free) candidate-record label.
    #[arg(long, default_value_t = gak_attack::EYES_DEFAULT_SEED)]
    seed: u64,
    /// Matched within-message shuffle-null trials for the held-out gate.
    #[arg(long = "trials", default_value_t = gak_attack::EYES_DEFAULT_TRIALS)]
    trials: usize,
    /// Disclosed beam-width label recorded in the candidate-record filename/header;
    /// does not affect the eyes held-out scoring (the eyes run performs no per-column
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

/// File-driven instruments over the hidden-state (deck-stabilizer, convention B)
/// GAK. Each mode runs on arbitrary ciphertext from the CLI and self-validates
/// against controls — it is a runnable tool, not a fixture-frozen analysis.
#[derive(Clone, Debug, Args)]
pub(crate) struct GakArgs {
    /// Which instrument to run.
    #[command(subcommand)]
    pub(crate) mode: GakMode,
}

/// The three `gak` instrument modes.
#[derive(Clone, Debug, Subcommand)]
pub(crate) enum GakMode {
    /// Structural hidden-vs-visible discriminator (Markov-excess; no language
    /// model). Prints the excess drop, matched same-length synthetic references,
    /// and a hidden/visible verdict.
    Discriminate(GakDiscriminateArgs),
    /// Honest candidate generator: the Viterbi + held-out genetic solver gated by a
    /// matched no-English control. Emits a candidate, never a decode.
    Solve(GakSolveArgs),
    /// In-process self-test: a synthetic positive control plus a matched null,
    /// printing PASS/FAIL so the instrument can be trusted before it is believed on
    /// real data.
    #[command(name = "self-test")]
    SelfTest(GakSelfTestArgs),
}

/// Arguments for `gak discriminate`.
#[derive(Clone, Debug, Args)]
pub(crate) struct GakDiscriminateArgs {
    /// Ciphertext sequence. Optional: omit to read from --input-file or stdin.
    pub(crate) ciphertext: Option<String>,
    /// Read the ciphertext from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "ciphertext")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the ciphertext from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["ciphertext", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order. Defaults to the 12-symbol convention-B
    /// alphabet ABCDEFGHIJKL; a non-12 alphabet reports the raw excess only (the
    /// synthetic calibration references are undefined off the 12-symbol regime).
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
}

/// Arguments for `gak solve`.
#[derive(Clone, Debug, Args)]
pub(crate) struct GakSolveArgs {
    /// Ciphertext sequence. Optional: omit to read from --input-file or stdin.
    pub(crate) ciphertext: Option<String>,
    /// Read the ciphertext from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "ciphertext")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the ciphertext from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["ciphertext", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order (must be the 12-symbol convention-B
    /// alphabet). Defaults to ABCDEFGHIJKL.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// English text file to train the plaintext bigram language model (reduced to
    /// 8 symbols by the assumed codec). Defaults to the bundled English corpus.
    #[arg(long = "lm-corpus")]
    pub(crate) lm_corpus: Option<std::path::PathBuf>,
    /// Genetic-search population size.
    #[arg(long, default_value_t = gak_attack::hidden_state_solver::DEFAULT_POPULATION)]
    pub(crate) population: usize,
    /// Genetic-search generations.
    #[arg(long, default_value_t = gak_attack::hidden_state_solver::DEFAULT_GENERATIONS)]
    pub(crate) generations: usize,
    /// Deterministic seed (decimal or 0x-hex) for the search and the matched
    /// no-English control.
    #[arg(
        long,
        default_value_t = gak_attack::hidden_state_solver::DEFAULT_SEED,
        value_parser = parse_seed
    )]
    pub(crate) seed: u64,
}

/// Arguments for `gak self-test`.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct GakSelfTestArgs {
    /// Deterministic seed (decimal or 0x-hex) for the synthetic blind solve.
    #[arg(
        long,
        default_value_t = gak_attack::hidden_state_solver::DEFAULT_SEED,
        value_parser = parse_seed
    )]
    pub(crate) seed: u64,
}

/// `isoscan`: translate-isomorph (exact repeated-substring) scanner with an
/// order-1 Markov matched null. Finds where a stream repeats — optionally on the
/// `--delta-mod` difference channel — and reports anchors as structural
/// candidates, never decodes.
#[derive(Debug, Args)]
pub(crate) struct IsoscanArgs {
    /// Symbol sequence. Optional: omit to read from --input-file or stdin.
    pub(crate) sequence: Option<String>,
    /// Read the sequence from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the sequence from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order (e.g. ABCDEFGHIJKL or 01234). Defaults to
    /// rendered orientation digits when omitted.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Scan the modular finite-difference channel `d[i] = (v[i+1]-v[i]) mod M`
    /// instead of the raw stream (exposes additive-walk / autokey plaintext
    /// repeats; e.g. 3 for puzzle `two`'s rotor channel, 5 for puzzle `one`).
    #[arg(long = "delta-mod")]
    pub(crate) delta_mod: Option<usize>,
    /// Maximum number of anchors to report.
    #[arg(long = "top-k", default_value_t = translate_isomorph::DEFAULT_TOP_K)]
    pub(crate) top_k: usize,
    /// Number of matched-null (order-1 Markov resample) trials.
    #[arg(long = "null-trials", default_value_t = translate_isomorph::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Deterministic seed (decimal or 0x-hex) for the matched null.
    #[arg(long, default_value_t = translate_isomorph::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run the in-process positive control (a planted exact repeat + matched null)
    /// and print PASS/FAIL instead of scanning input.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
