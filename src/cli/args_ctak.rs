//! Argument struct for the `ctakscan` subcommand (the ciphertext-autokey
//! feedback-deck discriminator). Kept in its own module so the analysis-arg
//! registry stays under the file-size budget.

use clap::Args;
use noita_eye_puzzle::analysis::ctak_feedback;

use super::shared::parse_seed;

/// `ctakscan`: the ciphertext-autokey (feedback) deck discriminator for the
/// `C3 × H` hidden-state GAK reading. Searches the advance map `g` of the
/// feedback regime `groupscan`/`keydiff` leave untested and reports whether one
/// `g` reproduces the rotor-anchor plaintext repeat in the deck channel above a
/// deck-resample null. A verdict is a structural discriminator over the
/// feedback-deck family, never recovered plaintext.
#[derive(Debug, Args)]
pub(crate) struct CtakscanArgs {
    /// Symbol sequence. Optional: omit to read from --input-file or stdin.
    pub(crate) sequence: Option<String>,
    /// Read the sequence from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    pub(crate) input_file: Option<std::path::PathBuf>,
    /// Read the sequence from stdin.
    #[arg(long = "stdin", conflicts_with_all = ["sequence", "input_file"])]
    pub(crate) stdin: bool,
    /// Cipher alphabet chars, in order (e.g. ABCDEFGHIJKL). Defaults to rendered
    /// orientation digits when omitted; the alphabet size must be a multiple of
    /// the rotor modulus and the implied deck size at most 4.
    #[arg(long = "alphabet")]
    pub(crate) alphabet: Option<String>,
    /// Rotor modulus: the transparent direct-product factor (`r = symbol % M`).
    /// The deck channel is `q = symbol / M` over `alphabet_size / M` card values.
    #[arg(long = "rotor-mod", default_value_t = ctak_feedback::DEFAULT_ROTOR_MOD)]
    pub(crate) rotor_mod: usize,
    /// Minimum rotor-difference-channel anchor length to seed a joint crib.
    #[arg(long = "min-anchor-len", default_value_t = ctak_feedback::DEFAULT_MIN_ANCHOR_LEN)]
    pub(crate) min_anchor_len: usize,
    /// Maximum number of rotor-difference-channel anchors used jointly.
    #[arg(long = "top-k", default_value_t = ctak_feedback::DEFAULT_TOP_K)]
    pub(crate) top_k: usize,
    /// Number of matched-null trials (each reruns the full advance-map search).
    #[arg(long = "null-trials", default_value_t = ctak_feedback::DEFAULT_NULL_TRIALS)]
    pub(crate) null_trials: usize,
    /// Deterministic seed (decimal or 0x-hex) for the matched null and controls.
    #[arg(long, default_value_t = ctak_feedback::DEFAULT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Run the in-process controls (planted feedback deck + no-feedback null) and
    /// print PASS/FAIL instead of scanning input.
    #[arg(long = "self-test")]
    pub(crate) self_test: bool,
}
