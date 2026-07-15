//! Argument struct for the hidden-base GAK/deck identifiability audit.

use clap::{Args, ValueEnum};
use noita_eye_puzzle::attack::gak_attack::lymm_deck::DEFAULT_HIDDEN_BASE_AUDIT_SEED;

use super::shared::parse_seed;

/// `gak-hidden-base-audit`: plant hidden-base known-plaintext fixtures and
/// measure base-decomposition identifiability. This is not a ciphertext-only
/// attack and uses exact re-encryption only.
#[derive(Clone, Debug, Args)]
pub(crate) struct GakHiddenBaseAuditArgs {
    /// Deck size.
    #[arg(long = "n", default_value_t = 11)]
    pub(crate) n: usize,
    /// Plaintext alphabet. Defaults to the first min(n-1, 26) uppercase letters.
    #[arg(long = "pt-alphabet")]
    pub(crate) pt_alphabet: Option<String>,
    /// Top-card swap budget used to plant and audit each `sigma_L`.
    #[arg(long = "num-swaps", default_value_t = 2)]
    pub(crate) num_swaps: usize,
    /// Number of identity-restart messages per fixture.
    #[arg(long = "messages", default_value_t = 8)]
    pub(crate) messages: usize,
    /// Plaintext alphabet characters per message.
    #[arg(long = "message-len", default_value_t = 64)]
    pub(crate) message_len: usize,
    /// Number of deterministic fixtures to sample.
    #[arg(long = "trials", default_value_t = 8)]
    pub(crate) trials: usize,
    /// Hidden-base construction family.
    #[arg(long = "base-kind", value_enum, default_value_t = GakHiddenBaseKind::Random)]
    pub(crate) base_kind: GakHiddenBaseKind,
    /// Deterministic seed for fixtures and controls.
    #[arg(long, default_value_t = DEFAULT_HIDDEN_BASE_AUDIT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Skip the planted-positive and matched-null controls.
    #[arg(long = "skip-controls")]
    pub(crate) skip_controls: bool,
}

/// `gak-hidden-base-s1-recover`: plant hidden-base `s=1` known-plaintext
/// fixtures and run the exhaustive unknown-base solver. This is not an eyes
/// attack and accepts only exact re-encryption.
#[derive(Clone, Debug, Args)]
pub(crate) struct GakHiddenBaseS1RecoverArgs {
    /// Deck size.
    #[arg(long = "n", default_value_t = 7)]
    pub(crate) n: usize,
    /// Plaintext alphabet. Defaults to the first min(n-1, 26) uppercase letters.
    #[arg(long = "pt-alphabet")]
    pub(crate) pt_alphabet: Option<String>,
    /// Number of identity-restart messages per fixture.
    #[arg(long = "messages", default_value_t = 8)]
    pub(crate) messages: usize,
    /// Plaintext alphabet characters per message.
    #[arg(long = "message-len", default_value_t = 48)]
    pub(crate) message_len: usize,
    /// Number of deterministic fixtures to sample.
    #[arg(long = "trials", default_value_t = 3)]
    pub(crate) trials: usize,
    /// Optional cap on candidate hidden bases tested per trial.
    #[arg(long = "max-base-candidates")]
    pub(crate) max_base_candidates: Option<usize>,
    /// Hidden-base construction family.
    #[arg(long = "base-kind", value_enum, default_value_t = GakHiddenBaseKind::Random)]
    pub(crate) base_kind: GakHiddenBaseKind,
    /// Deterministic seed for fixtures and controls.
    #[arg(long, default_value_t = DEFAULT_HIDDEN_BASE_AUDIT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Skip the planted-positive and matched-null solver controls.
    #[arg(long = "skip-controls")]
    pub(crate) skip_controls: bool,
}

/// `gak-hidden-base-local-recover`: plant hidden-base `s=2..3`
/// known-plaintext fixtures and run the bounded local solver. This is not an
/// eyes attack and accepts only exact re-encryption.
#[derive(Clone, Debug, Args)]
pub(crate) struct GakHiddenBaseLocalRecoverArgs {
    /// Deck size.
    #[arg(long = "n", default_value_t = 7)]
    pub(crate) n: usize,
    /// Plaintext alphabet. Defaults to the first min(n-1, 26) uppercase letters.
    #[arg(long = "pt-alphabet")]
    pub(crate) pt_alphabet: Option<String>,
    /// Top-card swap budget admitted by the local solver.
    #[arg(long = "num-swaps", default_value_t = 2)]
    pub(crate) num_swaps: usize,
    /// Number of identity-restart messages per fixture.
    #[arg(long = "messages", default_value_t = 8)]
    pub(crate) messages: usize,
    /// Plaintext alphabet characters per message.
    #[arg(long = "message-len", default_value_t = 48)]
    pub(crate) message_len: usize,
    /// Number of deterministic fixtures to sample.
    #[arg(long = "trials", default_value_t = 2)]
    pub(crate) trials: usize,
    /// Local-search random restarts per trial.
    #[arg(long = "attempts", default_value_t = 96)]
    pub(crate) attempts: usize,
    /// Coordinate-descent rounds per restart.
    #[arg(long = "max-rounds", default_value_t = 18)]
    pub(crate) max_rounds: usize,
    /// Maximum top-source hypotheses retained for sigma refinement.
    #[arg(long = "top-source-beam", default_value_t = 96)]
    pub(crate) top_source_beam: usize,
    /// Use only the landed second-symbol likelihood for top-source ranking.
    #[arg(long = "disable-third-symbol-rank")]
    pub(crate) disable_third_symbol_rank: bool,
    /// Candidate order for stalled two-letter sigma moves.
    #[arg(long = "joint-move-order", value_enum, default_value_t = GakHiddenBaseJointMoveOrder::Hybrid)]
    pub(crate) joint_move_order: GakHiddenBaseJointMoveOrder,
    /// Maximum two-letter sigma assignments scored per stalled s=3 restart.
    #[arg(long = "joint-move-cap", default_value_t = 4_096)]
    pub(crate) joint_move_cap: usize,
    /// Maximum two-letter sigma assignments scored over the complete run.
    #[arg(long = "joint-total-cap", default_value_t = 393_216)]
    pub(crate) joint_total_cap: usize,
    /// Maximum fourth-prefix triple assignments checked per stalled s=3 restart.
    #[arg(long = "triple-move-cap", default_value_t = 0)]
    pub(crate) triple_move_cap: usize,
    /// Maximum fourth-prefix triple assignments checked over the complete run.
    #[arg(long = "triple-total-cap", default_value_t = 0)]
    pub(crate) triple_total_cap: usize,
    /// Hidden-base construction family.
    #[arg(long = "base-kind", value_enum, default_value_t = GakHiddenBaseKind::Random)]
    pub(crate) base_kind: GakHiddenBaseKind,
    /// Deterministic seed for fixtures, controls, and local restarts.
    #[arg(long, default_value_t = DEFAULT_HIDDEN_BASE_AUDIT_SEED, value_parser = parse_seed)]
    pub(crate) seed: u64,
    /// Skip the planted-positive and matched-null solver controls.
    #[arg(long = "skip-controls")]
    pub(crate) skip_controls: bool,
}

/// Hidden-base construction family exposed by the CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum GakHiddenBaseKind {
    /// Uniform random permutation.
    Random,
    /// Structured affine base with shift=floor(n/3)+1 and decimation=3.
    Affine,
}

/// Two-letter candidate order exposed by the hidden-base local CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum GakHiddenBaseJointMoveOrder {
    /// Exhaust one letter-pair product before visiting the next pair.
    PairMajor,
    /// Visit one candidate from every letter pair in repeated strata.
    PairRoundRobin,
    /// Split each pass between round-robin breadth and pair-major depth.
    Hybrid,
}
