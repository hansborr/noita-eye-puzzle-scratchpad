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

/// Hidden-base construction family exposed by the CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum GakHiddenBaseKind {
    /// Uniform random permutation.
    Random,
    /// Structured affine base with shift=floor(n/3)+1 and decimation=3.
    Affine,
}
