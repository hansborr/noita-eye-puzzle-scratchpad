//! Top-level `clap` parser: the [`Cli`] entry point and the [`Command`]
//! subcommand enum. The per-command `*Args` structs and their `From` impls live
//! in the [`super::args_analysis`] / [`super::args_attack`] sibling modules.

use clap::{Parser, Subcommand};

use super::args_analysis::{
    ChainingArgs, ChainingGraphArgs, CipherAttackArgs, ConditionalArgs, ControlsArgs, DofNullArgs,
    HomogeneityArgs, HoneycombArgs, IsomorphNullArgs, ModularDiffArgs, NullArgs,
    PerfectIsomorphismArgs, PeriodicityArgs, PerseusArgs, PyryConditionsArgs, TransitivityArgs,
    TreeResidualArgs, ZeroAdjacencyNullArgs,
};
use super::args_attack::{
    AglGakArgs, GakAttackArgs, GakAttackEyesArgs, KeystreamArgs, ProfileArgs, RagbabyArgs,
    SolveArgs, StatsArgs,
};

#[derive(Debug, Parser)]
#[command(
    name = "noita-eye",
    about = "Noita eye-glyph puzzle toolkit",
    after_help = "Digit 5 is treated as a row delimiter and ignored for glyph statistics."
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
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
    /// Thread 4 eyes Step 3: point the matured attack at the real eye corpus.
    /// Held-out + Thread-3 gated; expected outcome is no surviving candidate; the
    /// decode remains blocked. Writes a mandatory candidate record.
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
    /// Search and score solve hypotheses; candidates are hypotheses, not decodes.
    Solve(SolveArgs),
    /// Crack a polyalphabetic keystream cipher (Vigenere/Beaufort/autokey) on a
    /// practice letter-puzzle. Honest-negative is the expected outcome on the
    /// non-periodic puzzles; any survivor is a hypothesis, never a decode.
    #[command(name = "keystream")]
    Keystream(KeystreamArgs),
    /// Crack a general (non-keyword) Ragbaby keyed-alphabet cipher on a practice
    /// letter-puzzle, or run the planted-recovery positive control (`--control`).
    /// Honest-negative is the expected outcome on the puzzles; any survivor is a
    /// hypothesis, never a decode.
    #[command(name = "ragbaby")]
    Ragbaby(RagbabyArgs),
    /// Ciphertext structural profile (`IoC`, per-period flatness, absent letters,
    /// per-word columns, cross-boundary repeats) for a practice letter-puzzle.
    /// These are structural negative findings that constrain the cipher family.
    Profile(ProfileArgs),
}
