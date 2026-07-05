//! Top-level `clap` parser: the [`Cli`] entry point and the [`Command`]
//! subcommand enum. The per-command `*Args` structs and their `From` impls live
//! in the [`super::args_analysis`] / [`super::args_attack`] sibling modules.

use clap::{Parser, Subcommand};

use super::args_analysis::{
    ChainingArgs, ChainingGraphArgs, CipherAttackArgs, ConditionalArgs, ControlsArgs, CrcscanArgs,
    DofNullArgs, GroupscanArgs, HomogeneityArgs, HoneycombArgs, IsomorphImperfectionArgs,
    IsomorphNullArgs, KeydiffArgs, LeakCeilingArgs, ModularDiffArgs, NullArgs,
    PerfectIsomorphismArgs, PeriodicityArgs, PerseusArgs, PyryConditionsArgs, TransitivityArgs,
    TreeResidualArgs, ZeroAdjacencyNullArgs,
};
use super::args_attack::{
    AglGakArgs, GakArgs, GakAttackArgs, GakAttackEyesArgs, IsoscanArgs, KeystreamArgs, ProfileArgs,
    RagbabyArgs, SolveArgs, StatsArgs,
};
use super::args_bigramcodec::BigramcodecArgs;
use super::args_codecpower::CodecpowerArgs;
use super::args_cribfit::CribfitArgs;
use super::args_ctak::CtakscanArgs;
use super::args_gak_swap::GakSwapRecoverArgs;
use super::args_isomap::IsomapArgs;
use super::args_maskdecode::MaskdecodeArgs;
use super::args_mdlcodec::MdlcodecArgs;
use super::args_pairclass::PairclassArgs;
use super::args_predicates::PredscanArgs;
use super::args_rankcodec::RankcodecArgs;
use super::args_rlcodec::RlcodecArgs;
use super::args_shadowfinish::ShadowfinishArgs;
use super::args_shadowsearch::ShadowsearchArgs;

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
    /// Hidden-state (deck-stabilizer) GAK instruments: a structural hidden-vs-visible
    /// discriminator, an honest candidate generator, and an in-process self-test.
    /// Runs on arbitrary ciphertext; a solve emits a candidate, never a decode.
    #[command(name = "gak")]
    Gak(GakArgs),
    /// Known-plaintext recovery for Lymm's top-swap deck-cipher mappings.
    /// Runs on arbitrary labeled `(plaintext, ciphertext)` pairs; exact
    /// re-encryption is the only verified recovery criterion.
    #[command(name = "gak-swap-recover")]
    GakSwapRecover(GakSwapRecoverArgs),
    /// Translate-isomorph (exact repeated-substring) scanner with an order-1
    /// Markov matched null. Locates where a stream repeats — optionally on the
    /// `--delta-mod` difference channel — as a structural candidate, never a decode.
    #[command(name = "isoscan")]
    Isoscan(IsoscanArgs),
    /// Equality-pattern isomorph column-map extraction plus closure of full
    /// maps. Reports a reconstructed state-group lower bound, never a decode.
    #[command(name = "isomap")]
    Isomap(IsomapArgs),
    /// Hidden-state key search over an `isomap`-derived closure group. Applies
    /// trimmed hard anchors and soft literal-repeat ranking, then reports
    /// quotient candidates under the closure shadow, never decodes.
    #[command(name = "shadowsearch", alias = "shadow-search")]
    Shadowsearch(ShadowsearchArgs),
    /// Crib-free finish over a `shadowsearch --output` residual artifact.
    /// Enumerates q-label digit permutations, digit orders, and charset tables;
    /// gates the ranking against matched decoy q-pattern nulls; and accepts only
    /// exact visible-ciphertext re-encoding through the representative shadow key.
    #[command(name = "shadowfinish", alias = "shadow-finish")]
    Shadowfinish(ShadowfinishArgs),
    /// Run-length codec battery for `±1`-walk puzzles. Derives the direction-blind
    /// run-length magnitude carrier, censuses its exact repeats, and gates a family
    /// of codecs against a matched Markov-resampled-`M` null. A near-English codec
    /// score that does not beat the matched null is an artifact, never a decode;
    /// the expected verdict on real `one` is an honest negative.
    #[command(name = "rlcodec")]
    Rlcodec(RlcodecArgs),
    /// Bigram-order codec probe for base-walk puzzles. Scores digit-pair, edge,
    /// and magnitude-pair token streams with English/Finnish bigram models, then
    /// reports readability coverage plus order-0 shuffle and order-1 Markov
    /// diagnostics. A candidate is a readable hypothesis, never a decode.
    #[command(name = "bigramcodec")]
    Bigramcodec(BigramcodecArgs),
    /// Detection-power ceiling for `rlcodec`'s comma-code matched-null gate at
    /// practice puzzle `one`'s carrier budget. Plants English and matched
    /// non-English controls, then reuses the actual `rlcodec` gate; this is a
    /// method calibration, never a plaintext claim.
    #[command(name = "codecpower")]
    Codecpower(CodecpowerArgs),
    /// Crib-anchored consistency filter for the codec-with-memory regime of
    /// `rlcodec`'s run-length carrier. Derives the cribs' run-gap/bit-gap geometry
    /// and the state/key periods it admits, tests each codec family by the
    /// language-free necessary condition that repeated plaintext spans decode
    /// identically, and language-gates the crib-consistent + English-viable
    /// survivors against the same matched null `rlcodec` uses. The expected verdict
    /// on real `one` is an honest negative plus the derived structural constraint.
    #[command(name = "cribfit")]
    Cribfit(CribfitArgs),
    /// Bounded-order predictive-rank codec analysis for `one`'s run-length
    /// carrier. Feasibility and crib-consistency are the primary discriminators;
    /// the quadgram gate is tertiary and underpowered at 135 magnitudes.
    #[command(name = "rankcodec")]
    Rankcodec(RankcodecArgs),
    /// Masked `C_n`-walk ASCII readout for `±1`-walk puzzles. Derives the
    /// walk's direction bits, sweeps static/alternating masks x chunk width x
    /// offset x bit-order x polarity x direction, and promotes a full-letter
    /// readout to a verified decode only via an exact round-trip re-encode.
    /// Packages the verified practice-puzzle-`one` solve (`Permutation
    /// Representation Destination`, `RoundTrip` 266/266).
    #[command(name = "maskdecode")]
    Maskdecode(MaskdecodeArgs),
    /// Crib-synchronous MDL-like affine running-key codec search for `one`'s
    /// run-length carrier. It selects a shortest crib-consistent candidate under a
    /// post-selection crib-pinned null; emitted-symbol-history codecs are out of
    /// scope, and the output is a candidate, never a decode.
    #[command(name = "mdlcodec")]
    Mdlcodec(MdlcodecArgs),
    /// Pair-class decipherment for `±1`-walk carriers with a two-symbols-per-letter
    /// codec (the practice-puzzle-`two` rotor-carrier model). Derives the residue
    /// walk's direction-bit pair tokens (a public 4-class image of the plaintext),
    /// finds exact repeated spans as tie anchors, and runs a memory-bounded
    /// dictionary beam solver with incremental coloring induction and hard tie
    /// equalities. Planted controls measure search power before any real result is
    /// trusted; a matched order-1 Markov null gates it. Emits candidates, never
    /// decodes. With no input flags it runs the embedded practice puzzle `two`.
    #[command(name = "pairclass")]
    Pairclass(PairclassArgs),
    /// D4/A4/S4 hidden-group element-order discriminator for the `C3 × H`
    /// hidden-state GAK reading of a deck/rotor cipher. Reads the deck channel's
    /// induced permutation across difference-channel anchors; a verdict is a
    /// structural discriminator over the hidden group, never a decode.
    #[command(name = "groupscan")]
    Groupscan(GroupscanArgs),
    /// Ciphertext-autokey (feedback) deck discriminator for the `C3 × H`
    /// hidden-state GAK reading of a deck/rotor cipher. Exhaustively searches the
    /// advance map `g` of the feedback regime that `groupscan`/`keydiff` leave
    /// untested (the deck advances on the emitted ciphertext, so its trajectory is
    /// computable), gated on whether one `g` reproduces the rotor-anchor plaintext
    /// repeat in the deck channel above a deck-resample null. A verdict is a
    /// structural discriminator over the feedback-deck family, never a decode.
    #[command(name = "ctakscan")]
    Ctakscan(CtakscanArgs),
    /// Toboter predicate battery + multiple-comparisons meta-analysis (Thread C).
    /// Recomputes each community-listed arithmetic predicate against the repo's
    /// matched nulls (within-message shuffle for the gap predicate, value-resample
    /// for the magnitude/sum predicates) and reports how many "surprising" hits
    /// would survive given how many were tested. Individually-weak predicates are
    /// never findings; the meta-analysis is the deliverable.
    #[command(name = "predscan")]
    Predscan(PredscanArgs),
    /// Thread B isomorph key-difference discriminator. Recovers the additive
    /// realisation Δ of the isomorph relabelling and classifies it by
    /// finite-difference order (identical / constant-additive / linear /
    /// irregular); the constant bucket splits classical-autokey vs
    /// progressive-alphabet. A verdict is a structural discriminator, never a decode.
    #[command(name = "keydiff")]
    Keydiff(KeydiffArgs),
    /// Stored-u32 CRC/hash word scanner with calibrated false-alarm significance.
    /// Reports candidate mapping anchors, never recovered plaintext.
    #[command(name = "crcscan")]
    Crcscan(CrcscanArgs),
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
    /// Thread G2 forward isomorph-imperfection disproof scan. With no input flags
    /// runs the verified eye corpus; a stream input is a cross-message test that
    /// does not apply to a single message and emits no claim about the input.
    #[command(name = "isomorphimperf", alias = "isomorph-imperfection")]
    Isomorphimperf(IsomorphImperfectionArgs),
    /// Leak supply / demand / bounds. With no input flags runs the verified eye
    /// corpus (the full report incl. the fitted coverage model). A stream input runs
    /// only the transparent measured supply, coupon-collector demand, and
    /// information-theoretic / counting bounds -- no recoverability prediction.
    #[command(name = "leakceiling", alias = "leak-ceiling")]
    Leakceiling(LeakCeilingArgs),
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
