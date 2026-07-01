//! Cipher attacks, language models, and the solve/keystream pipelines.
//!
//! - [`agl_gak`]: Thread 2 AGL(1,83)-GAK structural stress test and exclusion
//!   audit.
//! - [`cipher_attack`]: Experiment 12 attack/null harness that scores named
//!   candidate ciphers only under declared, unverified symbol-to-letter
//!   mappings.
//! - [`codecpower`]: detection-power calibration for `rlcodec`'s comma-code
//!   matched-null gate at practice puzzle `one`'s carrier budget.
//! - [`codec`]: codec transduction layer feeding the [`solve`] search.
//! - [`gak_attack`]: Thread 4 synthetic GAK generator and the decisive GCTAK
//!   solver gate, validated against held-back ground truth (synthetic-only).
//! - [`keystream`]: polyalphabetic keystream cracker (Vigenere/Beaufort/autokey)
//!   with an annealed key search, quadgram scoring, and z-score/held-out gates.
//! - [`language`]: English/Finnish n-gram language models for scoring candidate
//!   plaintexts.
//! - [`mdlcodec`]: crib-synchronous MDL-like affine running-key codec search for
//!   `one`'s run-length carrier, with post-selection crib-pinned nulls and a
//!   candidate-only verdict.
//! - [`profile`]: ciphertext structural profile (whole-stream and per-period
//!   index of coincidence, absent letters, per-word column `IoC`, and maximal
//!   cross-word-boundary repeats) for the practice letter puzzles.
//! - [`quadgram`]: large-corpus `A..Z` quadgram English language model for
//!   scoring candidate plaintexts during polyalphabetic key search.
//! - [`ragbaby`]: general (non-keyword) Ragbaby keyed-alphabet cracker with a
//!   simulated-annealing search, quadgram scoring, a planted-recovery positive
//!   control, and a matched-null/held-out survival gate.
//! - [`rankcodec`]: bounded-order predictive-rank codec analysis for `one`'s
//!   run-length magnitude carrier, with feasibility and crib-consistency as the
//!   primary discriminators and the underpowered quadgram gate as tertiary.
//! - [`rlcodec`]: run-length codec battery for `±1`-walk puzzles — derives the
//!   direction-blind magnitude carrier, censuses its exact repeats, and gates a
//!   family of codecs against a matched order-1 Markov null over each codec's
//!   decoded symbol stream, with a planted positive control and self-test.
//! - [`cribfit`]: crib-anchored consistency filter for the codec-with-memory
//!   regime of `rlcodec`'s carrier — a language-free necessary condition (repeated
//!   plaintext spans must decode identically) that excludes most stateful/keyed
//!   codecs and derives the admissible state/key period, reusing `rlcodec`'s
//!   carrier, matched-null gate, and English model.
//! - [`solve`]: unified search-and-score solve pipeline for candidate
//!   hypotheses, with round-trip, held-out, and matched-null gates.

pub mod agl_gak;
pub mod cipher_attack;
pub mod codec;
pub mod codecpower;
/// Shared scaffolding (`mean_std`, the null-comparison gate, the matched-null loop,
/// and the invariant candidate-record blocks) for the keystream and ragbaby crackers.
mod crack;
pub mod cribfit;
pub mod gak_attack;
pub mod keystream;
pub mod language;
pub mod mdlcodec;
pub mod profile;
pub mod quadgram;
pub mod ragbaby;
pub mod rankcodec;
pub mod rlcodec;
pub mod solve;
