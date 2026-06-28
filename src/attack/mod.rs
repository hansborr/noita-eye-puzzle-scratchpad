//! Cipher attacks, language models, and the solve/keystream pipelines.
//!
//! - [`agl_gak`]: Thread 2 AGL(1,83)-GAK structural stress test and exclusion
//!   audit.
//! - [`cipher_attack`]: Experiment 12 attack/null harness that scores named
//!   candidate ciphers only under declared, unverified symbol-to-letter
//!   mappings.
//! - [`codec`]: codec transduction layer feeding the [`solve`] search.
//! - [`gak_attack`]: Thread 4 synthetic GAK generator and the decisive GCTAK
//!   solver gate, validated against held-back ground truth (synthetic-only).
//! - [`keystream`]: polyalphabetic keystream cracker (Vigenere/Beaufort/autokey)
//!   with an annealed key search, quadgram scoring, and z-score/held-out gates.
//! - [`language`]: English/Finnish n-gram language models for scoring candidate
//!   plaintexts.
//! - [`profile`]: ciphertext structural profile (whole-stream and per-period
//!   index of coincidence, absent letters, per-word column `IoC`, and maximal
//!   cross-word-boundary repeats) for the practice letter puzzles.
//! - [`quadgram`]: large-corpus `A..Z` quadgram English language model for
//!   scoring candidate plaintexts during polyalphabetic key search.
//! - [`ragbaby`]: general (non-keyword) Ragbaby keyed-alphabet cracker with a
//!   simulated-annealing search, quadgram scoring, a planted-recovery positive
//!   control, and a matched-null/held-out survival gate.
//! - [`solve`]: unified search-and-score solve pipeline for candidate
//!   hypotheses, with round-trip, held-out, and matched-null gates.

pub mod agl_gak;
pub mod cipher_attack;
pub mod codec;
/// Shared scaffolding (`mean_std`, the null-comparison gate, the matched-null loop,
/// and the invariant candidate-record blocks) for the keystream and ragbaby crackers.
mod crack;
pub mod gak_attack;
pub mod keystream;
pub mod language;
pub mod profile;
pub mod quadgram;
pub mod ragbaby;
pub mod solve;
