//! General (non-keyword) Ragbaby cipher cracker for the practice letter-puzzles.
//!
//! The Ragbaby cipher is a polyalphabetic substitution over a single *keyed
//! alphabet* `K` (a permutation of the `base` letters). Each plaintext letter is
//! shifted along `K` by a position-dependent **key number** `N_i` derived from the
//! word structure of the text, then read back off `K`. The unknown this module
//! recovers is the keyed alphabet itself, found by a strong simulated-annealing
//! optimizer scored against the bundled [`crate::attack::quadgram`] English model.
//!
//! It is the keyed-alphabet analogue of [`crate::attack::keystream`]: it searches and
//! scores hypotheses, gates them against a matched null and a held-out fold, and
//! reports an explicit **honest negative** when nothing survives — the expected
//! outcome on the practice puzzles. Crucially it ships with a **positive control**
//! (a planted-recovery length sweep) so that a negative is only ever reported
//! alongside a demonstrated ability to recover a planted Ragbaby at that length.
//!
//! # Cipher definition
//!
//! Let `pos(x)` be the index of letter `x` in `K`. The plaintext is split into
//! words (maximal runs of letters); non-letters are separators. The per-letter key
//! number `N_i` depends on the numbering convention ([`Numbering`]):
//!
//! - [`Numbering::Std`] (ACA): the `k`-th letter (1-indexed) of word `w`
//!   (1-indexed) gets `N = w + (k - 1)`.
//! - [`Numbering::PerWord`]: each word is numbered `1, 2, 3, …` independently.
//! - [`Numbering::Continuous`]: the counter increments across the whole text and
//!   never resets (position-keyed).
//!
//! Encrypt: `c = K[(pos(p) + sign * N) mod base]`. Decrypt:
//! `p = K[(pos(c) - sign * N) mod base]`.
//!
//! ## Real-letter-index space
//!
//! `K` is a permutation whose **values are the real `A..Z` letter indices** of the
//! kept set, so the English quadgram model is meaningful at every base:
//!
//! - base 26: keep `[0..26]` (identity over `A..Z`).
//! - base 25: keep `[0..26]` minus `{9}` (J), folding `J -> I` before indexing.
//! - base 24: keep `[0..26]` minus `{9, 21}` (J, V), folding `J -> I`, `V -> U`.
//!
//! The kept letters are **not** relabelled into a contiguous `0..base` space: doing
//! so would shift every letter past `J` and the recovered plaintext would no longer
//! be English in scoring space (base-25/24 recovery would silently collapse). For
//! base 26 the path is the identity, so the base-26 case is unaffected.
//!
//! # Survival gate
//!
//! A candidate survives only when, against the **matched null** (the same annealed
//! search rerun on a Fisher-Yates shuffle of the ciphertext *letter* stream with
//! the key-number sequence `N_i` held fixed), it clears the z-score floor
//! ([`Z_THRESHOLD`]) and the absolute nat floor ([`MIN_NAT_MARGIN`]) on the
//! quadgram **mean** scale, AND `encrypt(decrypt) == ciphertext` (a round-trip
//! sanity gate), AND a held-out odd-index fold reads above the matched-null mean.
//! The matched null shares the search's degrees of freedom, so it measures exactly
//! what the keyed-alphabet search extracts from noise. A random-keyed-alphabet null
//! is reported as a diagnostic only — Ragbaby has no key-independence leak for it to
//! police (unlike ciphertext-autokey in [`crate::attack::keystream`]).

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::attack::quadgram::QuadgramModel;
use crate::nulls::null::SplitMix64;

mod cipher;
mod scoring;
mod search;
#[cfg(test)]
mod tests;

pub use cipher::{
    Numbering, Sign, decrypt_indices, decrypt_str, encrypt_indices, encrypt_str, fold_idx,
    keep_for_base, key_numbers, prepare,
};
pub use scoring::{
    RagbabyCandidate, RagbabyProblem, best_decryption, char_accuracy, crack, crack_with_model,
};
pub use search::RagbabySearchConfig;
use search::random_keyed_alphabet;

/// Minimum z-score (best score above the matched-null mean, in null standard
/// deviations) required to clear the survival gate, on the quadgram mean-log scale.
pub const Z_THRESHOLD: f64 = 6.0;

/// Minimum absolute nat margin (`best_score - matched_mean`, mean scale) required
/// to clear the survival gate, guarding the degenerate tiny-`std` case.
pub const MIN_NAT_MARGIN: f64 = 1.0;

/// Default multi-restart count (validated confirmatory default).
pub const DEFAULT_RESTARTS: usize = 40;

/// Default simulated-annealing iterations per restart (validated confirmatory
/// default).
pub const DEFAULT_ITERATIONS: usize = 20_000;

/// Default basin-hopping perturbation rounds per restart (validated confirmatory
/// default).
pub const DEFAULT_BASIN_HOPS: usize = 6;

/// Default annealing start temperature (nat scale).
pub const DEFAULT_T0: f64 = 12.0;

/// Default annealing end temperature (nat scale).
pub const DEFAULT_T1: f64 = 0.3;

/// Default deterministic seed for the search and both nulls.
pub const DEFAULT_SEED: u64 = 0x7261_6762_6162_7900;

/// Default random-keyed-alphabet null-trial count (the reported DIAGNOSTIC).
pub const DEFAULT_NULL_TRIALS: usize = 64;

/// Default matched-null trial count: reruns of the FULL search on a shuffled
/// ciphertext letter stream. Each trial is a full multi-restart anneal, so this is
/// the dominant cost knob — kept modest.
pub const DEFAULT_MATCHED_NULL_TRIALS: usize = 6;

/// Default planted-recovery trials per `(length, base)` cell in `--control`.
pub const DEFAULT_CONTROL_TRIALS: usize = 6;

// ===========================================================================
// Positive control: planted-recovery length sweep
// ===========================================================================

/// Configuration for the planted-recovery control sweep.
#[derive(Clone, Debug)]
pub struct ControlConfig {
    /// Plaintext letter-lengths to sweep.
    pub lengths: Vec<usize>,
    /// Alphabet bases to sweep.
    pub bases: Vec<usize>,
    /// Planted-recovery trials per `(length, base)` cell.
    pub trials: usize,
    /// Numbering convention used for all planted ciphers.
    pub numbering: Numbering,
    /// Shift sign used for all planted ciphers.
    pub sign: Sign,
    /// Optimizer configuration (the seed seeds the whole sweep).
    pub search: RagbabySearchConfig,
}

/// One `(length, base)` cell of the planted-recovery control sweep.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ControlPoint {
    /// Target plaintext letter-length.
    pub length: usize,
    /// Alphabet base.
    pub base: usize,
    /// Number of planted-recovery trials run.
    pub trials: usize,
    /// Fraction of trials reaching ≥ 0.9 char accuracy versus the known plaintext.
    pub recovery_rate: f64,
    /// Median per-trial char accuracy.
    pub median_acc: f64,
    /// Mean per-trial char accuracy.
    pub mean_acc: f64,
}

/// Splits `corpus` into uppercased ASCII-letter words (runs of letters).
fn corpus_words(corpus: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for ch in corpus.chars() {
        if ch.is_ascii_alphabetic() {
            current.push(ch.to_ascii_uppercase());
        } else if !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Draws a contiguous run of `words` whose total letter count first reaches
/// `target_letters`, joined by single spaces (mirrors the Python control chunker).
fn sample_chunk(words: &[String], target_letters: usize, rng: &mut SplitMix64) -> String {
    if words.is_empty() {
        return String::new();
    }
    let upper = words.len().saturating_sub(80).max(1);
    let start = (rng.next_u64() % upper as u64) as usize;
    let mut accumulated: Vec<&str> = Vec::new();
    let mut total = 0usize;
    let mut index = start;
    while total < target_letters && index < words.len() {
        if let Some(word) = words.get(index) {
            total += word.len();
            accumulated.push(word.as_str());
        }
        index += 1;
    }
    accumulated.join(" ")
}

/// Summarizes the per-trial accuracies of one `(length, base)` cell.
fn summarize_control(length: usize, base: usize, accs: &[f64]) -> ControlPoint {
    let trials = accs.len();
    let recovered = accs.iter().filter(|&&acc| acc >= 0.9).count();
    let recovery_rate = if trials == 0 {
        0.0
    } else {
        recovered as f64 / trials as f64
    };
    let mut sorted = accs.to_vec();
    sorted.sort_by(f64::total_cmp);
    let median_acc = crate::nulls::null::median_f64(&sorted);
    let mean_acc = if trials == 0 {
        0.0
    } else {
        accs.iter().sum::<f64>() / trials as f64
    };
    ControlPoint {
        length,
        base,
        trials,
        recovery_rate,
        median_acc,
        mean_acc,
    }
}

/// Runs the planted-recovery control sweep: for each `(length, base)`, plant a
/// random-keyed-alphabet Ragbaby of an English excerpt of `corpus`, run the
/// optimizer, and report the recovery rate and accuracy. This is the POSITIVE
/// CONTROL that makes a negative on the real puzzles trustworthy. Deterministic in
/// `control.search.seed`.
#[must_use]
pub fn control_sweep(
    corpus: &str,
    control: &ControlConfig,
    model: &QuadgramModel,
) -> Vec<ControlPoint> {
    let words = corpus_words(corpus);
    let mut master = SplitMix64::new(control.search.seed);
    let mut points = Vec::new();
    for &length in &control.lengths {
        for &base in &control.bases {
            let keep = keep_for_base(base);
            let mut accs: Vec<f64> = Vec::with_capacity(control.trials);
            for _trial in 0..control.trials {
                let plaintext = sample_chunk(&words, length, &mut master);
                let (plain_idx, nums) = prepare(&plaintext, control.numbering, base);
                let planted = random_keyed_alphabet(&keep, &mut master);
                let cipher =
                    encrypt_indices(&plain_idx, &nums, &planted, control.sign.value(), base);
                let cfg = RagbabySearchConfig {
                    seed: master.next_u64(),
                    ..control.search
                };
                let problem = RagbabyProblem {
                    cipher: &cipher,
                    nums: &nums,
                    base,
                    sign: control.sign,
                    numbering: control.numbering,
                };
                let recovered = best_decryption(&problem, &cfg, model);
                accs.push(char_accuracy(&recovered, &plain_idx));
            }
            points.push(summarize_control(length, base, &accs));
        }
    }
    points
}

// ===========================================================================
// Candidate record writer (mirrors keystream::write_keystream_record)
// ===========================================================================

/// Slugifies a label into a filename-safe lowercase token.
fn slugify(label: &str) -> String {
    label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// Builds the stable, clock-free candidate-record filename.
fn record_filename(label: &str, candidate: &RagbabyCandidate, seed: u64) -> String {
    format!(
        "ragbaby-{}-base{}-{}-{}-seed-{seed:016x}.md",
        slugify(label),
        candidate.base,
        candidate.numbering.name(),
        candidate.sign.name()
    )
}

/// Renders the candidate-record markdown body (pure; testable without the
/// filesystem). Reproduces [`crate::attack::solve::SOLVE_CLAIM_CEILING`] verbatim so no
/// record can make a stronger claim than the solve pipeline.
fn render_record(
    label: &str,
    seed: u64,
    candidate: &RagbabyCandidate,
) -> Result<String, fmt::Error> {
    use std::fmt::Write as _;
    let mut out = String::new();
    writeln!(out, "# Ragbaby candidate record: {label}")?;
    writeln!(out)?;
    writeln!(
        out,
        "Stable label (NO wall-clock): label={label} seed=0x{seed:016x} base={} numbering={} sign={}",
        candidate.base,
        candidate.numbering.name(),
        candidate.sign.label()
    )?;
    writeln!(out)?;
    writeln!(out, "## Verdict")?;
    writeln!(out)?;
    let verdict = if candidate.survives {
        "CANDIDATE SURVIVED ALL GATES (round-trip + matched-null + held-out) — logged as a HYPOTHESIS, NOT a decode"
    } else {
        "NO surviving candidate — decode remains blocked"
    };
    writeln!(out, "**{verdict}.**")?;
    writeln!(out)?;
    writeln!(out, "## Claim ceiling (absolute)")?;
    writeln!(out)?;
    writeln!(out, "{}", crate::attack::solve::SOLVE_CLAIM_CEILING)?;
    writeln!(
        out,
        "Nothing in this record is stronger. A clean honest negative is a SUCCESS."
    )?;
    writeln!(out)?;
    writeln!(out, "## Gates (never collapsed)")?;
    writeln!(out)?;
    writeln!(
        out,
        "Survival requires the MATCHED null (the same annealed keyed-alphabet search \
         rerun on a Fisher-Yates shuffle of the ciphertext LETTER stream, holding the \
         key-number sequence N_i fixed) plus round-trip and held-out. The matched \
         null shares the search's degrees of freedom, so it polices SEARCH \
         OVERFITTING. The random-keyed-alphabet null is reported as a DIAGNOSTIC only \
         (Ragbaby has no key-independence leak for it to police)."
    )?;
    writeln!(out)?;
    writeln!(out, "- round_trip_ok: {}", candidate.round_trip_ok)?;
    writeln!(out, "- best_score (mean): {:.6}", candidate.best_score)?;
    writeln!(
        out,
        "- matched_mean: {:.6}  matched_std: {:.6}  matched_z: {:.4}",
        candidate.matched_mean, candidate.matched_std, candidate.matched_z
    )?;
    writeln!(
        out,
        "- beats_matched_null [SURVIVAL GATE: overfitting] (z >= {Z_THRESHOLD} AND margin >= {MIN_NAT_MARGIN}): {}",
        candidate.beats_matched_null
    )?;
    writeln!(
        out,
        "- null_mean: {:.6}  null_std: {:.6}  z: {:.4}  beats_null [DIAGNOSTIC]: {}",
        candidate.null_mean, candidate.null_std, candidate.z, candidate.beats_null
    )?;
    writeln!(
        out,
        "- heldout_score: {:.6}  matched_heldout_mean: {:.6}  heldout_ok (>): {}",
        candidate.heldout_score, candidate.matched_heldout_mean, candidate.heldout_ok
    )?;
    writeln!(out)?;
    writeln!(out, "## Recovered keyed alphabet (real letter indices)")?;
    writeln!(out)?;
    writeln!(out, "{:?}", candidate.key)?;
    writeln!(out)?;
    writeln!(out, "## Decrypt (HYPOTHESIS, NOT a decode)")?;
    writeln!(out)?;
    writeln!(out, "{}", candidate.render_plaintext())?;
    Ok(out)
}

/// Writes a candidate record (a labelled HYPOTHESIS, never a decode) to `dir`,
/// creating the directory if needed. The filename is stable (label + base +
/// numbering + sign + seed; no wall clock), so re-running overwrites the prior
/// record. Returns the path written.
///
/// # Errors
/// Returns an [`io::Error`] if the directory cannot be created or the file cannot
/// be written.
pub fn write_ragbaby_record(
    dir: &Path,
    label: &str,
    seed: u64,
    candidate: &RagbabyCandidate,
) -> io::Result<PathBuf> {
    let path = dir.join(record_filename(label, candidate, seed));
    let body = render_record(label, seed, candidate)
        .map_err(|_error| io::Error::other("record formatting failed"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(&path, body)?;
    Ok(path)
}
