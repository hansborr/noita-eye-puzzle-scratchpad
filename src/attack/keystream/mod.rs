//! Polyalphabetic keystream cracker for the practice letter-puzzles.
//!
//! This module implements four keystream cipher families over `&[u8]` letter
//! indices (alphabet size `N`, default 26) and an annealed multi-restart key
//! search that maximizes the [`crate::attack::quadgram`] English model score of the
//! decryption. It is the letter-puzzle analogue of [`crate::attack::solve`]: it searches
//! and scores hypotheses, gates them against a matched null and a held-out fold,
//! and reports an explicit **honest negative** when nothing survives — which is
//! the expected outcome on the genuinely non-periodic-polyalphabetic practice
//! puzzles.
//!
//! # Cipher families
//!
//! Subtraction is computed as `(a + N - (b % N)) % N` to avoid `usize`
//! underflow. The primer/key is a `&[u8]` of length `L`, each value `< N`.
//!
//! - [`KeystreamFamily::Vigenere`]: `c_i = (p_i + k_{i mod L}) mod N`.
//! - [`KeystreamFamily::Beaufort`] (an involution): `c_i = (k_{i mod L} - p_i) mod N`.
//! - [`KeystreamFamily::PlaintextAutokey`]: keystream is `primer ++ plaintext`;
//!   `k_i = primer_i` for `i < L`, else `p_{i-L}`. Decryption is causal,
//!   recovering `p_{i-L}` left-to-right.
//! - [`KeystreamFamily::CiphertextAutokey`]: keystream is `primer ++ ciphertext`;
//!   `k_i = primer_i` for `i < L`, else `c_{i-L}`.
//!
//! # Survival gates: two complementary nulls
//!
//! Survival requires clearing **two** nulls, each policing a distinct failure
//! mode, plus a round-trip sanity check and a held-out fold.
//!
//! 1. **Matched null** (the gate this module's bug fix adds, mirroring the
//!    defence [`crate::attack::solve`] uses): rerun the IDENTICAL annealed search (same
//!    family, key length, restarts, iterations, temperature) on Fisher-Yates
//!    **shuffled** copies of the ciphertext. The shuffle preserves the exact
//!    letter multiset (unigram frequency held fixed) and destroys only
//!    higher-order structure, so the matched null measures *what the search
//!    itself extracts from noise*. The annealed key search has `L` free
//!    parameters and overfits short ciphertext: a weaker random-key null (which
//!    never pays for the search's optimization power) green-lights pure noise at
//!    high `L`; the matched null does not. A true cipher of real English decrypts
//!    to roughly `-10` nats while the matched null on shuffled ciphertext overfits
//!    only to roughly `-12`, so the true positive clears it but overfitting cannot.
//!
//! 2. **Random-key null** (retained, not demoted): score decryptions under random
//!    *keys* of the un-shuffled ciphertext. This is the only null that polices the
//!    [`KeystreamFamily::CiphertextAutokey`] **key-independence leak**
//!    (`p_i = c_i - c_{i-L}` for `i >= L`): on a long plaintext that decrypt is
//!    English *regardless of the key*, so a random key reads as English too and
//!    `best_score` cannot clear it. The matched null shuffles the ciphertext,
//!    which DESTROYS that leak, so it would (wrongly) promote ct-autokey on its
//!    own — only the random-key null keeps that honest.
//!
//! A candidate survives only when, against the matched null it clears the z-score
//! floor ([`Z_THRESHOLD`]) and the absolute nat floor ([`MIN_NAT_MARGIN`],
//! guarding tiny-`std` degeneracy) ([`beats_matched_null`]), against the
//! random-key null it clears the same pair ([`beats_null`]), AND a held-out fold
//! reads above the matched-null mean. Neither null alone is sufficient: the
//! matched null catches search overfitting, the random-key null catches the
//! key-independence leak.
//!
//! [`crate::attack::solve`] gates with `SEARCH_BEATS_NULL_MARGIN = 0.15` on the *bigram*
//! mean-log scale; that margin is far too lenient on the *quadgram* scale here
//! (English and random-key decryptions differ by roughly four nats), which is why
//! this module uses the z-score plus nat-floor pair above.
//!
//! [`beats_matched_null`]: KeystreamCandidate::beats_matched_null
//! [`beats_null`]: KeystreamCandidate::beats_null

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::attack::quadgram::{QuadgramError, QuadgramModel};

mod cipher;
mod search;
#[cfg(test)]
mod tests;

use cipher::decrypt_into;
pub use cipher::{KeystreamFamily, decrypt, encrypt};
use search::{matched_null, random_key_null, search};

/// Minimum z-score (best score above a null mean, in null standard deviations)
/// required to clear a null gate.
///
/// Applied to the matched null for [`KeystreamCandidate::beats_matched_null`] (the
/// survival gate) and to the random-key null for the
/// [`beats_null`](KeystreamCandidate::beats_null) diagnostic. Calibrated for the
/// quadgram mean-log scale, replacing [`crate::attack::solve::SEARCH_BEATS_NULL_MARGIN`]
/// (a bigram-scale bare margin that is far too lenient here).
pub const Z_THRESHOLD: f64 = 6.0;

/// Minimum absolute nat margin (`best_score - null_mean`) required to clear a null
/// gate, guarding the degenerate tiny-`std` case where a z-score alone would
/// explode. Applied to both [`KeystreamCandidate::beats_matched_null`] (survival)
/// and [`beats_null`](KeystreamCandidate::beats_null) (diagnostic).
pub const MIN_NAT_MARGIN: f64 = 1.0;

/// Default alphabet size used by [`KeystreamSearchConfig::default`].
pub const DEFAULT_ALPHABET_SIZE: usize = 26;

/// Default multi-restart count used by [`KeystreamSearchConfig::default`].
pub const DEFAULT_RESTARTS: usize = 12;

/// Default annealing iterations per restart used by
/// [`KeystreamSearchConfig::default`].
pub const DEFAULT_ITERATIONS: usize = 8_000;

/// Default annealing start temperature used by
/// [`KeystreamSearchConfig::default`].
pub const DEFAULT_ANNEAL_TEMP: f64 = 1.0;

/// Default deterministic seed used by [`KeystreamSearchConfig::default`].
pub const DEFAULT_SEED: u64 = 0x6b65_7973_7472_6d00;

/// Default random-key null-trial count used by
/// [`KeystreamSearchConfig::default`].
pub const DEFAULT_NULL_TRIALS: usize = 64;

/// Default matched-null trial count used by [`KeystreamSearchConfig::default`].
///
/// Mirrors [`crate::attack::solve::DEFAULT_NULL_TRIALS`]: each trial reruns the FULL
/// annealed search on a shuffled copy of the ciphertext, so this is the dominant
/// cost knob — keep it modest.
pub const DEFAULT_MATCHED_NULL_TRIALS: usize = 16;

/// Configuration for the annealed multi-restart key search.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KeystreamSearchConfig {
    /// Alphabet size `N` (clamped to at least `1`).
    pub alphabet_size: usize,
    /// Number of random restarts (each seeds a fresh random key).
    pub restarts: usize,
    /// Annealing iterations per restart.
    pub iterations: usize,
    /// Annealing start temperature; falls linearly to `0`. A value of `0`
    /// (or less) is a pure hill-climb (worsening moves always rejected).
    pub anneal_temp: f64,
    /// Deterministic PRNG seed for the entire search and both nulls.
    pub seed: u64,
    /// Number of random-key null trials used for the reported DIAGNOSTIC
    /// (`null_mean`/`null_std`/`z`/`beats_null`), no longer the survival gate.
    pub null_trials: usize,
    /// Number of matched-null trials: reruns of the FULL search on Fisher-Yates
    /// shuffled ciphertext. This is the survival gate
    /// ([`KeystreamCandidate::beats_matched_null`]); `0` disables it (the
    /// candidate can never survive).
    pub matched_null_trials: usize,
}

impl Default for KeystreamSearchConfig {
    fn default() -> Self {
        Self {
            alphabet_size: DEFAULT_ALPHABET_SIZE,
            restarts: DEFAULT_RESTARTS,
            iterations: DEFAULT_ITERATIONS,
            anneal_temp: DEFAULT_ANNEAL_TEMP,
            seed: DEFAULT_SEED,
            null_trials: DEFAULT_NULL_TRIALS,
            matched_null_trials: DEFAULT_MATCHED_NULL_TRIALS,
        }
    }
}

/// One scored, gated keystream hypothesis for a single `(family, key length)`.
///
/// A surviving candidate is a HYPOTHESIS, never a confirmed decode.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the gate verdicts (round-trip, beats-matched-null, beats-null diagnostic, held-out, survives) are kept as separate fields and never collapsed, mirroring solve.rs's never-collapse gate discipline"
)]
pub struct KeystreamCandidate {
    /// Cipher family searched.
    pub family: KeystreamFamily,
    /// Key (primer) length searched.
    pub key_len: usize,
    /// Best key recovered by the search.
    pub key: Vec<u8>,
    /// Best (highest) quadgram mean-log score found over all restarts.
    pub best_score: f64,
    /// Mean quadgram score of the random-key null (DIAGNOSTIC; not the gate).
    pub null_mean: f64,
    /// Standard deviation of the random-key null (DIAGNOSTIC).
    pub null_std: f64,
    /// `(best_score - null_mean) / null_std` (or `0` when `null_std == 0`);
    /// the random-key-null z-score (DIAGNOSTIC).
    pub z: f64,
    /// Mean best score of the matched null (the same search rerun on shuffled
    /// ciphertext). This is the honest "what the search extracts from noise"
    /// baseline and drives the survival gate.
    pub matched_mean: f64,
    /// Standard deviation of the matched-null best scores.
    pub matched_std: f64,
    /// `(best_score - matched_mean) / matched_std` (or `0` when
    /// `matched_std == 0`); the matched-null z-score.
    pub matched_z: f64,
    /// Whether `encrypt(decrypt(c, key), key) == c` (always true; a sanity gate).
    pub round_trip_ok: bool,
    /// Quadgram score of the odd-indexed held-out fold of the best decrypt.
    pub heldout_score: f64,
    /// Mean held-out (odd-index) fold score across the matched-null reruns — the
    /// apples-to-apples baseline the candidate's `heldout_score` must beat.
    /// Comparing `heldout_score` to the full-stream `matched_mean` instead (the old
    /// bug) falsely failed a true decode, since a fold of English is not contiguous
    /// English and so scores below the full stream while the null pays no such
    /// penalty. `0.0` when `matched_null_trials == 0`.
    pub matched_heldout_mean: f64,
    /// Survival gate (random-key null): whether the candidate clears
    /// [`Z_THRESHOLD`] and [`MIN_NAT_MARGIN`] against the random-key null. This is
    /// the only gate that polices the [`KeystreamFamily::CiphertextAutokey`]
    /// key-independence leak (the matched null shuffles the ciphertext and so
    /// cannot).
    pub beats_null: bool,
    /// Survival gate (matched null): whether the candidate clears [`Z_THRESHOLD`]
    /// and [`MIN_NAT_MARGIN`] against the MATCHED null (and
    /// `matched_null_trials > 0`). Polices search overfitting at high key length.
    pub beats_matched_null: bool,
    /// Whether `heldout_score > matched_heldout_mean` (the held-out fold reads above
    /// the matched null's held-out fold — apples-to-apples). `false` when
    /// `matched_null_trials == 0`.
    pub heldout_ok: bool,
    /// `round_trip_ok && beats_matched_null && beats_null && heldout_ok` — both
    /// nulls must be cleared (each polices a distinct failure mode).
    pub survives: bool,
    /// The best decryption (letter indices).
    pub decrypt: Vec<u8>,
}

impl KeystreamCandidate {
    /// Renders the best decryption as `A..` letters (`0 -> 'A'`); indices outside
    /// `0..26` render as `'?'`.
    #[must_use]
    pub fn render_plaintext(&self) -> String {
        self.decrypt
            .iter()
            .map(|&v| if v < 26 { (b'A' + v) as char } else { '?' })
            .collect()
    }
}

/// Cracks `ciphertext` for one `(family, key_len)` against a prebuilt quadgram
/// `model`, returning a fully-gated [`KeystreamCandidate`].
///
/// Reuse this entry point when cracking many `(family, key length)` pairs so the
/// (expensive) quadgram model is built once. Deterministic in `cfg.seed`.
#[must_use]
pub fn crack_with_model(
    ciphertext: &[u8],
    family: KeystreamFamily,
    key_len: usize,
    cfg: &KeystreamSearchConfig,
    model: &QuadgramModel,
) -> KeystreamCandidate {
    let n = cfg.alphabet_size.max(1);
    let l = key_len.max(1);
    let mut buffer: Vec<usize> = Vec::with_capacity(ciphertext.len());

    let (key, _search_best) = search(ciphertext, family, l, n, cfg, model);

    // Recompute the best decryption (the buffer was last used by the search) and
    // derive the score, decrypt, and held-out fold from it.
    decrypt_into(family, ciphertext, &key, n, &mut buffer);
    let best_score = model.score_indices(&buffer);
    let decrypt_indices: Vec<u8> = buffer.iter().map(|&v| v as u8).collect();
    let heldout_score = model.score_indices(&crate::nulls::heldout::odd_index_fold(&buffer));

    // Random-key null: a DIAGNOSTIC only (too weak to gate — it never pays for
    // the search's optimization power, so it green-lights overfitting at high L).
    let (null_mean, null_std) = random_key_null(ciphertext, family, l, n, cfg, model, &mut buffer);
    let margin = best_score - null_mean;
    let z = if null_std > 0.0 {
        margin / null_std
    } else {
        0.0
    };

    // Matched null: the survival bar (same search rerun on shuffled ciphertext).
    let (matched_mean, matched_std, matched_heldout_mean) =
        matched_null(ciphertext, family, l, n, cfg, model);
    let matched_margin = best_score - matched_mean;
    let matched_z = if matched_std > 0.0 {
        matched_margin / matched_std
    } else {
        0.0
    };

    let round_trip_ok = encrypt(family, &decrypt_indices, &key, n) == ciphertext;
    // Random-key null gate: the defense against the [`KeystreamFamily::CiphertextAutokey`]
    // KEY-INDEPENDENCE leak (`p_i = c_i - c_{i-L}` for `i >= L`). The matched null
    // shuffles the ciphertext, which DESTROYS that leak, so it cannot police it —
    // only the random-key null can (a random key reproduces the same key-independent
    // English tail, so `best_score` cannot clear it). For the keyed families a true
    // recovery clears this comfortably.
    let beats_null = z >= Z_THRESHOLD && margin >= MIN_NAT_MARGIN;
    // Matched-null gate: the defense against SEARCH OVERFITTING at high key length
    // (the false-positive bug this gate fixes). The annealed search's optimization
    // power inflates `best_score` on short ciphertext; the matched null pays for
    // exactly that power on the shuffled (structureless) multiset, so overfitting
    // cannot clear it. `matched_null_trials == 0` never silently passes.
    let beats_matched_null =
        cfg.matched_null_trials > 0 && matched_z >= Z_THRESHOLD && matched_margin >= MIN_NAT_MARGIN;
    // Held-out fold judged against the matched null's HELD-OUT fold (apples-to-apples).
    // Comparing to the full-stream `matched_mean` instead falsely failed a true decode,
    // since a fold of English is not contiguous English and so scores below the full
    // stream while the null pays no such penalty.
    let heldout_ok = cfg.matched_null_trials > 0 && heldout_score > matched_heldout_mean;
    // Survival requires clearing BOTH nulls: the matched null (overfitting) AND the
    // random-key null (the ct-autokey key-independence leak). A true keyed recovery
    // clears both; overfitting fails the matched null; the ct-autokey leak fails the
    // random-key null. Each null polices a distinct failure mode, so neither alone
    // is sufficient — the matched null is the NEW gate, not a replacement.
    let survives = round_trip_ok && beats_matched_null && beats_null && heldout_ok;

    KeystreamCandidate {
        family,
        key_len: l,
        key,
        best_score,
        null_mean,
        null_std,
        z,
        matched_mean,
        matched_std,
        matched_z,
        round_trip_ok,
        heldout_score,
        matched_heldout_mean,
        beats_null,
        beats_matched_null,
        heldout_ok,
        survives,
        decrypt: decrypt_indices,
    }
}

/// Cracks `ciphertext` for one `(family, key_len)`, building the English
/// quadgram model internally.
///
/// Prefer [`crack_with_model`] when cracking many pairs (build the model once).
///
/// # Errors
/// Returns [`QuadgramError`] if the bundled English quadgram model cannot be
/// built (it should not be in a correct build).
pub fn crack(
    ciphertext: &[u8],
    family: KeystreamFamily,
    key_len: usize,
    cfg: &KeystreamSearchConfig,
) -> Result<KeystreamCandidate, QuadgramError> {
    let model = QuadgramModel::english()?;
    Ok(crack_with_model(ciphertext, family, key_len, cfg, &model))
}

/// Normalizes a puzzle string to letter indices: ASCII letters are kept and
/// uppercased to `0..=25`; every other character (spaces, punctuation, the
/// `seven` puzzle's `#` markers, newlines) is dropped.
#[must_use]
pub fn normalize_puzzle(text: &str) -> Vec<u8> {
    text.chars()
        .filter(char::is_ascii_alphabetic)
        .map(|ch| ch.to_ascii_uppercase() as u8 - b'A')
        .collect()
}

/// The bundled practice letter-puzzles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PracticePuzzle {
    /// Practice puzzle `three`.
    Three,
    /// Practice puzzle `four`.
    Four,
    /// Practice puzzle `five` (has the gap-40 `UXECHTINIT` 10-gram repeat).
    Five,
    /// Practice puzzle `seven` (uses `#` markers, stripped on normalization).
    Seven,
}

/// Returns the raw bundled text for a practice puzzle (committed under
/// `research/data/practice-puzzles/`).
#[must_use]
pub fn practice_puzzle_text(puzzle: PracticePuzzle) -> &'static str {
    match puzzle {
        PracticePuzzle::Three => include_str!("../../../research/data/practice-puzzles/three"),
        PracticePuzzle::Four => include_str!("../../../research/data/practice-puzzles/four"),
        PracticePuzzle::Five => include_str!("../../../research/data/practice-puzzles/five"),
        PracticePuzzle::Seven => include_str!("../../../research/data/practice-puzzles/seven"),
    }
}

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
fn record_filename(label: &str, candidate: &KeystreamCandidate, seed: u64) -> String {
    format!(
        "keystream-{}-{}-l{}-seed-{seed:016x}.md",
        slugify(label),
        candidate.family.name(),
        candidate.key_len
    )
}

/// Renders the candidate-record markdown body (pure; testable without the
/// filesystem). Reproduces [`crate::attack::solve::SOLVE_CLAIM_CEILING`] verbatim so no
/// record can make a stronger claim than the solve pipeline.
fn render_record(
    label: &str,
    seed: u64,
    candidate: &KeystreamCandidate,
) -> Result<String, fmt::Error> {
    use std::fmt::Write as _;
    let mut out = String::new();
    writeln!(out, "# Keystream candidate record: {label}")?;
    writeln!(out)?;
    writeln!(
        out,
        "Stable label (NO wall-clock): label={label} seed=0x{seed:016x} family={} key-len={}",
        candidate.family.name(),
        candidate.key_len
    )?;
    writeln!(out)?;
    writeln!(out, "## Verdict")?;
    writeln!(out)?;
    let verdict = if candidate.survives {
        "CANDIDATE SURVIVED ALL GATES (round-trip + matched-null + random-key-null + held-out) — logged as a HYPOTHESIS, NOT a decode"
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
        "Survival requires BOTH nulls plus round-trip and held-out. The MATCHED \
         null (the same annealed search rerun on Fisher-Yates shuffled ciphertext, \
         holding the unigram multiset fixed and destroying higher-order structure) \
         polices SEARCH OVERFITTING. The RANDOM-KEY null (random keys on the \
         un-shuffled ciphertext) polices the ciphertext-autokey KEY-INDEPENDENCE \
         leak, which the matched null cannot see. Neither alone is sufficient."
    )?;
    writeln!(out)?;
    writeln!(out, "- round_trip_ok: {}", candidate.round_trip_ok)?;
    writeln!(out, "- best_score: {:.6}", candidate.best_score)?;
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
        "- null_mean: {:.6}  null_std: {:.6}  z: {:.4}",
        candidate.null_mean, candidate.null_std, candidate.z
    )?;
    writeln!(
        out,
        "- beats_null [SURVIVAL GATE: key-independence leak] (z >= {Z_THRESHOLD} AND margin >= {MIN_NAT_MARGIN}): {}",
        candidate.beats_null
    )?;
    writeln!(
        out,
        "- heldout_score: {:.6}  matched_heldout_mean: {:.6}  heldout_ok (> matched_heldout_mean): {}",
        candidate.heldout_score, candidate.matched_heldout_mean, candidate.heldout_ok
    )?;
    writeln!(out)?;
    writeln!(out, "## Recovered key (letter indices)")?;
    writeln!(out)?;
    writeln!(out, "{:?}", candidate.key)?;
    writeln!(out)?;
    writeln!(out, "## Decrypt (HYPOTHESIS, NOT a decode)")?;
    writeln!(out)?;
    writeln!(out, "{}", candidate.render_plaintext())?;
    Ok(out)
}

/// Writes a candidate record (a labelled HYPOTHESIS, never a decode) to `dir`,
/// creating the directory if needed. The filename is stable (label + family +
/// key length + seed; no wall clock), so re-running overwrites the prior record.
///
/// Returns the path written.
///
/// # Errors
/// Returns an [`io::Error`] if the directory cannot be created or the file cannot
/// be written.
pub fn write_keystream_record(
    dir: &Path,
    label: &str,
    seed: u64,
    candidate: &KeystreamCandidate,
) -> io::Result<PathBuf> {
    let path = dir.join(record_filename(label, candidate, seed));
    let body = render_record(label, seed, candidate)
        .map_err(|_error| io::Error::other("record formatting failed"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(&path, body)?;
    Ok(path)
}
