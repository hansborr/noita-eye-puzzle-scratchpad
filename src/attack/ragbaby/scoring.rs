use crate::attack::quadgram::{QuadgramError, QuadgramModel};
use crate::nulls::null::{SplitMix64, mix_seed};

use super::cipher::{Numbering, Sign, decrypt_into, encrypt_indices, keep_for_base};
use super::search::{RagbabySearch, RagbabySearchConfig, random_keyed_alphabet, search};
use super::{MIN_NAT_MARGIN, Z_THRESHOLD};

/// Deterministic tag mixed into the random-keyed-alphabet null seed so that null is
/// decorrelated from the search stream while staying reproducible.
const NULL_SEED_TAG: u64 = 0x0072_6167_6e75_6c00;

/// Deterministic tag mixed into the matched-null shuffle/search seeds (the
/// `SplitMix64` golden-ratio constant) so the matched null is decorrelated from
/// both the search and the random-keyed-alphabet null streams.
const MATCHED_NULL_SEED_TAG: u64 = 0x9e37_79b9_7f4a_7c15;

/// Fraction of positions (over the shorter length) where `a` and `b` agree
/// (`0.0` for empty input).
#[must_use]
pub fn char_accuracy(a: &[usize], b: &[usize]) -> f64 {
    let n = a.len().min(b.len());
    if n == 0 {
        return 0.0;
    }
    let matches = a.iter().zip(b).take(n).filter(|(x, y)| x == y).count();
    matches as f64 / n as f64
}

/// A prepared Ragbaby ciphertext for one `(base, numbering, sign)` hypothesis.
///
/// The `cipher` and `nums` streams come from [`prepare`](super::prepare) and must be the same
/// length; `numbering` is carried for the candidate record and the null seed tags.
#[derive(Clone, Copy, Debug)]
pub struct RagbabyProblem<'a> {
    /// Folded real-letter-index ciphertext stream.
    pub cipher: &'a [usize],
    /// Per-letter key numbers (reduced modulo `base`), same length as `cipher`.
    pub nums: &'a [usize],
    /// Alphabet base (24, 25, or 26).
    pub base: usize,
    /// Shift sign.
    pub sign: Sign,
    /// Key-numbering convention.
    pub numbering: Numbering,
}

impl RagbabyProblem<'_> {
    /// A stable per-hypothesis tag decorrelating the per-`(base, numbering, sign)`
    /// null streams.
    fn tag(&self) -> u64 {
        (self.base as u64).wrapping_mul(0x0100_0000) ^ self.numbering.tag() ^ self.sign.tag()
    }
}

/// One scored, gated keyed-alphabet hypothesis for a single
/// `(base, numbering, sign)`.
///
/// A surviving candidate is a HYPOTHESIS, never a confirmed decode.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the gate verdicts (round-trip, beats-matched-null, beats-null diagnostic, held-out, survives) are kept as separate fields and never collapsed, mirroring keystream.rs's never-collapse gate discipline"
)]
pub struct RagbabyCandidate {
    /// Alphabet base searched.
    pub base: usize,
    /// Numbering convention searched.
    pub numbering: Numbering,
    /// Shift sign searched.
    pub sign: Sign,
    /// Best keyed alphabet recovered (real-letter-index permutation).
    pub key: Vec<usize>,
    /// Best quadgram MEAN-log score of the recovered plaintext (gate scale).
    pub best_score: f64,
    /// Mean quadgram score of the random-keyed-alphabet null (DIAGNOSTIC).
    pub null_mean: f64,
    /// Standard deviation of the random-keyed-alphabet null (DIAGNOSTIC).
    pub null_std: f64,
    /// `(best_score - null_mean) / null_std` (or `0`); the diagnostic z-score.
    pub z: f64,
    /// Mean best score of the matched null (the same search rerun on a shuffled
    /// ciphertext letter stream with `N_i` held fixed). Drives the survival gate.
    pub matched_mean: f64,
    /// Standard deviation of the matched-null best scores.
    pub matched_std: f64,
    /// `(best_score - matched_mean) / matched_std` (or `0`); the survival z-score.
    pub matched_z: f64,
    /// Whether `encrypt(decrypt) == ciphertext` (always true; a sanity gate).
    pub round_trip_ok: bool,
    /// Quadgram score of the odd-indexed held-out fold of the best decrypt.
    pub heldout_score: f64,
    /// Mean held-out (odd-index) fold score across the matched-null reruns — the
    /// apples-to-apples baseline the candidate's `heldout_score` must beat.
    pub matched_heldout_mean: f64,
    /// Diagnostic: clears [`Z_THRESHOLD`]/[`MIN_NAT_MARGIN`] vs the random-keyed
    /// null. Not part of survival — Ragbaby has no key-independence leak.
    pub beats_null: bool,
    /// Survival gate: clears [`Z_THRESHOLD`]/[`MIN_NAT_MARGIN`] vs the matched null
    /// (and `matched_null_trials > 0`). Polices search overfitting.
    pub beats_matched_null: bool,
    /// Whether `heldout_score > matched_heldout_mean`. `false` when
    /// `matched_null_trials == 0`.
    pub heldout_ok: bool,
    /// `round_trip_ok && beats_matched_null && heldout_ok`.
    pub survives: bool,
    /// The best decryption (plaintext letter indices).
    pub decrypt: Vec<usize>,
}

impl RagbabyCandidate {
    /// Renders the best decryption as `A..` letters (`0 -> 'A'`); indices outside
    /// `0..26` render as `'?'`.
    #[must_use]
    pub fn render_plaintext(&self) -> String {
        self.decrypt
            .iter()
            .map(|&v| {
                if v < 26 {
                    (b'A' + v as u8) as char
                } else {
                    '?'
                }
            })
            .collect()
    }
}

/// Builds the random-keyed-alphabet null `(mean, std)`: scores decryptions of the
/// real ciphertext under random keyed alphabets (no search). A DIAGNOSTIC only.
fn random_key_null(
    problem: &RagbabyProblem,
    keep: &[usize],
    cfg: &RagbabySearchConfig,
    model: &QuadgramModel,
) -> (f64, f64) {
    if cfg.null_trials == 0 {
        return (0.0, 0.0);
    }
    let ctx = RagbabySearch {
        cipher: problem.cipher,
        nums: problem.nums,
        base: problem.base,
        sign: problem.sign.value(),
        keep,
        model,
    };
    let mut rng = SplitMix64::new(mix_seed(cfg.seed, NULL_SEED_TAG ^ problem.tag()));
    let mut inv = [0usize; 26];
    let mut out: Vec<usize> = Vec::with_capacity(problem.cipher.len());
    let mut scores: Vec<f64> = Vec::with_capacity(cfg.null_trials);
    for _trial in 0..cfg.null_trials {
        let key = random_keyed_alphabet(keep, &mut rng);
        decrypt_into(
            problem.cipher,
            problem.nums,
            &key,
            ctx.sign,
            problem.base,
            &mut inv,
            &mut out,
        );
        scores.push(model.score_indices(&out));
    }
    crate::attack::crack::mean_std(&scores)
}

/// Builds the matched null `(mean, std)` — the honest survival bar. Each trial
/// Fisher-Yates **shuffles** the ciphertext letter stream (holding `N_i` fixed, so
/// the search's degrees of freedom are identical) and reruns the IDENTICAL anneal,
/// recording the best decrypt's MEAN score. Returns `(0.0, 0.0)` when disabled.
/// Held-out fold of a decrypt: the odd-indexed letters scored as a stream.
///
/// This is only ever meaningful as a *relative* generalisation check — the
/// candidate's held-out fold is compared against the **matched null's** held-out
/// fold (apples-to-apples). Every-other-letter of English is NOT contiguous
/// English, so its absolute quadgram score is low; comparing it to the full-stream
/// mean (as an earlier version did) falsely fails even a perfect decode.
fn heldout_fold_score(decrypt: &[usize], model: &QuadgramModel) -> f64 {
    model.score_indices(&crate::nulls::heldout::odd_index_fold(decrypt))
}

/// Matched null: reruns the identical search on Fisher–Yates-shuffled cipher
/// letters (key-number sequence held fixed). Returns `(full_mean, full_std,
/// heldout_mean)` — the held-out mean is the baseline for the generalisation gate.
fn matched_null(
    problem: &RagbabyProblem,
    keep: &[usize],
    cfg: &RagbabySearchConfig,
    model: &QuadgramModel,
) -> (f64, f64, f64) {
    // The shared loop owns only the shuffle + aggregation; the seed math and the bare
    // search stay here (a fresh decrypt is allocated per trial — keystream instead
    // reuses a scratch buffer). `matched_null_trials == 0` yields zeroed stats
    // (== the old early-return `(0.0, 0.0, 0.0)`).
    let stats = crate::attack::crack::matched_null_loop(
        problem.cipher,
        cfg.matched_null_trials,
        |trial| cfg.seed ^ MATCHED_NULL_SEED_TAG ^ problem.tag() ^ (trial as u64),
        |shuffled, trial| {
            let search_seed = mix_seed(
                cfg.seed,
                MATCHED_NULL_SEED_TAG ^ problem.tag() ^ ((trial as u64) << 32),
            );
            let trial_cfg = RagbabySearchConfig {
                seed: search_seed,
                ..*cfg
            };
            let ctx = RagbabySearch {
                cipher: shuffled,
                nums: problem.nums,
                base: problem.base,
                sign: problem.sign.value(),
                keep,
                model,
            };
            let (key, _sum) = search(&ctx, &trial_cfg);
            let decrypt = ctx.decrypt(&key);
            (
                model.score_indices(&decrypt),
                heldout_fold_score(&decrypt, model),
            )
        },
    );
    (stats.full_mean, stats.full_std, stats.heldout_mean)
}

/// Cracks one prepared `(base, numbering, sign)` problem against a prebuilt
/// quadgram `model`, returning a fully-gated [`RagbabyCandidate`].
///
/// Reuse this entry point across many hypotheses so the (expensive) quadgram model
/// is built once. Deterministic in `cfg.seed`.
#[must_use]
pub fn crack_with_model(
    problem: &RagbabyProblem,
    cfg: &RagbabySearchConfig,
    model: &QuadgramModel,
) -> RagbabyCandidate {
    let keep = keep_for_base(problem.base);
    let ctx = RagbabySearch {
        cipher: problem.cipher,
        nums: problem.nums,
        base: problem.base,
        sign: problem.sign.value(),
        keep: &keep,
        model,
    };
    let (key, _best_sum) = search(&ctx, cfg);
    let decrypt = ctx.decrypt(&key);
    let best_score = model.score_indices(&decrypt);
    let heldout_score = heldout_fold_score(&decrypt, model);

    let (null_mean, null_std) = random_key_null(problem, &keep, cfg, model);
    let random = crate::attack::crack::NullComparison::new(best_score, null_mean, null_std);

    let (matched_mean, matched_std, matched_heldout_mean) =
        matched_null(problem, &keep, cfg, model);
    let matched = crate::attack::crack::NullComparison::new(best_score, matched_mean, matched_std);

    let round_trip_ok =
        encrypt_indices(&decrypt, problem.nums, &key, ctx.sign, problem.base) == problem.cipher;
    // DIAGNOSTIC only (Ragbaby has no key-independence leak): NO trial guard
    // (`enabled = true`), matching the pre-consolidation boolean exactly.
    let beats_null = random.clears(true, Z_THRESHOLD, MIN_NAT_MARGIN);
    let beats_matched_null =
        matched.clears(cfg.matched_null_trials > 0, Z_THRESHOLD, MIN_NAT_MARGIN);
    // Generalisation gate: the candidate's held-out (odd-index) fold must read more
    // English than the matched null's held-out fold (apples-to-apples). Comparing to
    // the full-stream `matched_mean` instead would falsely fail a true decode, since
    // every-other-letter of English is not itself contiguous English.
    let heldout_ok = cfg.matched_null_trials > 0 && heldout_score > matched_heldout_mean;
    // Survival is the matched null (overfitting) plus the round-trip and held-out
    // checks; the random-keyed-alphabet null is a diagnostic, since Ragbaby has no
    // key-independence leak for it to police.
    let survives = round_trip_ok && beats_matched_null && heldout_ok;

    RagbabyCandidate {
        base: problem.base,
        numbering: problem.numbering,
        sign: problem.sign,
        key,
        best_score,
        null_mean,
        null_std,
        z: random.z,
        matched_mean,
        matched_std,
        matched_z: matched.z,
        round_trip_ok,
        heldout_score,
        matched_heldout_mean,
        beats_null,
        beats_matched_null,
        heldout_ok,
        survives,
        decrypt,
    }
}

/// Cracks one prepared problem, building the English quadgram model internally.
///
/// Prefer [`crack_with_model`] across many hypotheses (build the model once).
///
/// # Errors
/// Returns [`QuadgramError`] if the bundled English quadgram model cannot be built
/// (it should not be in a correct build).
pub fn crack(
    problem: &RagbabyProblem,
    cfg: &RagbabySearchConfig,
) -> Result<RagbabyCandidate, QuadgramError> {
    let model = QuadgramModel::english()?;
    Ok(crack_with_model(problem, cfg, &model))
}

/// Runs only the optimizer (no nulls) and returns the best decryption (plaintext
/// letter indices) for a prepared problem. Used by the planted-recovery control.
#[must_use]
pub fn best_decryption(
    problem: &RagbabyProblem,
    cfg: &RagbabySearchConfig,
    model: &QuadgramModel,
) -> Vec<usize> {
    let keep = keep_for_base(problem.base);
    let ctx = RagbabySearch {
        cipher: problem.cipher,
        nums: problem.nums,
        base: problem.base,
        sign: problem.sign.value(),
        keep: &keep,
        model,
    };
    let (key, _sum) = search(&ctx, cfg);
    ctx.decrypt(&key)
}
