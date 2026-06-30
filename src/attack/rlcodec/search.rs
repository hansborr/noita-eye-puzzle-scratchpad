//! Injective symbol→letter substitution search (hill-climb with random restarts),
//! scored by the English quadgram model.

use crate::attack::quadgram::QuadgramModel;
use crate::nulls::null::{SplitMix64, fisher_yates, random_index_below};

use super::RlError;

/// Size of the English letter alphabet the symbols map into.
const LETTERS: usize = 26;
/// Shortest decoded stream the search will attempt (a substitution on fewer
/// letters is dominated by overfitting, so it is reported as skipped).
pub const MIN_LETTERS: usize = 8;
/// Simulated-annealing start temperature **per scored window**, in the
/// summed-log-prob (nats) units of [`QuadgramModel::score_indices_sum`]. A single
/// letter swap perturbs every window touching the swapped letters, so the
/// swap-delta scale grows with the stream length; tying the start temperature to
/// the window count keeps the acceptance rate sane on both short and long streams
/// (a fixed start temperature freezes long streams prematurely into a local
/// optimum). Calibrated so the long planted control converges reliably.
const SA_TEMP_PER_WINDOW: f64 = 0.45;
/// Floor on the start temperature so very short streams still anneal.
const SA_MIN_START_TEMP: f64 = 8.0;
/// Simulated-annealing end temperature (geometric cooling target).
const SA_END_TEMP: f64 = 0.20;

/// The best substitution the search found for one symbol stream.
#[derive(Clone, Debug, PartialEq)]
pub struct SubResult {
    /// Best summed quadgram log-probability (the search objective).
    pub best_sum: f64,
    /// Best mean quadgram log-probability (length-comparable, the report metric).
    pub best_mean: f64,
    /// Symbol→letter index map (`0..26`) achieving the best score; empty when
    /// skipped.
    pub mapping: Vec<usize>,
    /// The rendered best-scoring plaintext; empty when skipped.
    pub text: String,
    /// `true` when the stream was too short or its alphabet exceeded 26 letters,
    /// so no search was run.
    pub skipped: bool,
}

impl SubResult {
    /// The sentinel returned when the stream cannot be substitution-searched.
    fn skipped() -> Self {
        Self {
            best_sum: f64::NEG_INFINITY,
            best_mean: f64::NEG_INFINITY,
            mapping: Vec::new(),
            text: String::new(),
            skipped: true,
        }
    }
}

/// Anneals an injective symbol→letter map maximising the English quadgram score
/// of the rendered plaintext.
///
/// Symbols are dense ids in `0..n_alphabet`. A full `26`-letter permutation is
/// maintained so unused letters can rotate in via transposition proposals; the
/// objective is [`QuadgramModel::score_indices_sum`] (well-scaled deltas). Each
/// restart runs a simulated anneal with geometric cooling from a length-scaled
/// start temperature down to `SA_END_TEMP`, tracking the best permutation it
/// ever visits; the best over all restarts is returned. Annealing (rather than
/// greedy hill-climb) is what
/// makes the search converge reliably on the harder large-alphabet streams, so
/// the planted positive control fires deterministically at a modest budget. The
/// reported `best_mean` is the length-comparable mean. Deterministic in `seed`.
///
/// When `n_alphabet > 26` (cannot inject into the letter alphabet) or
/// `symbols.len() < MIN_LETTERS` (too little text to constrain a substitution),
/// a skipped sentinel is returned instead.
///
/// # Errors
/// Returns [`RlError::Random`] if an in-crate index draw rejects its bound
/// (unreachable for the bounds used here).
pub fn substitution_search(
    symbols: &[usize],
    n_alphabet: usize,
    model: &QuadgramModel,
    restarts: usize,
    iters: usize,
    seed: u64,
) -> Result<SubResult, RlError> {
    if n_alphabet > LETTERS || symbols.len() < MIN_LETTERS {
        return Ok(SubResult::skipped());
    }

    let mut rng = SplitMix64::new(seed);
    let mut scratch = vec![0usize; symbols.len()];
    let mut best_sum = f64::NEG_INFINITY;
    let mut best_perm: Vec<usize> = (0..LETTERS).collect();
    let window_count = symbols.len().saturating_sub(3);
    let start_temp = (SA_TEMP_PER_WINDOW * window_count as f64).max(SA_MIN_START_TEMP);
    let cooling = cooling_factor(iters, start_temp);

    for _restart in 0..restarts.max(1) {
        let mut perm: Vec<usize> = (0..LETTERS).collect();
        fisher_yates(&mut perm, &mut rng)?;
        let mut current = score_perm(model, symbols, &perm, &mut scratch);
        let mut restart_best = current;
        let mut restart_best_perm = perm.clone();
        let mut temperature = start_temp;
        for _proposal in 0..iters {
            let i = random_index_below(LETTERS, &mut rng)?;
            let j = random_index_below(LETTERS, &mut rng)?;
            if i == j {
                temperature *= cooling;
                continue;
            }
            perm.swap(i, j);
            let candidate = score_perm(model, symbols, &perm, &mut scratch);
            let delta = candidate - current;
            if delta >= 0.0
                || unit_f64(&mut rng) < (delta / temperature.max(f64::MIN_POSITIVE)).exp()
            {
                current = candidate;
                if current > restart_best {
                    restart_best = current;
                    restart_best_perm.clone_from(&perm);
                }
            } else {
                perm.swap(i, j);
            }
            temperature *= cooling;
        }
        if restart_best > best_sum {
            best_sum = restart_best;
            best_perm.clone_from(&restart_best_perm);
        }
    }

    let mapping: Vec<usize> = (0..n_alphabet)
        .map(|symbol| best_perm.get(symbol).copied().unwrap_or(0))
        .collect();
    let letters: Vec<usize> = symbols
        .iter()
        .map(|&symbol| best_perm.get(symbol).copied().unwrap_or(0))
        .collect();
    let best_mean = model.score_indices(&letters);
    let text = letters
        .iter()
        .map(|&letter| char::from(b'A'.saturating_add(u8::try_from(letter).unwrap_or(0))))
        .collect();

    Ok(SubResult {
        best_sum,
        best_mean,
        mapping,
        text,
        skipped: false,
    })
}

/// Per-step geometric cooling factor taking the temperature from `start_temp`
/// (the length-scaled start) to `SA_END_TEMP` over `iters` steps.
fn cooling_factor(iters: usize, start_temp: f64) -> f64 {
    if iters <= 1 {
        return 1.0;
    }
    (SA_END_TEMP / start_temp).powf(1.0 / iters as f64)
}

/// Draws a uniform `[0, 1)` double from the 53 high bits of one PRNG word.
fn unit_f64(rng: &mut SplitMix64) -> f64 {
    (rng.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
}

/// Scores `symbols` under `perm` (symbol→letter), reusing `scratch` to avoid
/// per-proposal allocation.
fn score_perm(
    model: &QuadgramModel,
    symbols: &[usize],
    perm: &[usize],
    scratch: &mut [usize],
) -> f64 {
    for (slot, &symbol) in scratch.iter_mut().zip(symbols.iter()) {
        *slot = perm.get(symbol).copied().unwrap_or(0);
    }
    model.score_indices_sum(scratch)
}
