//! Bigram-scored injective symbol-to-letter substitution search.

use crate::attack::language::LanguageModel;
use crate::nulls::null::{SplitMix64, fisher_yates, random_index_below};

use super::BigramError;

/// Shortest token stream searched by the substitution annealer.
pub const MIN_TOKENS: usize = 8;

const SA_TEMP_PER_SYMBOL: f64 = 0.25;
const SA_MIN_START_TEMP: f64 = 6.0;
const SA_END_TEMP: f64 = 0.08;

/// The best substitution found for one token stream.
#[derive(Clone, Debug, PartialEq)]
pub struct BigramSubResult {
    /// Best summed bigram log likelihood.
    pub best_sum: f64,
    /// Best mean bigram log likelihood.
    pub best_mean: f64,
    /// Symbol-to-language-alphabet index map.
    pub mapping: Vec<usize>,
    /// Rendered best-scoring candidate text.
    pub text: String,
    /// Whether the stream was too short or too alphabet-rich to search.
    pub skipped: bool,
}

impl BigramSubResult {
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

/// Anneals an injective token-symbol to language-letter map using the
/// [`LanguageModel`] bigram mean log likelihood as the objective.
///
/// Symbols must be dense ids in `0..n_alphabet`. The search keeps a full
/// permutation of the model alphabet so unused letters can enter the mapped
/// prefix by swaps. Deterministic in `seed`.
///
/// # Errors
/// Returns [`BigramError`] if a random draw or language-model score fails.
pub fn substitution_search(
    symbols: &[usize],
    n_alphabet: usize,
    model: &LanguageModel,
    restarts: usize,
    iters: usize,
    seed: u64,
) -> Result<BigramSubResult, BigramError> {
    let letter_count = model.alphabet().len();
    if n_alphabet > letter_count || symbols.len() < MIN_TOKENS {
        return Ok(BigramSubResult::skipped());
    }

    let mut rng = SplitMix64::new(seed);
    let mut scratch = vec![0usize; symbols.len()];
    let mut best_sum = f64::NEG_INFINITY;
    let mut best_perm: Vec<usize> = (0..letter_count).collect();
    let start_temp = (SA_TEMP_PER_SYMBOL * symbols.len() as f64).max(SA_MIN_START_TEMP);
    let cooling = cooling_factor(iters, start_temp);

    for _restart in 0..restarts.max(1) {
        let mut perm: Vec<usize> = (0..letter_count).collect();
        fisher_yates(&mut perm, &mut rng)?;
        let mut current = score_perm(model, symbols, &perm, &mut scratch)?;
        let mut restart_best = current;
        let mut restart_best_perm = perm.clone();
        let mut temperature = start_temp;

        for _proposal in 0..iters {
            let i = random_index_below(n_alphabet, &mut rng)?;
            let j = random_index_below(letter_count, &mut rng)?;
            if i == j {
                temperature *= cooling;
                continue;
            }
            perm.swap(i, j);
            let candidate = score_perm(model, symbols, &perm, &mut scratch)?;
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
    let score = model.score_indices(&letters)?;
    let text = letters
        .iter()
        .filter_map(|&letter| model.alphabet().symbol(letter))
        .collect();

    Ok(BigramSubResult {
        best_sum,
        best_mean: score.bigram_mean_log_likelihood,
        mapping,
        text,
        skipped: false,
    })
}

fn cooling_factor(iters: usize, start_temp: f64) -> f64 {
    if iters <= 1 {
        return 1.0;
    }
    (SA_END_TEMP / start_temp).powf(1.0 / iters as f64)
}

fn unit_f64(rng: &mut SplitMix64) -> f64 {
    (rng.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
}

fn score_perm(
    model: &LanguageModel,
    symbols: &[usize],
    perm: &[usize],
    scratch: &mut [usize],
) -> Result<f64, BigramError> {
    for (slot, &symbol) in scratch.iter_mut().zip(symbols.iter()) {
        *slot = perm.get(symbol).copied().unwrap_or(0);
    }
    let score = model.score_indices(scratch)?;
    Ok(score.bigram_mean_log_likelihood * scratch.len() as f64)
}
