//! The speculative / hypothesis cleartext layer (kill gate 3) — reached only if both
//! structural gates passed.
//!
//! The symbol->letter mapping here is a hypothesis, never recovered: an explicitly-
//! arbitrary affine projection scored under the Finnish and English models behind a
//! matched null. This is never primary evidence; the implied plaintext is logged
//! verbatim for human review regardless of the verdict.

use super::super::{
    EYE_READING_ALPHABET_SIZE, EyesAttackConfig, GakAttackError, LanguageModel,
    SpeculativeCleartext, SplitMix64, TrigramValue, language, mix_seed, random_index_below,
};

/// Runs the speculative cleartext-plausibility gate (kill gate 3) — only reached if
/// both structural gates passed (the expected case is that this is never run).
///
/// The symbol→letter mapping here is a hypothesis, never recovered: the
/// reading-layer symbols are mapped onto the language alphabet by a fixed,
/// explicitly-arbitrary affine projection `value*stride % alphabet_len`, the
/// implied plaintext is scored under the Finnish and English models (Finnish
/// weighted highly — Noita is a Finnish game), and the scores are compared
/// against a matched null drawn from the same affine family (random coprime
/// stride + offset), so the single real stride sits at a well-defined percentile
/// within one exchangeable family rather than against a different-shape draw.
/// This is never primary evidence; the implied plaintext is logged verbatim for
/// human review regardless of the verdict.
///
/// # Errors
/// Returns [`GakAttackError::Language`] if a language model cannot be built.
pub(super) fn eyes_speculative_cleartext(
    message_values: &[Vec<TrigramValue>],
    config: &EyesAttackConfig,
) -> Result<SpeculativeCleartext, GakAttackError> {
    let finnish = language::finnish_model()?;
    let english = language::english_model()?;
    let alphabet_len = finnish.alphabet().len().max(1);

    // Hypothesized (arbitrary) symbol→letter mapping: a fixed modular projection of
    // the reading-layer value onto the language alphabet. This is not recovered and
    // is labelled a hypothesis everywhere.
    let mapping = eyes_hypothesis_mapping(alphabet_len, config.seed);
    let indices: Vec<usize> = message_values
        .iter()
        .flatten()
        .map(|value| mapping.get(usize::from(value.get())).copied().unwrap_or(0))
        .collect();

    let implied_plaintext = render_implied_plaintext(&indices, &finnish);
    let finnish_score = finnish
        .score_indices(&indices)
        .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);
    let english_score = english
        .score_indices(&indices)
        .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);

    // Matched null: draw other mappings from the same affine family (random
    // coprime stride + offset) and re-score. The implied plaintext only "beats"
    // the null if it exceeds the affine-family mean — and even then it is a
    // hypothesis.
    let (finnish_null_mean, english_null_mean) =
        eyes_mapping_null(message_values, alphabet_len, config, &finnish, &english);

    Ok(SpeculativeCleartext {
        implied_plaintext,
        finnish_score,
        english_score,
        finnish_null_mean,
        english_null_mean,
        beats_finnish_null: finnish_score > finnish_null_mean,
        beats_english_null: english_score > english_null_mean,
    })
}

/// Builds the hypothesized (arbitrary, never-recovered) symbol→letter mapping for
/// the speculative gate: a fixed modular projection of each reading-layer value onto
/// the language alphabet. Labelled a hypothesis everywhere it is used.
fn eyes_hypothesis_mapping(alphabet_len: usize, seed: u64) -> Vec<usize> {
    let stride = 1 + (seed as usize % alphabet_len.max(1));
    (0..EYE_READING_ALPHABET_SIZE)
        .map(|value| (value.wrapping_mul(stride)) % alphabet_len)
        .collect()
}

/// Draws one `(stride, offset)` pair from the affine family used by
/// [`eyes_hypothesis_mapping`]: a stride coprime to `len` (so the map is a
/// bijection on `0..len`) and a uniform offset in `0..len`. Returns `None` if an
/// index draw fails (unreachable for `len >= 1` on 64-bit targets).
fn draw_affine_stride_offset(len: usize, rng: &mut SplitMix64) -> Option<(usize, usize)> {
    // Rejection-sample a coprime stride in 1..=len, mirroring the real mapping's
    // `1 + (seed % len)` range. `len` is coprime to itself only when `len == 1`,
    // and `stride == 1` is always coprime, so this loop always terminates.
    let stride = loop {
        let stride = random_index_below(len, rng).ok()? + 1;
        if gcd(stride, len) == 1 {
            break stride;
        }
    };
    let offset = random_index_below(len, rng).ok()?;
    Some((stride, offset))
}

/// Greatest common divisor of two non-negative integers (Euclid's algorithm).
fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

/// Renders the implied plaintext string under a hypothesized mapping (for verbatim
/// logging). Each index becomes its alphabet symbol; out-of-range indices become `?`.
fn render_implied_plaintext(indices: &[usize], model: &LanguageModel) -> String {
    let mut rendered = String::with_capacity(indices.len());
    for &index in indices {
        match model.alphabet().symbol(index) {
            Some(symbol) => rendered.push(symbol),
            None => rendered.push('?'),
        }
    }
    rendered
}

/// Matched null for the speculative cleartext gate: mean Finnish/English bigram
/// scores over mappings drawn from the same affine family as the real hypothesis
/// (see [`eyes_hypothesis_mapping`]). Each trial draws a random stride coprime to
/// `alphabet_len` and a random offset and builds `full[value] = (value*a + b) %
/// alphabet_len`, so the single real stride sits at a well-defined percentile of
/// one exchangeable family rather than against a different-shape (random
/// relabeling) draw.
fn eyes_mapping_null(
    message_values: &[Vec<TrigramValue>],
    alphabet_len: usize,
    config: &EyesAttackConfig,
    finnish: &LanguageModel,
    english: &LanguageModel,
) -> (f64, f64) {
    let trials = config.trials.clamp(1, 256);
    let mut finnish_sum = 0.0f64;
    let mut english_sum = 0.0f64;
    let mut counted = 0usize;
    for trial in 0..trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            0x6d61_705f_6e75_6c6c ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        // Draw this trial's mapping from the same affine family as the real
        // hypothesis: a stride `a` coprime to `alphabet_len` and an offset `b`.
        let len = alphabet_len.max(1);
        let Some((a, b)) = draw_affine_stride_offset(len, &mut rng) else {
            continue;
        };
        let full: Vec<usize> = (0..EYE_READING_ALPHABET_SIZE)
            .map(|value| (value.wrapping_mul(a).wrapping_add(b)) % len)
            .collect();
        let indices: Vec<usize> = message_values
            .iter()
            .flatten()
            .map(|value| full.get(usize::from(value.get())).copied().unwrap_or(0))
            .collect();
        let f = finnish
            .score_indices(&indices)
            .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);
        let e = english
            .score_indices(&indices)
            .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);
        if f.is_finite() && e.is_finite() {
            finnish_sum += f;
            english_sum += e;
            counted = counted.saturating_add(1);
        }
    }
    if counted == 0 {
        (f64::NEG_INFINITY, f64::NEG_INFINITY)
    } else {
        (finnish_sum / counted as f64, english_sum / counted as f64)
    }
}
