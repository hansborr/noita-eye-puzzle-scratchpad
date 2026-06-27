use super::search::search_cipher;
use super::{
    CipherAttackConfig, CipherAttackError, CipherFamily, LanguageKind, MappingKind,
    POSITIVE_CONTROL_CAESAR_SHIFT, POSITIVE_CONTROL_MIN_MARGIN, POSITIVE_CONTROL_NULL_TRIALS,
    POSITIVE_CONTROL_TEXT, POSITIVE_CONTROL_VIGENERE_SHIFTS, PlantRecovery, PositiveControlReport,
    ScoreNull, ScoringPlan,
};
use crate::attack::language::english_model;
use crate::ciphers::{
    CaesarKey, CipherError, EYE_READING_ALPHABET_SIZE, VigenereKey, caesar_encrypt,
    vigenere_encrypt,
};
use crate::core::glyph::Glyph;
use crate::nulls::null::{SplitMix64, fisher_yates, mix_seed, random_index_below};

pub(super) fn summarize_null(real_score: f64, samples: &[f64]) -> ScoreNull {
    let trials = samples.len();
    let mean = if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<f64>() / trials as f64
    };
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let max = sorted.last().copied().unwrap_or(0.0);
    let q95 = quantile_from_sorted(&sorted, 95, 100);
    let empirical_p_count = samples.iter().filter(|&&score| score >= real_score).count();
    ScoreNull {
        trials,
        mean,
        q95,
        max,
        empirical_p_count,
        empirical_p: if trials == 0 {
            0.0
        } else {
            empirical_p_count as f64 / trials as f64
        },
    }
}

fn quantile_from_sorted(sorted: &[f64], numerator: usize, denominator: usize) -> f64 {
    let Some(last_index) = sorted.len().checked_sub(1) else {
        return 0.0;
    };
    let rank = last_index.saturating_mul(numerator) / denominator;
    sorted.get(rank).copied().unwrap_or(0.0)
}

pub(super) fn vigenere_key_space(
    alphabet_size: usize,
    max_period: usize,
) -> Result<usize, CipherAttackError> {
    if max_period == 0 {
        return Err(CipherAttackError::ZeroVigenereMaxPeriod);
    }
    let mut total = 0usize;
    let mut period_space = 1usize;
    for _period in 1..=max_period {
        period_space = period_space
            .checked_mul(alphabet_size)
            .ok_or(CipherAttackError::RandomBoundTooLarge { bound: usize::MAX })?;
        total = total
            .checked_add(period_space)
            .ok_or(CipherAttackError::RandomBoundTooLarge { bound: usize::MAX })?;
    }
    Ok(total)
}

pub(super) fn vigenere_shifts_from_ordinal(
    ordinal: usize,
    alphabet_size: usize,
    max_period: usize,
) -> Result<Vec<usize>, CipherAttackError> {
    let mut remaining = ordinal;
    let mut period_space = 1usize;
    for period in 1..=max_period {
        period_space = period_space
            .checked_mul(alphabet_size)
            .ok_or(CipherAttackError::RandomBoundTooLarge { bound: usize::MAX })?;
        if remaining < period_space {
            return Ok(shifts_for_period(remaining, period, alphabet_size));
        }
        remaining -= period_space;
    }
    Err(CipherAttackError::RandomBoundTooLarge { bound: ordinal })
}

fn shifts_for_period(mut ordinal: usize, period: usize, alphabet_size: usize) -> Vec<usize> {
    let mut shifts = Vec::with_capacity(period);
    for _position in 0..period {
        shifts.push(ordinal % alphabet_size);
        ordinal /= alphabet_size;
    }
    shifts
}

pub(super) fn vigenere_key_space_label(max_period: usize, total: usize) -> String {
    format!("sum 83^p for p=1..={max_period} ({total} keys)")
}

pub(super) fn vigenere_note(exhaustive: bool, candidates: usize) -> String {
    if exhaustive {
        format!("brute-forced all {candidates} short-period Vigenere keys")
    } else {
        format!("sampled {candidates} short-period Vigenere keys with SplitMix64")
    }
}

pub(super) fn caesar_key_label(shift: usize) -> String {
    format!("shift={shift}")
}

pub(super) fn vigenere_key_label(shifts: &[usize]) -> String {
    let values = shifts
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("period={} shifts={values}", shifts.len())
}

pub(super) fn shuffled_messages(
    messages: &[Vec<Glyph>],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<Glyph>>, CipherAttackError> {
    let mut shuffled = Vec::with_capacity(messages.len());
    for message in messages {
        let mut local = message.clone();
        fisher_yates(&mut local, rng)?;
        shuffled.push(local);
    }
    Ok(shuffled)
}

pub(super) fn random_permutation(
    alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, CipherAttackError> {
    let mut values = (0..alphabet_size).collect::<Vec<_>>();
    fisher_yates(&mut values, rng)?;
    Ok(values)
}

pub(super) fn random_distinct_control(
    control_a: usize,
    rng: &mut SplitMix64,
) -> Result<usize, CipherAttackError> {
    loop {
        let control_b = random_index_below(EYE_READING_ALPHABET_SIZE, rng)?;
        if control_b != control_a {
            return Ok(control_b);
        }
    }
}

pub(super) fn format_prefix(values: &[usize], limit: usize) -> String {
    let mut parts = values
        .iter()
        .take(limit)
        .map(usize::to_string)
        .collect::<Vec<_>>();
    if values.len() > limit {
        parts.push("...".to_owned());
    }
    format!("[{}]", parts.join(","))
}

pub(super) fn run_positive_controls(seed: u64) -> Result<PositiveControlReport, CipherAttackError> {
    let plaintext = positive_control_plaintext()?;
    let plans = vec![english_modulo_plan()?];
    let control_config = CipherAttackConfig {
        seed: mix_seed(seed, 0x706f_7369_7469_7665),
        samples: 10_000,
        null_trials: POSITIVE_CONTROL_NULL_TRIALS,
        vigenere_max_period: POSITIVE_CONTROL_VIGENERE_SHIFTS.len(),
    };

    let caesar_key = CaesarKey::new(EYE_READING_ALPHABET_SIZE, POSITIVE_CONTROL_CAESAR_SHIFT)?;
    let caesar_ciphertext =
        encrypt_messages(&plaintext, |message| caesar_encrypt(message, &caesar_key))?;
    let caesar = recover_plant(
        CipherFamily::Caesar,
        control_config,
        &caesar_ciphertext,
        &plans,
        caesar_key_label(POSITIVE_CONTROL_CAESAR_SHIFT),
    )?;

    let vigenere_shifts = POSITIVE_CONTROL_VIGENERE_SHIFTS.to_vec();
    let vigenere_key = VigenereKey::new(EYE_READING_ALPHABET_SIZE, vigenere_shifts.clone())?;
    let vigenere_ciphertext = encrypt_messages(&plaintext, |message| {
        vigenere_encrypt(message, &vigenere_key)
    })?;
    let vigenere = recover_plant(
        CipherFamily::Vigenere,
        control_config,
        &vigenere_ciphertext,
        &plans,
        vigenere_key_label(&vigenere_shifts),
    )?;

    Ok(PositiveControlReport { caesar, vigenere })
}

fn english_modulo_plan() -> Result<ScoringPlan, CipherAttackError> {
    Ok(ScoringPlan {
        language: LanguageKind::English,
        model: english_model()?,
        mapping: MappingKind::Modulo,
        target_letters: 26,
    })
}

fn positive_control_plaintext() -> Result<Vec<Vec<Glyph>>, CipherAttackError> {
    let model = english_model()?;
    let indices = model.alphabet().normalize_text(POSITIVE_CONTROL_TEXT)?;
    let mut message = Vec::with_capacity(indices.len());
    for index in indices {
        let value = u16::try_from(index).map_err(|_error| CipherAttackError::EmptyMapping)?;
        message.push(Glyph(value));
    }
    Ok(vec![message])
}

fn encrypt_messages(
    messages: &[Vec<Glyph>],
    mut encrypt: impl FnMut(&[Glyph]) -> Result<Vec<Glyph>, CipherError>,
) -> Result<Vec<Vec<Glyph>>, CipherAttackError> {
    let mut encrypted = Vec::with_capacity(messages.len());
    for message in messages {
        encrypted.push(encrypt(message)?);
    }
    Ok(encrypted)
}

fn recover_plant(
    cipher: CipherFamily,
    config: CipherAttackConfig,
    ciphertext: &[Vec<Glyph>],
    plans: &[ScoringPlan],
    expected_key: String,
) -> Result<PlantRecovery, CipherAttackError> {
    let real = search_cipher(cipher, config, ciphertext, plans)?;
    let Some(best) = real.best.into_iter().next() else {
        return Err(CipherAttackError::NoKeyCandidates { cipher });
    };
    let samples = plant_null_scores(cipher, config, ciphertext, plans)?;
    let null = summarize_null(best.score.bigram_mean_log_likelihood, &samples);
    let margin = best.score.bigram_mean_log_likelihood - null.max;
    if best.key != expected_key || margin < POSITIVE_CONTROL_MIN_MARGIN {
        return Err(CipherAttackError::PositiveControlFailed {
            cipher,
            expected_key,
            recovered_key: best.key,
            real_score: best.score.bigram_mean_log_likelihood,
            null_max: null.max,
        });
    }
    Ok(PlantRecovery {
        cipher,
        plaintext_symbols: best.score.symbols,
        expected_key,
        recovered_key: best.key,
        real_score: best.score,
        null,
        margin_over_null_max: margin,
    })
}

fn plant_null_scores(
    cipher: CipherFamily,
    config: CipherAttackConfig,
    ciphertext: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<Vec<f64>, CipherAttackError> {
    let mut samples = Vec::with_capacity(config.null_trials);
    let mut rng = SplitMix64::new(mix_seed(config.seed, cipher.seed_tag() ^ 0x0070_6c61_6e74));
    for _trial in 0..config.null_trials {
        let shuffled = shuffled_messages(ciphertext, &mut rng)?;
        let outcome = search_cipher(cipher, config, &shuffled, plans)?;
        let Some(best) = outcome.best.into_iter().next() else {
            return Err(CipherAttackError::NoKeyCandidates { cipher });
        };
        samples.push(best.score.bigram_mean_log_likelihood);
    }
    Ok(samples)
}
