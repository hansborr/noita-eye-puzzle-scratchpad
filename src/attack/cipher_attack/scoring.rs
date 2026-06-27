use super::{CandidateScore, CipherAttackError, MappingKind, ScoringPlan};
use crate::attack::language::LanguageModel;
use crate::ciphers::{CipherError, EYE_READING_ALPHABET_SIZE};
use crate::core::glyph::Glyph;

pub(super) fn decrypt_messages(
    messages: &[Vec<Glyph>],
    mut decrypt: impl FnMut(&[Glyph]) -> Result<Vec<Glyph>, CipherError>,
) -> Result<Vec<Vec<Glyph>>, CipherAttackError> {
    let mut decrypted = Vec::with_capacity(messages.len());
    for message in messages {
        decrypted.push(decrypt(message)?);
    }
    Ok(decrypted)
}

pub(super) fn score_candidate(
    messages: &[Vec<Glyph>],
    plan: &ScoringPlan,
) -> Result<CandidateScore, CipherAttackError> {
    let mapped = map_messages(messages, plan)?;
    weighted_language_score(&mapped, &plan.model)
}

fn map_messages(
    messages: &[Vec<Glyph>],
    plan: &ScoringPlan,
) -> Result<Vec<Vec<usize>>, CipherAttackError> {
    match plan.mapping {
        MappingKind::Modulo => map_messages_modulo(messages, plan.target_letters),
        MappingKind::FrequencyRankCdf => map_messages_frequency_rank(messages, plan),
    }
}

fn map_messages_modulo(
    messages: &[Vec<Glyph>],
    target_letters: usize,
) -> Result<Vec<Vec<usize>>, CipherAttackError> {
    if target_letters == 0 {
        return Err(CipherAttackError::EmptyMapping);
    }
    let mut mapped_messages = Vec::with_capacity(messages.len());
    for message in messages {
        let mut mapped = Vec::with_capacity(message.len());
        for glyph in message {
            let symbol = eye_symbol(*glyph)?;
            mapped.push(symbol % target_letters);
        }
        mapped_messages.push(mapped);
    }
    Ok(mapped_messages)
}

fn map_messages_frequency_rank(
    messages: &[Vec<Glyph>],
    plan: &ScoringPlan,
) -> Result<Vec<Vec<usize>>, CipherAttackError> {
    let table = frequency_rank_table(messages, plan)?;
    let mut mapped_messages = Vec::with_capacity(messages.len());
    for message in messages {
        let mut mapped = Vec::with_capacity(message.len());
        for glyph in message {
            let symbol = eye_symbol(*glyph)?;
            let Some(&index) = table.get(symbol) else {
                return Err(CipherAttackError::EmptyMapping);
            };
            mapped.push(index);
        }
        mapped_messages.push(mapped);
    }
    Ok(mapped_messages)
}

fn frequency_rank_table(
    messages: &[Vec<Glyph>],
    plan: &ScoringPlan,
) -> Result<Vec<usize>, CipherAttackError> {
    if plan.target_letters == 0 || plan.target_letters > plan.model.alphabet().len() {
        return Err(CipherAttackError::EmptyMapping);
    }

    let mut counts = vec![0usize; EYE_READING_ALPHABET_SIZE];
    for message in messages {
        for glyph in message {
            let symbol = eye_symbol(*glyph)?;
            let Some(count) = counts.get_mut(symbol) else {
                return Err(CipherAttackError::EmptyMapping);
            };
            *count += 1;
        }
    }

    let mut ranked_symbols = counts
        .iter()
        .copied()
        .enumerate()
        .collect::<Vec<(usize, usize)>>();
    ranked_symbols.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let ranked_letters = ranked_language_letters(plan)?;
    let total_weight = ranked_letters
        .iter()
        .map(|(_index, count)| *count)
        .sum::<usize>();
    if total_weight == 0 {
        return Err(CipherAttackError::EmptyMapping);
    }

    let mut table = vec![0usize; EYE_READING_ALPHABET_SIZE];
    for (rank, (symbol, _count)) in ranked_symbols.iter().copied().enumerate() {
        let fraction = (rank as f64 + 0.5) / EYE_READING_ALPHABET_SIZE as f64;
        let letter = ranked_letter_for_fraction(fraction, &ranked_letters, total_weight)?;
        let Some(slot) = table.get_mut(symbol) else {
            return Err(CipherAttackError::EmptyMapping);
        };
        *slot = letter;
    }
    Ok(table)
}

fn ranked_language_letters(plan: &ScoringPlan) -> Result<Vec<(usize, usize)>, CipherAttackError> {
    let mut ranked = Vec::with_capacity(plan.target_letters);
    for index in 0..plan.target_letters {
        ranked.push((index, plan.model.unigram_count(index)?));
    }
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    Ok(ranked)
}

fn ranked_letter_for_fraction(
    fraction: f64,
    ranked_letters: &[(usize, usize)],
    total_weight: usize,
) -> Result<usize, CipherAttackError> {
    let threshold = fraction * total_weight as f64;
    let mut cumulative = 0usize;
    for (index, count) in ranked_letters.iter().copied() {
        cumulative += count;
        if cumulative as f64 >= threshold {
            return Ok(index);
        }
    }
    ranked_letters
        .last()
        .map(|(index, _count)| *index)
        .ok_or(CipherAttackError::EmptyMapping)
}

fn weighted_language_score(
    messages: &[Vec<usize>],
    model: &LanguageModel,
) -> Result<CandidateScore, CipherAttackError> {
    let mut symbols = 0usize;
    let mut unigram = 0.0;
    let mut bigram = 0.0;

    for message in messages {
        if message.is_empty() {
            continue;
        }
        let score = model.score_indices(message)?;
        symbols += score.symbols;
        unigram += score.unigram_mean_log_likelihood * score.symbols as f64;
        bigram += score.bigram_mean_log_likelihood * score.symbols as f64;
    }

    if symbols == 0 {
        return Err(CipherAttackError::EmptyCorpus);
    }

    Ok(CandidateScore {
        symbols,
        unigram_mean_log_likelihood: unigram / symbols as f64,
        bigram_mean_log_likelihood: bigram / symbols as f64,
    })
}

fn eye_symbol(glyph: Glyph) -> Result<usize, CipherAttackError> {
    let symbol = usize::from(glyph.0);
    if symbol >= EYE_READING_ALPHABET_SIZE {
        return Err(CipherAttackError::ValueOutsideEyeAlphabet { value: glyph.0 });
    }
    Ok(symbol)
}
