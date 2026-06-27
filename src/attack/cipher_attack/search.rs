use super::nulls::{
    caesar_key_label, format_prefix, random_distinct_control, random_permutation,
    shuffled_messages, summarize_null, vigenere_key_label, vigenere_key_space,
    vigenere_key_space_label, vigenere_note, vigenere_shifts_from_ordinal,
};
use super::scoring::{decrypt_messages, score_candidate};
use super::{
    AttackRow, BestCandidate, CipherAttackConfig, CipherAttackError, CipherFamily, ScoringPlan,
    SearchSummary,
};
use crate::ciphers::{
    CaesarKey, ChaocipherKey, DeckCipherKey, EYE_READING_ALPHABET_SIZE, IncrementingWheelKey,
    VigenereKey, caesar_decrypt, chaocipher_decrypt, deck_cipher_decrypt,
    incrementing_wheel_decrypt, vigenere_decrypt,
};
use crate::core::glyph::Glyph;
use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

pub(super) fn append_cipher_rows(
    cipher: CipherFamily,
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
    rows: &mut Vec<AttackRow>,
) -> Result<(), CipherAttackError> {
    let real = search_cipher(cipher, config, messages, plans)?;
    let null_samples = null_samples(cipher, config, messages, plans)?;

    for ((plan, real_best), samples) in plans.iter().zip(real.best).zip(null_samples) {
        rows.push(AttackRow {
            cipher,
            language: plan.language,
            mapping_label: plan.mapping_label(),
            mapping_note: plan.mapping_note().to_owned(),
            search: real.summary.clone(),
            null: summarize_null(real_best.score.bigram_mean_log_likelihood, &samples),
            real: real_best,
        });
    }
    Ok(())
}

fn null_samples(
    cipher: CipherFamily,
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<Vec<Vec<f64>>, CipherAttackError> {
    let mut samples = vec![Vec::new(); plans.len()];
    let mut rng = SplitMix64::new(mix_seed(config.seed, cipher.seed_tag() ^ 0x6e75_6c6c));

    for _trial in 0..config.null_trials {
        let shuffled = shuffled_messages(messages, &mut rng)?;
        let outcome = search_cipher(cipher, config, &shuffled, plans)?;
        for (slot, best) in samples.iter_mut().zip(outcome.best) {
            slot.push(best.score.bigram_mean_log_likelihood);
        }
    }

    Ok(samples)
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct SearchOutcome {
    pub(super) summary: SearchSummary,
    pub(super) best: Vec<BestCandidate>,
}

pub(super) fn search_cipher(
    cipher: CipherFamily,
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    match cipher {
        CipherFamily::Caesar => search_caesar(messages, plans),
        CipherFamily::IncrementingWheel => search_incrementing_wheel(messages, plans),
        CipherFamily::Vigenere => search_vigenere(config, messages, plans),
        CipherFamily::Chaocipher => search_chaocipher(config, messages, plans),
        CipherFamily::Deck => search_deck(config, messages, plans),
    }
}

fn search_caesar(
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    let mut trackers = BestTrackers::new(plans.len());
    for shift in 0..EYE_READING_ALPHABET_SIZE {
        let key = CaesarKey::new(EYE_READING_ALPHABET_SIZE, shift)?;
        let decrypted = decrypt_messages(messages, |message| caesar_decrypt(message, &key))?;
        let label = caesar_key_label(shift);
        trackers.update(plans, &decrypted, &label)?;
    }
    Ok(SearchOutcome {
        summary: SearchSummary {
            key_space: "83 shifts".to_owned(),
            candidates_evaluated: EYE_READING_ALPHABET_SIZE,
            exhaustive: true,
            sampling_seed: None,
            note: "brute-forced all 83 shifts".to_owned(),
        },
        best: trackers.finish(CipherFamily::Caesar)?,
    })
}

fn search_incrementing_wheel(
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    let mut trackers = BestTrackers::new(plans.len());
    let mut candidates = 0usize;
    for start in 0..EYE_READING_ALPHABET_SIZE {
        for step in 0..EYE_READING_ALPHABET_SIZE {
            let key = IncrementingWheelKey::new(EYE_READING_ALPHABET_SIZE, start, step)?;
            let decrypted = decrypt_messages(messages, |message| {
                incrementing_wheel_decrypt(message, &key)
            })?;
            let label = format!("start={start} step={step}");
            trackers.update(plans, &decrypted, &label)?;
            candidates += 1;
        }
    }
    Ok(SearchOutcome {
        summary: SearchSummary {
            key_space: "83 x 83 start/step pairs".to_owned(),
            candidates_evaluated: candidates,
            exhaustive: true,
            sampling_seed: None,
            note: "brute-forced every start and step".to_owned(),
        },
        best: trackers.finish(CipherFamily::IncrementingWheel)?,
    })
}

fn search_vigenere(
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    let total = vigenere_key_space(EYE_READING_ALPHABET_SIZE, config.vigenere_max_period)?;
    let search_seed = mix_seed(config.seed, CipherFamily::Vigenere.seed_tag());
    let exhaustive = config.samples >= total;
    let candidates = if exhaustive { total } else { config.samples };
    let mut trackers = BestTrackers::new(plans.len());
    let mut rng = SplitMix64::new(search_seed);

    for ordinal_index in 0..candidates {
        let ordinal = if exhaustive {
            ordinal_index
        } else {
            random_index_below(total, &mut rng)?
        };
        let shifts = vigenere_shifts_from_ordinal(
            ordinal,
            EYE_READING_ALPHABET_SIZE,
            config.vigenere_max_period,
        )?;
        let key = VigenereKey::new(EYE_READING_ALPHABET_SIZE, shifts.clone())?;
        let decrypted = decrypt_messages(messages, |message| vigenere_decrypt(message, &key))?;
        let label = vigenere_key_label(&shifts);
        trackers.update(plans, &decrypted, &label)?;
    }

    Ok(SearchOutcome {
        summary: SearchSummary {
            key_space: vigenere_key_space_label(config.vigenere_max_period, total),
            candidates_evaluated: candidates,
            exhaustive,
            sampling_seed: if exhaustive { None } else { Some(search_seed) },
            note: vigenere_note(exhaustive, candidates),
        },
        best: trackers.finish(CipherFamily::Vigenere)?,
    })
}

fn search_chaocipher(
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    let search_seed = mix_seed(config.seed, CipherFamily::Chaocipher.seed_tag());
    let mut rng = SplitMix64::new(search_seed);
    let mut trackers = BestTrackers::new(plans.len());

    for sample_index in 0..config.samples {
        let left = random_permutation(EYE_READING_ALPHABET_SIZE, &mut rng)?;
        let right = random_permutation(EYE_READING_ALPHABET_SIZE, &mut rng)?;
        let key = ChaocipherKey::new(EYE_READING_ALPHABET_SIZE, left.clone(), right.clone())?;
        let decrypted = decrypt_messages(messages, |message| chaocipher_decrypt(message, &key))?;
        let label = format!(
            "sample={sample_index} seed={search_seed} left_prefix={} right_prefix={}",
            format_prefix(&left, 8),
            format_prefix(&right, 8)
        );
        trackers.update(plans, &decrypted, &label)?;
    }

    Ok(SearchOutcome {
        summary: SearchSummary {
            key_space: "about 83! x 83! initial alphabet pairs".to_owned(),
            candidates_evaluated: config.samples,
            exhaustive: false,
            sampling_seed: Some(search_seed),
            note: format!(
                "sampled {} Chaocipher keys with SplitMix64; this is not a brute force",
                config.samples
            ),
        },
        best: trackers.finish(CipherFamily::Chaocipher)?,
    })
}

fn search_deck(
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    let search_seed = mix_seed(config.seed, CipherFamily::Deck.seed_tag());
    let mut rng = SplitMix64::new(search_seed);
    let mut trackers = BestTrackers::new(plans.len());

    for sample_index in 0..config.samples {
        let deck = random_permutation(EYE_READING_ALPHABET_SIZE, &mut rng)?;
        let control_a = random_index_below(EYE_READING_ALPHABET_SIZE, &mut rng)?;
        let control_b = random_distinct_control(control_a, &mut rng)?;
        let key = DeckCipherKey::new(
            EYE_READING_ALPHABET_SIZE,
            deck.clone(),
            control_a,
            control_b,
        )?;
        let decrypted = decrypt_messages(messages, |message| deck_cipher_decrypt(message, &key))?;
        let label = format!(
            "sample={sample_index} seed={search_seed} controls=({control_a},{control_b}) deck_prefix={}",
            format_prefix(&deck, 8)
        );
        trackers.update(plans, &decrypted, &label)?;
    }

    Ok(SearchOutcome {
        summary: SearchSummary {
            key_space: "about 83! deck permutations times 83 x 82 controls".to_owned(),
            candidates_evaluated: config.samples,
            exhaustive: false,
            sampling_seed: Some(search_seed),
            note: format!(
                "sampled {} deck keys with SplitMix64; this is not a brute force",
                config.samples
            ),
        },
        best: trackers.finish(CipherFamily::Deck)?,
    })
}

#[derive(Clone, Debug)]
struct BestTrackers {
    best: Vec<Option<BestCandidate>>,
}

impl BestTrackers {
    fn new(plan_count: usize) -> Self {
        Self {
            best: vec![None; plan_count],
        }
    }

    fn update(
        &mut self,
        plans: &[ScoringPlan],
        decrypted: &[Vec<Glyph>],
        key: &str,
    ) -> Result<(), CipherAttackError> {
        for (plan, slot) in plans.iter().zip(self.best.iter_mut()) {
            let score = score_candidate(decrypted, plan)?;
            if slot.as_ref().is_none_or(|best| {
                score.bigram_mean_log_likelihood > best.score.bigram_mean_log_likelihood
            }) {
                *slot = Some(BestCandidate {
                    score,
                    key: key.to_owned(),
                });
            }
        }
        Ok(())
    }

    fn finish(self, cipher: CipherFamily) -> Result<Vec<BestCandidate>, CipherAttackError> {
        let mut best = Vec::with_capacity(self.best.len());
        for candidate in self.best {
            let Some(candidate) = candidate else {
                return Err(CipherAttackError::NoKeyCandidates { cipher });
            };
            best.push(candidate);
        }
        Ok(best)
    }
}
