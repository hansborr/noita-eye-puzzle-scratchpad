use super::{
    ALPHABET_SIZE, CONDITION_COUNT, CandidateFamily, ConditionVector, FamilyFixtureReport,
    FixtureDrawReport, MOTIF_EXACT_A, MOTIF_EXACT_B, MOTIF_NEAR, MOTIF_PREDECESSORS, MOTIF_STARTS,
    PyryCondition, PyryConditionsConfig, PyryConditionsError, SHARED_PREFIX, VIGENERE_PERIOD,
    VIGENERE_SHIFTS, WHEEL_STEP, evaluate_corpus, glyph_symbol, glyphs_to_values,
    render_usize_list,
};
use crate::ciphers::{
    DeckCipherKey, IncrementingWheelKey, VigenereKey, deck_cipher_encrypt,
    incrementing_wheel_encrypt, vigenere_encrypt,
};
use crate::core::glyph::Glyph;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{
    SplitMix64, mix_seed, random_index_below, shuffled_permutation, stateless_splitmix,
};

pub(super) fn evaluate_generated_families(
    config: PyryConditionsConfig,
    lengths: &[usize],
) -> Result<Vec<FamilyFixtureReport>, PyryConditionsError> {
    let mut family_reports = Vec::new();
    for family in CandidateFamily::all() {
        family_reports.push(evaluate_family(config, lengths, family)?);
    }
    Ok(family_reports)
}

fn evaluate_family(
    config: PyryConditionsConfig,
    lengths: &[usize],
    family: CandidateFamily,
) -> Result<FamilyFixtureReport, PyryConditionsError> {
    let mut draws = Vec::with_capacity(config.fixture_draws);
    let mut condition_pass_counts = [0usize; CONDITION_COUNT];
    let mut all_conditions_pass_count = 0usize;

    for draw_index in 0..config.fixture_draws {
        let draw_seed = mix_seed(config.seed, draw_index as u64);
        let mut plaintext_rng = SplitMix64::new(mix_seed(draw_seed, 0x0070_6c61_696e));
        let plaintext = build_plaintext_fixture(lengths, &mut plaintext_rng)?;
        let mut family_rng = SplitMix64::new(mix_seed(draw_seed, family.seed_tag()));
        let fixture = encrypt_fixture(family, &plaintext, &mut family_rng)?;
        let evaluation = evaluate_corpus(family.label(), &fixture.values);
        add_condition_counts(evaluation.vector, &mut condition_pass_counts);
        if evaluation.vector.all_pass() {
            all_conditions_pass_count += 1;
        }
        draws.push(FixtureDrawReport {
            draw_index,
            key_summary: fixture.key_summary,
            evaluation,
        });
    }

    Ok(FamilyFixtureReport {
        family,
        draws,
        condition_pass_counts,
        all_conditions_pass_count,
    })
}

fn add_condition_counts(vector: ConditionVector, counts: &mut [usize; CONDITION_COUNT]) {
    for condition in PyryCondition::all() {
        if vector.get(condition) {
            let index = condition.number().saturating_sub(1);
            if let Some(count) = counts.get_mut(index) {
                *count += 1;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct CipherFixture {
    values: Vec<Vec<TrigramValue>>,
    key_summary: String,
}

fn encrypt_fixture(
    family: CandidateFamily,
    plaintext: &[Vec<Glyph>],
    rng: &mut SplitMix64,
) -> Result<CipherFixture, PyryConditionsError> {
    match family {
        CandidateFamily::MonoalphabeticSubstitution => monoalphabetic_fixture(plaintext, rng),
        CandidateFamily::PeriodicVigenere => vigenere_fixture(plaintext),
        CandidateFamily::AutokeyAlbertiStyle => autokey_fixture(plaintext),
        CandidateFamily::DeckS83Permutation => deck_fixture(plaintext, rng),
        CandidateFamily::IncrementingWheel => wheel_fixture(plaintext, rng),
    }
}

fn monoalphabetic_fixture(
    plaintext: &[Vec<Glyph>],
    rng: &mut SplitMix64,
) -> Result<CipherFixture, PyryConditionsError> {
    let permutation = shuffled_permutation(ALPHABET_SIZE, rng)?;
    let mut messages = Vec::with_capacity(plaintext.len());
    for message in plaintext {
        let mut ciphertext = Vec::with_capacity(message.len());
        for glyph in message {
            let symbol = glyph_symbol(*glyph)?;
            let Some(&cipher_symbol) = permutation.get(symbol) else {
                return Err(PyryConditionsError::GeneratedSymbolOutsideAlphabet {
                    symbol: *glyph,
                    alphabet_size: ALPHABET_SIZE,
                });
            };
            ciphertext.push(Glyph(cipher_symbol as u16));
        }
        messages.push(glyphs_to_values(&ciphertext)?);
    }
    Ok(CipherFixture {
        values: messages,
        key_summary: "random S83 substitution permutation".to_owned(),
    })
}

fn vigenere_fixture(plaintext: &[Vec<Glyph>]) -> Result<CipherFixture, PyryConditionsError> {
    let key = VigenereKey::new(ALPHABET_SIZE, VIGENERE_SHIFTS.to_vec())?;
    let mut messages = Vec::with_capacity(plaintext.len());
    for message in plaintext {
        let ciphertext = vigenere_encrypt(message, &key)?;
        messages.push(glyphs_to_values(&ciphertext)?);
    }
    Ok(CipherFixture {
        values: messages,
        key_summary: format!("period-{VIGENERE_PERIOD} shifts {VIGENERE_SHIFTS:?}"),
    })
}

fn autokey_fixture(plaintext: &[Vec<Glyph>]) -> Result<CipherFixture, PyryConditionsError> {
    let mut messages = Vec::with_capacity(plaintext.len());
    for message in plaintext {
        messages.push(glyphs_to_values(&autokey_encrypt(message, 0)?)?);
    }
    Ok(CipherFixture {
        values: messages,
        key_summary: "plaintext-autokey additive seed shift 0".to_owned(),
    })
}

fn deck_fixture(
    plaintext: &[Vec<Glyph>],
    rng: &mut SplitMix64,
) -> Result<CipherFixture, PyryConditionsError> {
    let deck = shuffled_permutation(ALPHABET_SIZE, rng)?;
    let key = DeckCipherKey::new(ALPHABET_SIZE, deck, ALPHABET_SIZE - 2, ALPHABET_SIZE - 1)?;
    let mut messages = Vec::with_capacity(plaintext.len());
    for message in plaintext {
        let ciphertext = deck_cipher_encrypt(message, &key)?;
        messages.push(glyphs_to_values(&ciphertext)?);
    }
    Ok(CipherFixture {
        values: messages,
        key_summary: "SplitMix64-shuffled S83 deck, controls 81/82".to_owned(),
    })
}

fn wheel_fixture(
    plaintext: &[Vec<Glyph>],
    rng: &mut SplitMix64,
) -> Result<CipherFixture, PyryConditionsError> {
    let mut messages = Vec::with_capacity(plaintext.len());
    let mut starts = Vec::with_capacity(plaintext.len());
    for message in plaintext {
        let start = random_index_below(ALPHABET_SIZE, rng)?;
        starts.push(start);
        let key = IncrementingWheelKey::new(ALPHABET_SIZE, start, WHEEL_STEP)?;
        let ciphertext = incrementing_wheel_encrypt(message, &key)?;
        messages.push(glyphs_to_values(&ciphertext)?);
    }
    Ok(CipherFixture {
        values: messages,
        key_summary: format!(
            "step {WHEEL_STEP}, per-message starts {}",
            render_usize_list(&starts)
        ),
    })
}

fn autokey_encrypt(
    message: &[Glyph],
    seed_shift: usize,
) -> Result<Vec<Glyph>, PyryConditionsError> {
    let mut previous_plain = seed_shift % ALPHABET_SIZE;
    let mut ciphertext = Vec::with_capacity(message.len());
    for glyph in message {
        let plain = glyph_symbol(*glyph)?;
        let cipher = (plain + previous_plain) % ALPHABET_SIZE;
        ciphertext.push(Glyph(cipher as u16));
        previous_plain = plain;
    }
    Ok(ciphertext)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceSampler {
    population: Vec<usize>,
}

impl SourceSampler {
    fn new() -> Self {
        let mut population = Vec::new();
        for symbol in 0..ALPHABET_SIZE {
            let weight = 1 + stateless_splitmix(symbol as u64 ^ 0x7079_7279_7372_6300) % 31;
            for _copy in 0..weight {
                population.push(symbol);
            }
        }
        Self { population }
    }

    fn sample_symbol(&self, rng: &mut SplitMix64) -> Result<usize, PyryConditionsError> {
        let index = random_index_below(self.population.len(), rng)?;
        self.population
            .get(index)
            .copied()
            .ok_or(PyryConditionsError::RandomBoundTooLarge {
                bound: self.population.len(),
            })
    }

    fn sample_symbol_excluding(
        &self,
        excluded: &[usize],
        rng: &mut SplitMix64,
    ) -> Result<usize, PyryConditionsError> {
        loop {
            let symbol = self.sample_symbol(rng)?;
            if !excluded.contains(&symbol) {
                return Ok(symbol);
            }
        }
    }
}

fn build_plaintext_fixture(
    lengths: &[usize],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<Glyph>>, PyryConditionsError> {
    let sampler = SourceSampler::new();
    let mut messages = Vec::with_capacity(lengths.len());
    let mut fixed_masks = Vec::with_capacity(lengths.len());
    for (message_index, &length) in lengths.iter().enumerate() {
        let mut message = sample_plaintext_message(length, &sampler, rng)?;
        let mut fixed = vec![false; length];
        apply_shared_prefix(message_index, &mut message, &mut fixed, rng)?;
        apply_planted_isomorphs(message_index, &mut message, &mut fixed);
        messages.push(message);
        fixed_masks.push(fixed);
    }
    repair_plaintext_local_repeats(&mut messages, &fixed_masks, &sampler, rng)?;
    Ok(messages)
}

fn sample_plaintext_message(
    length: usize,
    sampler: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<Vec<Glyph>, PyryConditionsError> {
    let mut message = Vec::with_capacity(length);
    for position in 0..length {
        let excluded = previous_symbols(&message, position);
        let symbol = sampler.sample_symbol_excluding(&excluded, rng)?;
        message.push(Glyph(symbol as u16));
    }
    Ok(message)
}

fn previous_symbols(message: &[Glyph], position: usize) -> Vec<usize> {
    let mut excluded = Vec::new();
    if let Some(previous_position) = position.checked_sub(1)
        && let Some(glyph) = message.get(previous_position)
    {
        excluded.push(usize::from(glyph.0));
    }
    if let Some(previous_position) = position.checked_sub(2)
        && let Some(glyph) = message.get(previous_position)
    {
        excluded.push(usize::from(glyph.0));
    }
    excluded
}

fn apply_shared_prefix(
    message_index: usize,
    message: &mut [Glyph],
    fixed: &mut [bool],
    rng: &mut SplitMix64,
) -> Result<(), PyryConditionsError> {
    if message.is_empty() {
        return Ok(());
    }
    let prefix_second = SHARED_PREFIX.get(1).copied().unwrap_or_default();
    let mut varying_first =
        (message_index * 11 + random_index_below(ALPHABET_SIZE, rng)?) % ALPHABET_SIZE;
    if varying_first == prefix_second {
        varying_first = (varying_first + 1) % ALPHABET_SIZE;
    }
    set_fixed_symbol(message, fixed, 0, varying_first);
    for (offset, symbol) in SHARED_PREFIX.iter().copied().enumerate() {
        let position = offset + 1;
        set_fixed_symbol(message, fixed, position, symbol);
    }
    Ok(())
}

fn apply_planted_isomorphs(message_index: usize, message: &mut [Glyph], fixed: &mut [bool]) {
    if message_index != 0 {
        return;
    }
    apply_motif(
        message,
        fixed,
        MOTIF_STARTS.first().copied(),
        MOTIF_PREDECESSORS.first().copied(),
        &MOTIF_EXACT_A,
    );
    apply_motif(
        message,
        fixed,
        MOTIF_STARTS.get(1).copied(),
        MOTIF_PREDECESSORS.get(1).copied(),
        &MOTIF_EXACT_B,
    );
    apply_motif(
        message,
        fixed,
        MOTIF_STARTS.get(2).copied(),
        MOTIF_PREDECESSORS.get(2).copied(),
        &MOTIF_NEAR,
    );
}

fn apply_motif(
    message: &mut [Glyph],
    fixed: &mut [bool],
    start: Option<usize>,
    predecessor: Option<usize>,
    motif: &[usize],
) {
    let Some(start) = start else {
        return;
    };
    if let Some(previous_position) = start.checked_sub(1)
        && let Some(predecessor) = predecessor
    {
        set_fixed_symbol(message, fixed, previous_position, predecessor);
    }
    for (offset, symbol) in motif.iter().copied().enumerate() {
        set_fixed_symbol(message, fixed, start + offset, symbol);
    }
}

fn set_fixed_symbol(message: &mut [Glyph], fixed: &mut [bool], position: usize, symbol: usize) {
    if let Some(slot) = message.get_mut(position) {
        *slot = Glyph(symbol as u16);
    }
    if let Some(slot) = fixed.get_mut(position) {
        *slot = true;
    }
}

fn repair_plaintext_local_repeats(
    messages: &mut [Vec<Glyph>],
    fixed_masks: &[Vec<bool>],
    sampler: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<(), PyryConditionsError> {
    for _pass in 0..4 {
        let mut changed = false;
        for (message, fixed) in messages.iter_mut().zip(fixed_masks) {
            changed |= repair_message_local_repeats(message, fixed, sampler, rng)?;
        }
        if !changed {
            return Ok(());
        }
    }
    Ok(())
}

fn repair_message_local_repeats(
    message: &mut [Glyph],
    fixed: &[bool],
    sampler: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<bool, PyryConditionsError> {
    let mut changed = false;
    for position in 0..message.len() {
        if local_repeat_at(message, position) {
            let repair_position = repair_position(message, fixed, position);
            if let Some(repair_position) = repair_position {
                resample_plaintext_position(message, repair_position, sampler, rng)?;
                changed = true;
            }
        }
    }
    Ok(changed)
}

fn local_repeat_at(message: &[Glyph], position: usize) -> bool {
    let Some(current) = message.get(position) else {
        return false;
    };
    for distance in [1usize, 2] {
        let Some(previous_position) = position.checked_sub(distance) else {
            continue;
        };
        if message.get(previous_position) == Some(current) {
            return true;
        }
    }
    false
}

fn repair_position(message: &[Glyph], fixed: &[bool], position: usize) -> Option<usize> {
    if fixed.get(position).copied() == Some(false) {
        return Some(position);
    }
    for distance in [1usize, 2] {
        let previous_position = position.checked_sub(distance)?;
        if fixed.get(previous_position).copied() == Some(false) && previous_position < message.len()
        {
            return Some(previous_position);
        }
    }
    None
}

fn resample_plaintext_position(
    message: &mut [Glyph],
    position: usize,
    sampler: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<(), PyryConditionsError> {
    let excluded = neighbor_symbols(message, position);
    let symbol = sampler.sample_symbol_excluding(&excluded, rng)?;
    if let Some(slot) = message.get_mut(position) {
        *slot = Glyph(symbol as u16);
    }
    Ok(())
}

fn neighbor_symbols(message: &[Glyph], position: usize) -> Vec<usize> {
    let mut excluded = Vec::new();
    for distance in [1usize, 2] {
        if let Some(previous_position) = position.checked_sub(distance)
            && let Some(glyph) = message.get(previous_position)
        {
            excluded.push(usize::from(glyph.0));
        }
        if let Some(next_position) = position.checked_add(distance)
            && let Some(glyph) = message.get(next_position)
        {
            excluded.push(usize::from(glyph.0));
        }
    }
    excluded
}
