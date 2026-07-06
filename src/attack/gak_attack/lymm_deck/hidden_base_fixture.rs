//! Fixture construction for hidden-base GAK/deck identifiability audits.

use crate::nulls::null::{SplitMix64, mix_seed, random_index_below, shuffled_permutation};

use super::{
    HiddenBaseFixture, HiddenBaseFixtureConfig, HiddenBaseKind, KnownPlaintextPair, LymmDeckError,
    LymmDeckSpec, encrypt_lymm_deck, generate_random_pt_mapping, lymm_default_ct_alphabet,
};

const PLANT_SEED_TAG: u64 = 0x6862_706c_616e_7401;
const TEXT_SEED_TAG: u64 = 0x6862_7465_7874_0002;
const BASE_SEED_TAG: u64 = 0x6862_6261_7365_0003;

/// Plants a deterministic hidden-base known-plaintext fixture.
///
/// # Errors
/// Returns [`LymmDeckError`] if the fixture shape is invalid or encryption fails.
pub fn plant_hidden_base_fixture(
    config: &HiddenBaseFixtureConfig,
) -> Result<HiddenBaseFixture, LymmDeckError> {
    validate_fixture_config(config)?;
    let spec = build_hidden_base_spec(config)?;
    let planted = generate_random_pt_mapping(
        &spec,
        config.swap_budget,
        mix_seed(config.seed, PLANT_SEED_TAG),
    )?;
    let plaintexts = generate_plaintexts(config)?;
    let mut pairs = Vec::with_capacity(plaintexts.len());
    for (index, plaintext) in plaintexts.into_iter().enumerate() {
        let ciphertext = encrypt_lymm_deck(&spec, &planted.pt_mapping, &plaintext)?;
        pairs.push(KnownPlaintextPair {
            label: format!("m{index}"),
            plaintext,
            ciphertext,
        });
    }
    Ok(HiddenBaseFixture {
        spec,
        planted,
        pairs,
        config: config.clone(),
    })
}

fn validate_fixture_config(config: &HiddenBaseFixtureConfig) -> Result<(), LymmDeckError> {
    if config.n < 2 {
        return Err(LymmDeckError::DeckTooSmall { n: config.n });
    }
    if config.pt_alphabet.is_empty() {
        return Err(LymmDeckError::HiddenBaseConfig {
            reason: "plaintext alphabet must not be empty",
        });
    }
    if config.message_count == 0 {
        return Err(LymmDeckError::HiddenBaseConfig {
            reason: "message count must be at least one",
        });
    }
    if config.message_len == 0 {
        return Err(LymmDeckError::HiddenBaseConfig {
            reason: "message length must be at least one",
        });
    }
    if config.pt_alphabet.chars().count() > config.n.saturating_sub(1) {
        return Err(LymmDeckError::TooManyPlaintextLetters {
            requested: config.pt_alphabet.chars().count(),
            available: config.n.saturating_sub(1),
        });
    }
    Ok(())
}

fn build_hidden_base_spec(config: &HiddenBaseFixtureConfig) -> Result<LymmDeckSpec, LymmDeckError> {
    let ct_alphabet = lymm_default_ct_alphabet(config.n);
    match config.base_kind {
        HiddenBaseKind::Random => {
            let mut rng = SplitMix64::new(mix_seed(config.seed, BASE_SEED_TAG));
            let base = shuffled_permutation(config.n, &mut rng)?;
            LymmDeckSpec::from_base(config.n, &config.pt_alphabet, &ct_alphabet, base)
        }
        HiddenBaseKind::Affine { shift, decimation } => LymmDeckSpec::from_shift_decimation(
            config.n,
            &config.pt_alphabet,
            &ct_alphabet,
            shift,
            decimation,
        ),
    }
}

fn generate_plaintexts(config: &HiddenBaseFixtureConfig) -> Result<Vec<String>, LymmDeckError> {
    let alphabet = config.pt_alphabet.chars().collect::<Vec<_>>();
    let mut rng = SplitMix64::new(mix_seed(config.seed, TEXT_SEED_TAG));
    let mut messages = Vec::with_capacity(config.message_count);
    let mut cycle_index = 0usize;
    for message_index in 0..config.message_count {
        let mut plaintext = String::with_capacity(config.message_len);
        for position in 0..config.message_len {
            let letter_index = if position == 0 {
                message_index % alphabet.len()
            } else if cycle_index < alphabet.len() {
                let index = cycle_index;
                cycle_index = cycle_index.saturating_add(1);
                index
            } else {
                random_index_below(alphabet.len(), &mut rng)?
            };
            if let Some(&letter) = alphabet.get(letter_index) {
                plaintext.push(letter);
            }
        }
        messages.push(plaintext);
    }
    Ok(messages)
}
