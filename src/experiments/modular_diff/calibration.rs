//! Generated-fixture control calibration for the modular-difference experiment.
//!
//! Builds the wheel/Vigenere/deck/flat positive-control fixtures and the
//! within-message shuffle baseline, then calibrates the family bands used to
//! place the eye stream. Split out of the modular-difference body.

use crate::ciphers::{
    DeckCipherKey, IncrementingWheelKey, VigenereKey, deck_cipher_encrypt,
    incrementing_wheel_encrypt, vigenere_encrypt,
};
use crate::core::glyph::Glyph;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{
    NullSampler, SplitMix64, WithinMessageShuffle, f64_band, random_index_below,
    shuffled_permutation, stateless_splitmix,
};

use super::diff::{
    message_weighted_ioc_values, modular_difference_messages, summarize_difference_stream,
};
use super::{
    BandSeparation, CONTROL_FAMILIES, ControlFamily, ControlFamilyBand, ControlOrderReport,
    ControlSeparation, DifferenceOrderReport, DifferenceStats, FamilyPlacement, FingerprintBand,
    MAX_DIFFERENCE_ORDER, ModularDiffConfig, ModularDiffError, PRIMARY_MODULUS, ScalarBand,
    VIGENERE_SHIFTS, WHEEL_STEP, max_f64, trigram_from_usize,
};

#[derive(Clone, Copy, Debug, PartialEq)]
struct Fingerprint {
    ioc: f64,
    delta_ioc: f64,
    top_rate: f64,
    top_over_uniform: f64,
    period_excess: f64,
    best_lag_normalized_rate: f64,
    structure_score: f64,
}

impl Fingerprint {
    fn from_stats(stats: &DifferenceStats) -> Self {
        Self {
            ioc: stats.ioc,
            delta_ioc: stats.delta_ioc,
            top_rate: stats.top_difference.rate,
            top_over_uniform: stats.top_difference.over_uniform,
            period_excess: stats.period_excess,
            best_lag_normalized_rate: stats
                .best_autocorrelation
                .map_or(0.0, |row| row.normalized_rate),
            structure_score: stats.structure_score,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct FamilySamples {
    family: ControlFamily,
    fingerprints: Vec<Fingerprint>,
}

impl FamilySamples {
    fn new(family: ControlFamily, capacity: usize) -> Self {
        Self {
            family,
            fingerprints: Vec::with_capacity(capacity),
        }
    }
}

pub(super) fn calibrate_controls(
    config: ModularDiffConfig,
    lengths: &[usize],
    eye_differences: &[DifferenceOrderReport],
) -> Result<Vec<ControlOrderReport>, ModularDiffError> {
    let mut controls = Vec::new();
    for difference_order in 1..=MAX_DIFFERENCE_ORDER {
        let Some(eye_report) = eye_differences
            .iter()
            .find(|report| report.difference_order == difference_order)
        else {
            continue;
        };
        controls.push(calibrate_control_order(
            config,
            lengths,
            eye_report,
            difference_order,
        )?);
    }
    Ok(controls)
}

fn calibrate_control_order(
    config: ModularDiffConfig,
    lengths: &[usize],
    eye_report: &DifferenceOrderReport,
    difference_order: usize,
) -> Result<ControlOrderReport, ModularDiffError> {
    let mut rng = SplitMix64::new(mix_seed(
        config.seed,
        0x636f_6e74_726f_6c00 ^ difference_order as u64,
    ));
    let source = SourceSampler::new(PRIMARY_MODULUS);
    let mut family_samples = CONTROL_FAMILIES
        .iter()
        .copied()
        .map(|family| FamilySamples::new(family, config.trials))
        .collect::<Vec<_>>();

    for _trial in 0..config.trials {
        for samples in &mut family_samples {
            let fixture = build_control_fixture(samples.family, lengths, &source, &mut rng)?;
            let raw_ioc = message_weighted_ioc_values(&fixture);
            let differenced =
                modular_difference_messages(&fixture, difference_order, PRIMARY_MODULUS)?;
            let stats = summarize_difference_stream(
                &differenced,
                raw_ioc,
                PRIMARY_MODULUS,
                difference_order,
                config.max_period,
                config.max_lag,
            )?;
            samples.fingerprints.push(Fingerprint::from_stats(&stats));
        }
    }

    let family_bands = family_samples
        .iter()
        .map(|samples| ControlFamilyBand {
            family: samples.family,
            key_summary: samples.family.key_summary(),
            fingerprint: fingerprint_band(&samples.fingerprints),
        })
        .collect::<Vec<_>>();
    let separation = separation_from_bands(&family_bands);
    let eye_placement = classify_eye(
        &eye_report.stats,
        &eye_report.shuffle_baseline,
        &family_bands,
        separation,
    );

    Ok(ControlOrderReport {
        difference_order,
        family_bands,
        separation,
        eye_placement,
    })
}

fn separation_from_bands(family_bands: &[ControlFamilyBand]) -> ControlSeparation {
    let Some(wheel) = family_band(family_bands, ControlFamily::IncrementingWheel) else {
        return overlapping_separation();
    };
    let Some(vigenere) = family_band(family_bands, ControlFamily::PeriodicVigenere) else {
        return overlapping_separation();
    };
    let Some(deck) = family_band(family_bands, ControlFamily::DeckS83Keystream) else {
        return overlapping_separation();
    };
    let Some(flat) = family_band(family_bands, ControlFamily::FlatRandom) else {
        return overlapping_separation();
    };

    let nonwheel_top_ceiling = max_f64([
        vigenere.fingerprint.top_rate.q975,
        deck.fingerprint.top_rate.q975,
        flat.fingerprint.top_rate.q975,
    ]);
    let structureless_period_ceiling = deck
        .fingerprint
        .period_excess
        .q975
        .max(flat.fingerprint.period_excess.q975);
    ControlSeparation {
        wheel_top_rate: separated_when(wheel.fingerprint.top_rate.q025 > nonwheel_top_ceiling),
        vigenere_period_excess: separated_when(
            vigenere.fingerprint.period_excess.q025 > structureless_period_ceiling,
        ),
        deck_flat_structure: if bands_overlap(
            deck.fingerprint.structure_score,
            flat.fingerprint.structure_score,
        ) {
            BandSeparation::Overlapping
        } else {
            BandSeparation::Separated
        },
    }
}

fn overlapping_separation() -> ControlSeparation {
    ControlSeparation {
        wheel_top_rate: BandSeparation::Overlapping,
        vigenere_period_excess: BandSeparation::Overlapping,
        deck_flat_structure: BandSeparation::Overlapping,
    }
}

fn classify_eye(
    stats: &DifferenceStats,
    shuffle: &FingerprintBand,
    family_bands: &[ControlFamilyBand],
    separation: ControlSeparation,
) -> FamilyPlacement {
    if !separation.is_calibrated() {
        return FamilyPlacement::Uncalibrated;
    }
    let Some(wheel) = family_band(family_bands, ControlFamily::IncrementingWheel) else {
        return FamilyPlacement::Uncalibrated;
    };
    let Some(vigenere) = family_band(family_bands, ControlFamily::PeriodicVigenere) else {
        return FamilyPlacement::Uncalibrated;
    };
    let Some(deck) = family_band(family_bands, ControlFamily::DeckS83Keystream) else {
        return FamilyPlacement::Uncalibrated;
    };
    let Some(flat) = family_band(family_bands, ControlFamily::FlatRandom) else {
        return FamilyPlacement::Uncalibrated;
    };

    let nonwheel_top_ceiling = max_f64([
        vigenere.fingerprint.top_rate.q975,
        deck.fingerprint.top_rate.q975,
        flat.fingerprint.top_rate.q975,
    ]);
    if stats.top_difference.rate >= wheel.fingerprint.top_rate.q025
        && stats.top_difference.rate > nonwheel_top_ceiling
    {
        return FamilyPlacement::WheelLike;
    }

    let structureless_period_ceiling = max_f64([
        deck.fingerprint.period_excess.q975,
        flat.fingerprint.period_excess.q975,
        shuffle.period_excess.q975,
    ]);
    if stats.period_excess >= vigenere.fingerprint.period_excess.q025
        && stats.period_excess > structureless_period_ceiling
    {
        return FamilyPlacement::VigenereLike;
    }

    let structureless_ceiling = max_f64([
        deck.fingerprint.structure_score.max,
        flat.fingerprint.structure_score.max,
        shuffle.structure_score.max,
    ]);
    if stats.structure_score <= structureless_ceiling {
        FamilyPlacement::StructurelessLike
    } else {
        FamilyPlacement::BetweenBands
    }
}

fn family_band(
    family_bands: &[ControlFamilyBand],
    family: ControlFamily,
) -> Option<&ControlFamilyBand> {
    family_bands.iter().find(|band| band.family == family)
}

fn separated_when(condition: bool) -> BandSeparation {
    if condition {
        BandSeparation::Separated
    } else {
        BandSeparation::Overlapping
    }
}

fn bands_overlap(left: ScalarBand, right: ScalarBand) -> bool {
    left.q025 <= right.q975 && right.q025 <= left.q975
}

pub(super) fn shuffle_baseline(
    config: ModularDiffConfig,
    message_values: &[Vec<TrigramValue>],
    raw_ioc: f64,
    modulus: usize,
    difference_order: usize,
) -> Result<FingerprintBand, ModularDiffError> {
    let mut rng = SplitMix64::new(mix_seed(
        config.seed,
        0x7368_7566_666c_6500 ^ ((modulus as u64) << 8) ^ difference_order as u64,
    ));
    let mut samples = Vec::with_capacity(config.trials);
    let shuffle = WithinMessageShuffle {
        messages: message_values,
    };
    for _trial in 0..config.trials {
        let shuffled = shuffle.sample(&mut rng)?;
        let differenced = modular_difference_messages(&shuffled, difference_order, modulus)?;
        let stats = summarize_difference_stream(
            &differenced,
            raw_ioc,
            modulus,
            difference_order,
            config.max_period,
            config.max_lag,
        )?;
        samples.push(Fingerprint::from_stats(&stats));
    }
    Ok(fingerprint_band(&samples))
}

pub(super) fn build_control_fixture(
    family: ControlFamily,
    lengths: &[usize],
    source: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    match family {
        ControlFamily::IncrementingWheel => wheel_fixture(lengths, rng),
        ControlFamily::PeriodicVigenere => vigenere_fixture(lengths),
        ControlFamily::DeckS83Keystream => deck_fixture(lengths, source, rng),
        ControlFamily::FlatRandom => flat_random_fixture(lengths, rng),
    }
}

fn wheel_fixture(
    lengths: &[usize],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let mut messages = Vec::with_capacity(lengths.len());
    for &length in lengths {
        let start = random_index_below(PRIMARY_MODULUS, rng)?;
        let key = IncrementingWheelKey::new(PRIMARY_MODULUS, start, WHEEL_STEP)?;
        let plaintext = vec![Glyph(0); length];
        let ciphertext = incrementing_wheel_encrypt(&plaintext, &key)?;
        messages.push(glyphs_to_trigram_values(&ciphertext, PRIMARY_MODULUS)?);
    }
    Ok(messages)
}

fn vigenere_fixture(lengths: &[usize]) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let key = VigenereKey::new(PRIMARY_MODULUS, VIGENERE_SHIFTS.to_vec())?;
    let mut messages = Vec::with_capacity(lengths.len());
    for &length in lengths {
        let plaintext = vec![Glyph(0); length];
        let ciphertext = vigenere_encrypt(&plaintext, &key)?;
        messages.push(glyphs_to_trigram_values(&ciphertext, PRIMARY_MODULUS)?);
    }
    Ok(messages)
}

fn deck_fixture(
    lengths: &[usize],
    source: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let deck = shuffled_permutation(PRIMARY_MODULUS, rng)?;
    let key = DeckCipherKey::new(
        PRIMARY_MODULUS,
        deck,
        PRIMARY_MODULUS - 2,
        PRIMARY_MODULUS - 1,
    )?;
    let mut messages = Vec::with_capacity(lengths.len());
    for &length in lengths {
        let plaintext = source.sample_glyphs(length, rng)?;
        let ciphertext = deck_cipher_encrypt(&plaintext, &key)?;
        messages.push(glyphs_to_trigram_values(&ciphertext, PRIMARY_MODULUS)?);
    }
    Ok(messages)
}

fn flat_random_fixture(
    lengths: &[usize],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let mut messages = Vec::with_capacity(lengths.len());
    for &length in lengths {
        let mut values = Vec::with_capacity(length);
        for _position in 0..length {
            values.push(trigram_from_usize(
                random_index_below(PRIMARY_MODULUS, rng)?,
                PRIMARY_MODULUS,
            )?);
        }
        messages.push(values);
    }
    Ok(messages)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SourceSampler {
    population: Vec<usize>,
}

impl SourceSampler {
    pub(super) fn new(alphabet_size: usize) -> Self {
        let mut population = Vec::new();
        for symbol in 0..alphabet_size {
            let weight = 1 + (stateless_splitmix(symbol as u64 ^ 0x706c_6169_6e5f_7372) % 31);
            for _copy in 0..weight {
                population.push(symbol);
            }
        }
        Self { population }
    }

    fn sample_glyphs(
        &self,
        length: usize,
        rng: &mut SplitMix64,
    ) -> Result<Vec<Glyph>, ModularDiffError> {
        let mut glyphs = Vec::with_capacity(length);
        for _position in 0..length {
            let index = random_index_below(self.population.len(), rng)?;
            let Some(symbol) = self.population.get(index).copied() else {
                return Err(ModularDiffError::RandomBoundTooLarge {
                    bound: self.population.len(),
                });
            };
            glyphs.push(Glyph(symbol as u16));
        }
        Ok(glyphs)
    }
}

fn glyphs_to_trigram_values(
    glyphs: &[Glyph],
    modulus: usize,
) -> Result<Vec<TrigramValue>, ModularDiffError> {
    let mut values = Vec::with_capacity(glyphs.len());
    for glyph in glyphs {
        let raw = usize::from(glyph.0);
        if raw >= modulus {
            return Err(ModularDiffError::ValueOutsideModulus {
                value: u8::try_from(raw).unwrap_or(u8::MAX),
                modulus,
            });
        }
        values.push(trigram_from_usize(raw, modulus)?);
    }
    Ok(values)
}

fn fingerprint_band(samples: &[Fingerprint]) -> FingerprintBand {
    let band = |select: fn(&Fingerprint) -> f64| {
        ScalarBand::from(f64_band(&samples.iter().map(select).collect::<Vec<_>>()))
    };
    FingerprintBand {
        ioc: band(|sample| sample.ioc),
        delta_ioc: band(|sample| sample.delta_ioc),
        top_rate: band(|sample| sample.top_rate),
        top_over_uniform: band(|sample| sample.top_over_uniform),
        period_excess: band(|sample| sample.period_excess),
        best_lag_normalized_rate: band(|sample| sample.best_lag_normalized_rate),
        structure_score: band(|sample| sample.structure_score),
    }
}

fn mix_seed(seed: u64, tag: u64) -> u64 {
    stateless_splitmix(seed ^ tag.wrapping_mul(0x9e37_79b9_7f4a_7c15))
}
