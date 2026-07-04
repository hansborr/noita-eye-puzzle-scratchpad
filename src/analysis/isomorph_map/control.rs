//! In-process controls for the isomorph-map instrument.

use std::collections::BTreeSet;

use crate::analysis::translate_isomorph::markov_resample;
use crate::ciphers::{
    GakKey, GakKeyOptions, compose_permutations, gak_encrypt, validate_permutation,
};
use crate::core::glyph::Glyph;
use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

use super::{
    DEFAULT_CLOSURE_CAP, DEFAULT_TRIM, IsoMapError, MapKind, PatternSpan, close_full_maps,
    extract_column_map, isomorph_map_scan,
};

const S3_SIZE: usize = 6;
const POSITIVE_BLOCK_LEN: usize = 48;
const POSITIVE_MIN_SPAN: usize = 18;
const POSITIVE_TOP_K: usize = 16;
const SELF_TEST_NULL_TRIALS: usize = 64;
const DIRTY_ALPHABET: usize = 8;
const DIRTY_CORE_LEN: usize = 40;

/// Outcome of `isomap --self-test`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one pass/fail flag per independent control; the CLI renders them directly"
)]
pub struct IsoMapSelfTest {
    /// The planted hidden-state GAK ciphertext closed to the expected S3 group.
    pub gak_positive_passed: bool,
    /// The recovered positive-control group order.
    pub positive_group_order: usize,
    /// The Markov-resampled matched null produced no surviving maps and only the
    /// trivial closure.
    pub null_rejected: bool,
    /// The null-control closure order.
    pub null_group_order: usize,
    /// The dirty-boundary plant is protected by boundary trimming.
    pub dirty_boundary_passed: bool,
    /// All self-test controls passed.
    pub passed: bool,
}

/// Runs the in-process controls: planted hidden-state GAK positive, matched
/// Markov null, and dirty-boundary extraction.
///
/// # Errors
/// Returns [`IsoMapError`] if a control cannot be constructed or scanned.
pub fn isomorph_map_self_test(seed: u64) -> Result<IsoMapSelfTest, IsoMapError> {
    let control = build_s3_gak_control(seed)?;
    let positive_report = isomorph_map_scan(
        &control.ciphertext,
        S3_SIZE,
        POSITIVE_MIN_SPAN,
        DEFAULT_TRIM,
        POSITIVE_TOP_K,
        SELF_TEST_NULL_TRIALS,
        mix_seed(seed, 0x101),
    )?;
    let positive_maps = full_maps(&positive_report.maps);
    let positive_closure = close_full_maps(&positive_maps, S3_SIZE, DEFAULT_CLOSURE_CAP)?;
    let positive_subgroup = positive_closure
        .elements
        .iter()
        .all(|element| control.known_group.contains(element));
    let gak_positive_passed =
        positive_report.significant && positive_closure.order == S3_SIZE && positive_subgroup;

    let null_values = markov_null_stream(&control.ciphertext, seed)?;
    let null_report = isomorph_map_scan(
        &null_values,
        S3_SIZE,
        POSITIVE_MIN_SPAN,
        DEFAULT_TRIM,
        POSITIVE_TOP_K,
        SELF_TEST_NULL_TRIALS,
        mix_seed(seed, 0x202),
    )?;
    let null_maps = full_maps(&null_report.maps);
    let null_closure = close_full_maps(&null_maps, S3_SIZE, DEFAULT_CLOSURE_CAP)?;
    let null_rejected =
        !null_report.significant && null_report.maps.is_empty() && null_closure.order == 1;

    let dirty_boundary_passed = dirty_boundary_control()?;
    let passed = gak_positive_passed && null_rejected && dirty_boundary_passed;
    Ok(IsoMapSelfTest {
        gak_positive_passed,
        positive_group_order: positive_closure.order,
        null_rejected,
        null_group_order: null_closure.order,
        dirty_boundary_passed,
        passed,
    })
}

fn full_maps(maps: &[super::ColumnMap]) -> Vec<Vec<usize>> {
    maps.iter()
        .filter_map(|map| map.permutation.clone())
        .collect()
}

fn markov_null_stream(values: &[u16], seed: u64) -> Result<Vec<u16>, IsoMapError> {
    let stream: Vec<u32> = values.iter().map(|&value| u32::from(value)).collect();
    let mut rng = SplitMix64::new(mix_seed(seed, 0x303));
    let resampled = markov_resample(&stream, S3_SIZE, &mut rng)?;
    Ok(resampled
        .iter()
        .map(|&value| u16::try_from(value).unwrap_or(0))
        .collect())
}

struct GakControl {
    ciphertext: Vec<u16>,
    known_group: Vec<Vec<usize>>,
}

fn build_s3_gak_control(seed: u64) -> Result<GakControl, IsoMapError> {
    let s3 = s3_elements()?;
    let letters = regular_representations(&s3)?;
    let key = GakKey::deck(S3_SIZE, letters.clone(), GakKeyOptions::default())?;
    let known_group = permutation_closure(&letters, S3_SIZE)?;
    let transposition = regular_representation(&permutation_from_cycles(3, &[&[0, 1]]), &s3)?;
    let cycle = regular_representation(&permutation_from_cycles(3, &[&[0, 1, 2]]), &s3)?;
    let target_b = invert_permutation(&transposition)?;
    let target_c = invert_permutation(&cycle)?;

    let mut builder = PlainBuilder::new(letters);
    let block = planted_block(seed)?;
    builder.append_block(&block)?;
    builder.bridge_to(&target_b)?;
    builder.append_block(&block)?;
    builder.bridge_to(&target_c)?;
    builder.append_block(&block)?;

    let ciphertext = gak_encrypt(&builder.plaintext, &key)?
        .iter()
        .map(|glyph| glyph.0)
        .collect();
    Ok(GakControl {
        ciphertext,
        known_group,
    })
}

struct PlainBuilder {
    plaintext: Vec<Glyph>,
    state: Vec<usize>,
    letters: Vec<Vec<usize>>,
}

impl PlainBuilder {
    fn new(letters: Vec<Vec<usize>>) -> Self {
        Self {
            plaintext: Vec::new(),
            state: (0..S3_SIZE).collect(),
            letters,
        }
    }

    fn append_block(&mut self, block: &[usize]) -> Result<(), IsoMapError> {
        for &letter in block {
            self.append_letter(letter)?;
        }
        Ok(())
    }

    fn bridge_to(&mut self, target: &[usize]) -> Result<(), IsoMapError> {
        let inverse = invert_permutation(&self.state)?;
        let needed = compose_permutations(target, &inverse)?;
        let letter = self
            .letters
            .iter()
            .position(|candidate| candidate == &needed)
            .ok_or(IsoMapError::Permutation(
                crate::ciphers::CipherError::InternalInvariant {
                    context: "S3 GAK bridge letter",
                },
            ))?;
        self.append_letter(letter)
    }

    fn append_letter(&mut self, letter: usize) -> Result<(), IsoMapError> {
        let permutation = self.letters.get(letter).ok_or(IsoMapError::Permutation(
            crate::ciphers::CipherError::InternalInvariant {
                context: "S3 GAK plaintext letter",
            },
        ))?;
        self.state = compose_permutations(permutation, &self.state)?;
        self.plaintext
            .push(Glyph(u16::try_from(letter).unwrap_or(0)));
        Ok(())
    }
}

fn planted_block(seed: u64) -> Result<Vec<usize>, IsoMapError> {
    let mut rng = SplitMix64::new(mix_seed(seed, 0x404));
    let mut block = Vec::with_capacity(POSITIVE_BLOCK_LEN);
    for letter in 0..S3_SIZE {
        block.push(letter);
    }
    while block.len() < POSITIVE_BLOCK_LEN {
        block.push(random_index_below(S3_SIZE, &mut rng)?);
    }
    Ok(block)
}

fn s3_elements() -> Result<Vec<Vec<usize>>, IsoMapError> {
    permutation_closure(
        &[
            permutation_from_cycles(3, &[&[0, 1, 2]]),
            permutation_from_cycles(3, &[&[0, 1]]),
        ],
        3,
    )
}

fn regular_representations(group: &[Vec<usize>]) -> Result<Vec<Vec<usize>>, IsoMapError> {
    group
        .iter()
        .map(|element| regular_representation(element, group))
        .collect()
}

fn regular_representation(
    element: &[usize],
    group: &[Vec<usize>],
) -> Result<Vec<usize>, IsoMapError> {
    let mut permutation = Vec::with_capacity(group.len());
    for point in group {
        let product = compose_permutations(element, point)?;
        let image = group
            .iter()
            .position(|candidate| candidate == &product)
            .ok_or(IsoMapError::Permutation(
                crate::ciphers::CipherError::InternalInvariant {
                    context: "regular representation image",
                },
            ))?;
        permutation.push(image);
    }
    validate_permutation("regular representation", &permutation, group.len())?;
    Ok(permutation)
}

fn permutation_closure(
    generators: &[Vec<usize>],
    size: usize,
) -> Result<Vec<Vec<usize>>, IsoMapError> {
    let identity: Vec<usize> = (0..size).collect();
    let mut elements = BTreeSet::new();
    let mut worklist = Vec::new();
    let _inserted = elements.insert(identity.clone());
    worklist.push(identity);
    while let Some(element) = worklist.pop() {
        for generator in generators {
            let product = compose_permutations(generator, &element)?;
            if elements.insert(product.clone()) {
                worklist.push(product);
            }
        }
    }
    Ok(elements.into_iter().collect())
}

fn permutation_from_cycles(size: usize, cycles: &[&[usize]]) -> Vec<usize> {
    let mut permutation: Vec<usize> = (0..size).collect();
    for cycle in cycles {
        for (index, &source) in cycle.iter().enumerate() {
            let target = cycle
                .get((index + 1) % cycle.len())
                .copied()
                .unwrap_or(source);
            if let Some(slot) = permutation.get_mut(source) {
                *slot = target;
            }
        }
    }
    permutation
}

fn invert_permutation(permutation: &[usize]) -> Result<Vec<usize>, IsoMapError> {
    let mut inverse = vec![0; permutation.len()];
    for (source, &target) in permutation.iter().enumerate() {
        let Some(slot) = inverse.get_mut(target) else {
            return Err(IsoMapError::Permutation(
                crate::ciphers::CipherError::InternalInvariant {
                    context: "invert permutation target",
                },
            ));
        };
        *slot = source;
    }
    Ok(inverse)
}

fn dirty_boundary_control() -> Result<bool, IsoMapError> {
    let mut stream = vec![0u16; 180];
    let first = 30usize;
    let second = 120usize;
    let mut source_window = Vec::with_capacity(DIRTY_CORE_LEN + 2);
    let mut target_window = Vec::with_capacity(DIRTY_CORE_LEN + 2);
    source_window.push(7);
    target_window.push(0);
    for offset in 0..DIRTY_CORE_LEN {
        let source = offset % (DIRTY_ALPHABET - 1);
        source_window.push(u16::try_from(source).unwrap_or(0));
        target_window.push(u16::try_from(source + 1).unwrap_or(0));
    }
    source_window.push(7);
    target_window.push(0);
    for (offset, &value) in source_window.iter().enumerate() {
        if let Some(slot) = stream.get_mut(first + offset) {
            *slot = value;
        }
    }
    for (offset, &value) in target_window.iter().enumerate() {
        if let Some(slot) = stream.get_mut(second + offset) {
            *slot = value;
        }
    }

    let span = PatternSpan {
        length: DIRTY_CORE_LEN + 2,
        first,
        second,
        gap: second - first,
    };
    let untrimmed = extract_column_map(&stream, DIRTY_ALPHABET, span, 0)?;
    let trimmed = extract_column_map(&stream, DIRTY_ALPHABET, span, 1)?;
    Ok(untrimmed.kind == MapKind::Full
        && trimmed.kind == MapKind::Partial
        && trimmed.boundary_positions_dropped == 2
        && trimmed.mapping.get(7).copied().flatten().is_none())
}
