use super::eval::{decrypt_round_trip, reinsert_transparent, render_indices};
use super::{
    AnnealSchedule, AnyCipher, AnyCodec, Candidate, CipherFamilySpec, Codec, Glyph, Language,
    LanguageModel, Mapping, MappingSearch, SEARCH_BEATS_NULL_MARGIN, SolveError, SolveRequest,
    SplitMix64, codec_round_trip_ok, family_seed_tag, fisher_yates, mix_seed, model_for,
    resolved_output_alphabet_size,
};

// ---------------------------------------------------------------------------
// Phase 2 — mapping search (hill-climb / simulated annealing).
// ---------------------------------------------------------------------------

/// Outcome of one mapping search: the best mapping found and its in-sample score.
struct MappingSearchOutcome {
    mapping: Mapping,
    score: f64,
}

/// One reversible proposal applied to a mapping table during the search.
enum Proposal {
    /// Repointed `symbol`'s target, restoring `old` on rejection.
    Repoint { symbol: usize, old: usize },
    /// Swapped the targets of symbols `a` and `b`.
    Swap { a: usize, b: usize },
}

pub(super) fn solve_search(
    req: &SolveRequest<'_>,
    search: &MappingSearch,
    codec: &AnyCodec,
) -> Result<Vec<Candidate>, SolveError> {
    let mut candidates = Vec::new();
    for family in &req.space.families {
        for language in req.space.language.languages() {
            let null_mean = matched_null_search_mean(req, family, *language, search, codec)?;
            for (cipher_index, cipher) in family.ciphers.iter().enumerate() {
                if let Some(candidate) = evaluate_cipher_search(
                    req,
                    family,
                    cipher,
                    cipher_index,
                    *language,
                    null_mean,
                    search,
                    codec,
                )? {
                    candidates.push(candidate);
                }
            }
        }
    }
    Ok(candidates)
}

// The codec stage threads an extra dimension through the established search
// pipeline; the params are the existing pipeline shape plus `codec`, so bundling
// them into a context struct would obscure rather than clarify.
#[allow(
    clippy::too_many_arguments,
    reason = "Phase-1 codec wiring adds one codec parameter to the existing search path"
)]
pub(super) fn evaluate_cipher_search(
    req: &SolveRequest<'_>,
    family: &CipherFamilySpec,
    cipher: &AnyCipher,
    cipher_index: usize,
    language: Language,
    null_mean: f64,
    search: &MappingSearch,
    codec: &AnyCodec,
) -> Result<Option<Candidate>, SolveError> {
    let Some(decrypted_symbols) = decrypt_round_trip(cipher, req.ciphertext)? else {
        return Ok(None);
    };
    let model = model_for(req, language);
    let transduced = codec.transduce(&decrypted_symbols)?;
    // The mapping search domain is the codec's output alphabet (Identity resolves
    // back to the cipher alphabet size, keeping the eyes path byte-for-byte).
    let mapping_domain = resolved_output_alphabet_size(codec, req.space.cipher_alphabet_size);
    let symbols = to_symbol_indices(&transduced, mapping_domain)?;
    let seed = search_seed(search.seed, family, cipher_index, language);

    let full = search_mapping(&symbols, mapping_domain, model, search, seed)?;
    let mapped = full.mapping.apply(&transduced)?;
    let rendered_text =
        reinsert_transparent(&render_indices(&mapped, model)?, req.transparent, codec);
    let heldout_mapping_score = heldout_search_score(
        &symbols,
        mapping_domain,
        model,
        search,
        mix_seed(seed, 0x0068_656c_646f_7574),
    )?;

    Ok(Some(Candidate {
        cipher: cipher.clone(),
        crypto_round_trip_ok: true,
        codec_round_trip_ok: codec_round_trip_ok(codec, &decrypted_symbols),
        decrypted_symbols,
        codec: codec.clone(),
        mapping: full.mapping,
        language,
        rendered_text,
        score: full.score,
        heldout_mapping_score,
        null_mean,
        beats_null: full.score >= null_mean + SEARCH_BEATS_NULL_MARGIN,
    }))
}

/// Held-out mapping gate for the searched case: search a mapping on a CONTIGUOUS
/// train fold (the first half), then score it on the disjoint second-half fold.
///
/// The split is contiguous, not alternating, so each fold keeps its bigram
/// adjacency — an alternating split would shred the very structure the bigram
/// model reads, pinning even a correct mapping at chance. An at-chance or negative
/// held-out score means the searched mapping overfit the train fold rather than
/// decoding anything — the mapping-layer analogue of the cipher round-trip, which
/// cannot validate a many-to-one (non-invertible) map.
fn heldout_search_score(
    symbols: &[usize],
    cipher_alphabet_size: usize,
    model: &LanguageModel,
    search: &MappingSearch,
    seed: u64,
) -> Result<f64, SolveError> {
    let midpoint = symbols.len() / 2;
    let (train, heldout) = symbols.split_at(midpoint);
    if train.len() < 2 || heldout.len() < 2 {
        // Too short to split; fall back to scoring the full searched mapping.
        let full = search_mapping(symbols, cipher_alphabet_size, model, search, seed)?;
        return Ok(full.score);
    }
    let trained = search_mapping(train, cipher_alphabet_size, model, search, seed)?;
    let mapped_heldout = apply_table(trained.mapping.table(), heldout)?;
    Ok(model
        .score_indices(&mapped_heldout)?
        .bigram_mean_log_likelihood)
}

/// Reruns the IDENTICAL search on `null_trials` Fisher-Yates-shuffled copies of
/// the ciphertext and returns the mean best-per-family in-sample score.
///
/// Same seed-tag discipline as the fixed-mapping null (`mix_seed(seed, tag ^
/// 0x6e75_6c6c)`), so the searched null is calibrated identically. A search on
/// shuffled symbols still fits noise, which is exactly why
/// [`SEARCH_BEATS_NULL_MARGIN`] guards [`Candidate::beats_null`].
fn matched_null_search_mean(
    req: &SolveRequest<'_>,
    family: &CipherFamilySpec,
    language: Language,
    search: &MappingSearch,
    codec: &AnyCodec,
) -> Result<f64, SolveError> {
    let model = model_for(req, language);
    let shuffle_seed = mix_seed(req.space.seed, family_seed_tag(family) ^ 0x6e75_6c6c);
    let mut rng = SplitMix64::new(shuffle_seed);
    let mut total = 0.0;
    for trial in 0..req.space.null_trials {
        let mut shuffled = req.ciphertext.to_vec();
        fisher_yates(&mut shuffled, &mut rng)?;
        let trial_seed = search_seed(search.seed, family, trial, language);
        total += best_family_search_score(
            &shuffled,
            family,
            req.space.cipher_alphabet_size,
            model,
            search,
            trial_seed,
            codec,
        )?;
    }
    Ok(total / req.space.null_trials as f64)
}

#[allow(
    clippy::too_many_arguments,
    reason = "Phase-1 codec wiring adds one codec parameter to the existing search path"
)]
pub(super) fn best_family_search_score(
    ciphertext: &[Glyph],
    family: &CipherFamilySpec,
    cipher_alphabet_size: usize,
    model: &LanguageModel,
    search: &MappingSearch,
    seed: u64,
    codec: &AnyCodec,
) -> Result<f64, SolveError> {
    let mut best = None;
    let mapping_domain = resolved_output_alphabet_size(codec, cipher_alphabet_size);
    for (cipher_index, cipher) in family.ciphers.iter().enumerate() {
        let Some(decrypted_symbols) = decrypt_round_trip(cipher, ciphertext)? else {
            continue;
        };
        let transduced = codec.transduce(&decrypted_symbols)?;
        let symbols = to_symbol_indices(&transduced, mapping_domain)?;
        let cipher_seed = mix_seed(seed, cipher_index as u64);
        let outcome = search_mapping(&symbols, mapping_domain, model, search, cipher_seed)?;
        if best.is_none_or(|previous| outcome.score > previous) {
            best = Some(outcome.score);
        }
    }
    best.ok_or(SolveError::EmptyHypothesisSpace)
}

/// Hill-climbs (or anneals) a symbol→letter mapping maximizing the in-sample
/// bigram mean log-likelihood of `symbols` under `model`, with multi-restart.
fn search_mapping(
    symbols: &[usize],
    cipher_alphabet_size: usize,
    model: &LanguageModel,
    cfg: &MappingSearch,
    seed: u64,
) -> Result<MappingSearchOutcome, SolveError> {
    let language_size = model.alphabet().len();
    // When the cipher alphabet fits the language alphabet a substitution is
    // injective, so the search is constrained to bijections (swap / relabel-to-
    // unused). An unconstrained many-to-one search would collapse the alphabet
    // onto a few high-probability letters and beat the model on pure noise; the
    // injective constraint keeps the in-sample objective honest. A larger cipher
    // alphabet (the 83→29 eyes) forces many-to-one, where the degeneracy is
    // symmetric with the matched null and the honest negative still holds.
    let injective = cipher_alphabet_size <= language_size;
    let ranked_letters = language_frequency_rank(model)?;
    let symbol_order = symbol_frequency_order(symbols, cipher_alphabet_size);
    let restarts = cfg.restarts.max(1);
    let mut rng = SplitMix64::new(seed);
    let mut best: Option<MappingSearchOutcome> = None;
    let mut buffer = Vec::with_capacity(symbols.len());

    for restart in 0..restarts {
        let mut table = initial_table(
            restart,
            &symbol_order,
            &ranked_letters,
            cipher_alphabet_size,
            language_size,
            &mut rng,
        )?;
        let mut current = score_table(&table, symbols, model, &mut buffer)?;
        for iteration in 0..cfg.iterations {
            let temperature = temperature_at(cfg.anneal, iteration, cfg.iterations);
            let proposal = propose(
                &mut table,
                cipher_alphabet_size,
                language_size,
                injective,
                &mut rng,
            )?;
            let proposed = score_table(&table, symbols, model, &mut buffer)?;
            let delta = proposed - current;
            if accept(delta, temperature, &mut rng) {
                current = proposed;
            } else {
                undo_proposal(&mut table, &proposal);
            }
        }
        if best
            .as_ref()
            .is_none_or(|previous| current > previous.score)
        {
            best = Some(MappingSearchOutcome {
                mapping: Mapping::from_table(table),
                score: current,
            });
        }
    }
    best.ok_or(SolveError::EmptyHypothesisSpace)
}

/// Scores a mapping `table` over the `symbols` stream (reusing `buffer` to avoid
/// per-iteration allocation in the search hot loop).
fn score_table(
    table: &[usize],
    symbols: &[usize],
    model: &LanguageModel,
    buffer: &mut Vec<usize>,
) -> Result<f64, SolveError> {
    let mapped = apply_table_into(table, symbols, buffer)?;
    Ok(model.score_indices(mapped)?.bigram_mean_log_likelihood)
}

fn apply_table_into<'b>(
    table: &[usize],
    symbols: &[usize],
    buffer: &'b mut Vec<usize>,
) -> Result<&'b [usize], SolveError> {
    buffer.clear();
    for &symbol in symbols {
        let &letter = table
            .get(symbol)
            .ok_or(SolveError::MappingSymbolOutsideTable {
                symbol,
                table_len: table.len(),
            })?;
        buffer.push(letter);
    }
    Ok(buffer)
}

fn apply_table(table: &[usize], symbols: &[usize]) -> Result<Vec<usize>, SolveError> {
    let mut buffer = Vec::with_capacity(symbols.len());
    let _slice = apply_table_into(table, symbols, &mut buffer)?;
    Ok(buffer)
}

/// Builds the initial mapping table for a restart. Restart `0` uses a
/// frequency-rank alignment (most-frequent cipher symbol → most-frequent target
/// letter); later restarts perturb that alignment with random swaps to escape its
/// basin while keeping a sensible target multiset.
fn initial_table(
    restart: usize,
    symbol_order: &[usize],
    ranked_letters: &[usize],
    cipher_alphabet_size: usize,
    language_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, SolveError> {
    let mut table = vec![0usize; cipher_alphabet_size];
    for (rank, &symbol) in symbol_order.iter().enumerate() {
        let letter = ranked_letters
            .get(rank % language_size.max(1))
            .copied()
            .unwrap_or(0);
        if let Some(slot) = table.get_mut(symbol) {
            *slot = letter;
        }
    }
    if restart > 0 && cipher_alphabet_size >= 2 {
        for _swap in 0..cipher_alphabet_size {
            let a = crate::null::random_index_below(cipher_alphabet_size, rng)?;
            let b = crate::null::random_index_below(cipher_alphabet_size, rng)?;
            table.swap(a, b);
        }
    }
    Ok(table)
}

/// Proposes a reversible move.
///
/// In the **injective** (substitution) regime moves preserve a bijection: a swap
/// of two symbols' targets, or — when the language alphabet is wider than the
/// cipher alphabet — a relabel of one symbol to a currently-unused letter. In the
/// **many-to-one** regime (the eyes) ~20% of moves repoint a symbol to any letter
/// and ~80% swap, reaching mappings no bijection can express.
fn propose(
    table: &mut [usize],
    cipher_alphabet_size: usize,
    language_size: usize,
    injective: bool,
    rng: &mut SplitMix64,
) -> Result<Proposal, SolveError> {
    if cipher_alphabet_size < 2 {
        let target = crate::null::random_index_below(language_size.max(1), rng)?;
        let old = table.first().copied().unwrap_or(0);
        if let Some(slot) = table.first_mut() {
            *slot = target;
        }
        return Ok(Proposal::Repoint { symbol: 0, old });
    }
    if injective {
        let unused =
            (language_size > cipher_alphabet_size).then(|| unused_letters(table, language_size));
        let relabel =
            unused.as_ref().is_some_and(|set| !set.is_empty()) && rng.next_u64().is_multiple_of(2);
        if let (true, Some(set)) = (relabel, unused.as_ref()) {
            let pick = crate::null::random_index_below(set.len(), rng)?;
            let target = set.get(pick).copied().unwrap_or(0);
            let symbol = crate::null::random_index_below(cipher_alphabet_size, rng)?;
            let old = table.get(symbol).copied().unwrap_or(0);
            if let Some(slot) = table.get_mut(symbol) {
                *slot = target;
            }
            return Ok(Proposal::Repoint { symbol, old });
        }
        return swap_targets(table, cipher_alphabet_size, rng);
    }
    if rng.next_u64().is_multiple_of(5) {
        let symbol = crate::null::random_index_below(cipher_alphabet_size, rng)?;
        let target = crate::null::random_index_below(language_size.max(1), rng)?;
        let old = table.get(symbol).copied().unwrap_or(0);
        if let Some(slot) = table.get_mut(symbol) {
            *slot = target;
        }
        return Ok(Proposal::Repoint { symbol, old });
    }
    swap_targets(table, cipher_alphabet_size, rng)
}

fn swap_targets(
    table: &mut [usize],
    cipher_alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Proposal, SolveError> {
    let a = crate::null::random_index_below(cipher_alphabet_size, rng)?;
    let mut b = crate::null::random_index_below(cipher_alphabet_size, rng)?;
    if a == b {
        b = (b + 1) % cipher_alphabet_size;
    }
    table.swap(a, b);
    Ok(Proposal::Swap { a, b })
}

/// Returns the language letters not currently used as any symbol's target.
fn unused_letters(table: &[usize], language_size: usize) -> Vec<usize> {
    let mut used = vec![false; language_size];
    for &letter in table {
        if let Some(slot) = used.get_mut(letter) {
            *slot = true;
        }
    }
    (0..language_size)
        .filter(|letter| !used.get(*letter).copied().unwrap_or(true))
        .collect()
}

fn undo_proposal(table: &mut [usize], proposal: &Proposal) {
    match *proposal {
        Proposal::Repoint { symbol, old } => {
            if let Some(slot) = table.get_mut(symbol) {
                *slot = old;
            }
        }
        Proposal::Swap { a, b } => table.swap(a, b),
    }
}

/// Metropolis acceptance: always accept a non-worsening move; accept a worsening
/// move of size `delta < 0` with probability `exp(delta / temperature)`. At
/// temperature `0` (pure hill-climb) a worsening move is always rejected.
fn accept(delta: f64, temperature: f64, rng: &mut SplitMix64) -> bool {
    if delta >= 0.0 {
        return true;
    }
    if temperature <= 0.0 {
        return false;
    }
    let uniform = (rng.next_u64() >> 11) as f64 / ((1u64 << 53) as f64);
    (delta / temperature).exp() > uniform
}

fn temperature_at(anneal: Option<AnnealSchedule>, iteration: usize, iterations: usize) -> f64 {
    let Some(schedule) = anneal else {
        return 0.0;
    };
    if iterations <= 1 {
        return schedule.start_temperature.max(0.0);
    }
    let progress = iteration as f64 / (iterations - 1) as f64;
    let temperature = schedule.start_temperature
        + (schedule.end_temperature - schedule.start_temperature) * progress;
    temperature.max(0.0)
}

/// Ranks language indices by descending unigram log-likelihood (most-frequent
/// first), using only the public scorer (no private field access).
fn language_frequency_rank(model: &LanguageModel) -> Result<Vec<usize>, SolveError> {
    let size = model.alphabet().len();
    let mut scored = Vec::with_capacity(size);
    for index in 0..size {
        let log_likelihood = model.score_indices(&[index])?.unigram_mean_log_likelihood;
        scored.push((index, log_likelihood));
    }
    scored.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    Ok(scored.into_iter().map(|(index, _)| index).collect())
}

/// Orders cipher symbols by descending occurrence count in `symbols`.
fn symbol_frequency_order(symbols: &[usize], cipher_alphabet_size: usize) -> Vec<usize> {
    let mut counts = vec![0usize; cipher_alphabet_size];
    for &symbol in symbols {
        if let Some(count) = counts.get_mut(symbol) {
            *count += 1;
        }
    }
    let mut order = (0..cipher_alphabet_size).collect::<Vec<_>>();
    order.sort_by(|&left, &right| {
        counts
            .get(right)
            .copied()
            .unwrap_or(0)
            .cmp(&counts.get(left).copied().unwrap_or(0))
            .then_with(|| left.cmp(&right))
    });
    order
}

fn to_symbol_indices(
    symbols: &[Glyph],
    cipher_alphabet_size: usize,
) -> Result<Vec<usize>, SolveError> {
    let mut indices = Vec::with_capacity(symbols.len());
    for glyph in symbols {
        let symbol = usize::from(glyph.0);
        if symbol >= cipher_alphabet_size {
            return Err(SolveError::CiphertextSymbolOutsideAlphabet {
                symbol,
                alphabet_size: cipher_alphabet_size,
            });
        }
        indices.push(symbol);
    }
    Ok(indices)
}

pub(super) fn search_seed(
    base: u64,
    family: &CipherFamilySpec,
    cipher_index: usize,
    language: Language,
) -> u64 {
    let family_tag = family_seed_tag(family) ^ language_tag(language);
    mix_seed(base, mix_seed(family_tag, cipher_index as u64))
}

fn language_tag(language: Language) -> u64 {
    match language {
        Language::Finnish => 0xf1_f1_f1_f1_f1_f1_f1_f1,
        Language::English => 0xe9_e9_e9_e9_e9_e9_e9_e9,
    }
}
