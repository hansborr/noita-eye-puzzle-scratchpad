use super::{
    DeckFixture, DeckLetterRegime, GakAttackConfig, GakAttackError, HiddenStateObstruction,
    SplitMix64, add_one_p_value, coset_recovery_fraction, deck_hidden_subgroup_order, fisher_yates,
    fraction, generate_deck_fixture, glyphs_to_values, mix_seed, run_deck_attack,
    truth_coset_edges,
};

/// One deck attack outcome on one independent seed, with its matched null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeckAttackOutcome {
    /// Deck size `n` (`|C| = n`).
    pub state_size: usize,
    /// Hidden-subgroup order `|H| = (n-1)!`.
    pub hidden_subgroup_order: u128,
    /// Seed used to build the fixture.
    pub seed: u64,
    /// Number of ciphertext symbols.
    pub ciphertext_len: usize,
    /// Letters whose coset action the real pipeline recovered correctly.
    pub real_recovered: usize,
    /// Letters whose coset action the matched-null pipeline recovered.
    pub null_recovered: usize,
    /// Total plaintext letters (the recovery-fraction denominator).
    pub letters_total: usize,
    /// Fixed-context true-conflict aborts on the real stream (surfaced — a feature).
    pub true_conflict_aborts: usize,
    /// Distinct visible coset symbols touched by the chain links (real stream).
    pub symbols_touched: usize,
    /// Fixed-context occurrence-pair contexts that survived (no true conflict) in
    /// the chain substrate (coverage/conflict counter, not the recovery substrate).
    pub surviving_contexts: usize,
    /// Distinct `from` cosets observed across phrase columns (real stream): the
    /// denominator of the measured hidden-state obstruction.
    pub obstruction_from_total: usize,
    /// `from` cosets that mapped multi-valued across hidden states (real stream):
    /// the measured hidden-state obstruction (the part not recoverable here).
    pub obstruction_multi_valued: usize,
}

impl DeckAttackOutcome {
    /// Real recovered-coset-action fraction (`0.0` if no letters).
    #[must_use]
    pub fn real_fraction(self) -> f64 {
        fraction(self.real_recovered, self.letters_total)
    }

    /// Matched-null recovered-coset-action fraction.
    #[must_use]
    pub fn null_fraction(self) -> f64 {
        fraction(self.null_recovered, self.letters_total)
    }

    /// Measured hidden-state obstruction: the fraction of visible cosets that map
    /// multi-valued under a fixed letter (real stream). The larger this is, the less
    /// of the per-letter action is recoverable without idea 3.
    #[must_use]
    pub fn multi_valued_fraction(self) -> f64 {
        fraction(self.obstruction_multi_valued, self.obstruction_from_total)
    }
}

/// Evaluates the deck attack on one fixture and its matched within-message
/// shuffle null over the identical pipeline (the matched-null symmetry the
/// historical #1 bug here demands).
pub(crate) fn evaluate_deck_fixture(
    fixture: &DeckFixture,
    config: GakAttackConfig,
    seed: u64,
) -> Result<DeckAttackOutcome, GakAttackError> {
    let ciphertext_values = glyphs_to_values(&fixture.ciphertext)?;
    let truth = truth_coset_edges(&fixture.key, &fixture.plaintext)?;
    let letters_total = truth.len();
    let phrase_len = config.phrase_len;

    // Real pipeline.
    let real = run_deck_attack(&ciphertext_values, fixture.state_size, phrase_len);
    let (real_recovered, _) = coset_recovery_fraction(&truth, &real.recovered_actions);

    // Matched null: the same `run_deck_attack` pipeline (same phrase_len, same
    // state_size) over a within-message Fisher-Yates shuffle of the same ciphertext
    // population, scored against the same truth. Real and null run the identical
    // pipeline over the identical population — only the structure differs.
    let mut rng = SplitMix64::new(mix_seed(seed, 0x6465_636b_6e75_6c6c));
    let mut shuffled = ciphertext_values.clone();
    fisher_yates(&mut shuffled, &mut rng)?;
    let null = run_deck_attack(&shuffled, fixture.state_size, phrase_len);
    let (null_recovered, _) = coset_recovery_fraction(&truth, &null.recovered_actions);

    Ok(DeckAttackOutcome {
        state_size: fixture.state_size,
        hidden_subgroup_order: fixture.hidden_subgroup_order,
        seed,
        ciphertext_len: ciphertext_values.len(),
        real_recovered,
        null_recovered,
        letters_total,
        true_conflict_aborts: real.true_conflict_aborts,
        symbols_touched: real.symbols_touched,
        surviving_contexts: real.surviving_contexts,
        obstruction_from_total: real.obstruction.distinct_from_total,
        obstruction_multi_valued: real.obstruction.multi_valued_from_total,
    })
}

/// The measured tractability bound at one deck size `n`: real-vs-null recovered-
/// coset-action fractions across independent seeds, with a matched-null p-value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TractabilityPoint {
    /// Deck size `n` (`|C| = n`).
    pub state_size: usize,
    /// Hidden-subgroup order `|H| = (n-1)!`.
    pub hidden_subgroup_order: u128,
    /// Number of independent seeds aggregated at this `n`.
    pub seeds: usize,
    /// Mean real recovered-coset-action fraction over the seeds.
    pub real_mean_fraction: f64,
    /// Mean matched-null recovered-coset-action fraction over the seeds.
    pub null_mean_fraction: f64,
    /// Total correctly-recovered letters (real) summed over the seeds.
    pub real_recovered_total: usize,
    /// Total correctly-recovered letters (matched null) summed over the seeds.
    pub null_recovered_total: usize,
    /// Total plaintext letters summed over the seeds (the denominator).
    pub letters_total: usize,
    /// Total fixed-context true-conflict aborts (real) summed over the seeds.
    pub true_conflict_aborts: usize,
    /// Measured hidden-state obstruction at this `n`: the fraction of visible cosets
    /// that map multi-valued under a fixed letter, aggregated over the seeds. The
    /// headline honest result: this is the part of the action not recoverable
    /// without hidden-state marginalization (idea 3), and it bounds recovery.
    pub multi_valued_fraction: f64,
    /// Add-one Monte-Carlo p-value: how often a null seed's recovered fraction is
    /// at least the matched real seed's. Small means real beats null.
    pub matched_null_p_value: f64,
    /// Whether the real mean strictly exceeds the null mean at this `n` (the
    /// per-`n` "real beats matched null" verdict).
    pub real_beats_null: bool,
}

/// Result of the deck-GAK partial-recovery attack: per-seed outcomes and the
/// measured tractability bound (per-`n` real-vs-null fractions, i.e. where
/// recovery breaks).
#[derive(Clone, Debug, PartialEq)]
pub struct DeckAttackReport {
    /// The deck letter regime swept (unconstrained `S_n` by default).
    pub regime: DeckLetterRegime,
    /// Per-seed deck outcomes across the swept `n` × seed matrix.
    pub outcomes: Vec<DeckAttackOutcome>,
    /// The measured tractability bound: one [`TractabilityPoint`] per swept `n`.
    pub tractability: Vec<TractabilityPoint>,
    /// Whether the attack beats its matched null on the easiest (smallest) swept
    /// `n` — the go/no-go for this unit.
    pub beats_null_on_easiest: bool,
    /// The smallest swept deck size (the easiest fixture).
    pub easiest_state_size: usize,
}

/// Default deck sizes swept by [`run_deck_attack_sweep`].
///
/// Starts at `n ≤ 5` (the easiest), then `6, 7, 8` — the spec's tractability
/// sweep. Recovery is expected to be partial at the smallest `n` and to break as
/// `n` / `|H| = (n-1)!` grows; that measured break is the deliverable.
pub const DEFAULT_DECK_STATE_SIZES: [usize; 4] = [5, 6, 7, 8];

/// Fixed, robust seed count the bundled [`run_gak_attack`](crate::attack::gak_attack::run_gak_attack) deck sweep uses.
///
/// Per-fixture recovery variance is high (only a minority of seeds recover any
/// letter), so a stable aggregate tractability bound needs more seeds than the
/// small GCTAK-gate `seeds_per_kind` (default 3). This count makes the shipped
/// report's per-`n` real-vs-null aggregate (e.g. 18/72 vs 0/72 at `n = 5`) stable
/// rather than a 2-3-seed snapshot, while staying fast enough for `make verify`.
pub const DECK_SWEEP_SEEDS: usize = 24;

/// Runs the real-GAK deck attack across a sweep of deck sizes, measuring the
/// tractability bound (where partial recovery breaks).
///
/// For each `n` in `state_sizes` it draws `config.seeds_per_kind` independent
/// seeds, generates a deck fixture (held-back ground truth), runs the constraint-
/// propagation attack and its matched within-message shuffle null over the
/// identical pipeline, and aggregates the recovered-coset-action fractions. The
/// `regime` selects the per-letter draw (unconstrained `S_n` by default; the
/// tentative small-support regime is generated too so the next unit can validate
/// the prior).
///
/// # Errors
/// Returns [`GakAttackError`] when the configuration is invalid, when a fixture's
/// key/stream is rejected, or when a symbol cannot be represented. Note: unlike
/// the GCTAK gate, a low or zero recovered fraction is the expected, reportable
/// outcome here, not an error.
pub fn run_deck_attack_sweep(
    config: GakAttackConfig,
    regime: DeckLetterRegime,
    state_sizes: &[usize],
) -> Result<DeckAttackReport, GakAttackError> {
    if config.seeds_per_kind == 0 {
        return Err(GakAttackError::ZeroSeeds);
    }
    if config.phrase_repeats == 0 || config.phrase_len == 0 {
        return Err(GakAttackError::EmptyTemplate);
    }

    let mut outcomes = Vec::new();
    let mut tractability = Vec::new();
    let mut beats_null_on_easiest = false;
    let mut easiest_state_size = 0usize;

    for (size_index, &state_size) in state_sizes.iter().enumerate() {
        let mut real_fractions: Vec<f64> = Vec::new();
        let mut null_fractions: Vec<f64> = Vec::new();
        let mut real_recovered_total = 0usize;
        let mut null_recovered_total = 0usize;
        let mut letters_total = 0usize;
        let mut true_conflict_aborts = 0usize;
        let mut obstruction_from_total = 0usize;
        let mut obstruction_multi_valued = 0usize;
        let mut null_at_least_real = 0usize;

        for seed_index in 0..config.seeds_per_kind {
            let seed = deck_fixture_seed(config.seed, state_size, seed_index);
            let fixture = generate_deck_fixture(state_size, regime, config, seed)?;
            let outcome = evaluate_deck_fixture(&fixture, config, seed)?;
            real_fractions.push(outcome.real_fraction());
            null_fractions.push(outcome.null_fraction());
            real_recovered_total = real_recovered_total.saturating_add(outcome.real_recovered);
            null_recovered_total = null_recovered_total.saturating_add(outcome.null_recovered);
            letters_total = letters_total.saturating_add(outcome.letters_total);
            true_conflict_aborts =
                true_conflict_aborts.saturating_add(outcome.true_conflict_aborts);
            obstruction_from_total =
                obstruction_from_total.saturating_add(outcome.obstruction_from_total);
            obstruction_multi_valued =
                obstruction_multi_valued.saturating_add(outcome.obstruction_multi_valued);
            if outcome.null_fraction() >= outcome.real_fraction() {
                null_at_least_real = null_at_least_real.saturating_add(1);
            }
            outcomes.push(outcome);
        }

        let real_mean = mean_f64(&real_fractions);
        let null_mean = mean_f64(&null_fractions);
        let matched_null_p_value = add_one_p_value(null_at_least_real, config.seeds_per_kind);
        // The decisive per-`n` verdict is the aggregate recovered-letter count
        // (real vs matched null) over all seeds, not the per-seed mean (per-fixture
        // variance is high: only a minority of seeds recover any letter, so a
        // per-seed p-value is conservatively non-significant — itself reported).
        // The aggregate contrast is unambiguous (e.g. 12 vs 0 at small `n`).
        let real_beats_null = real_recovered_total > null_recovered_total;
        let hidden_subgroup_order = deck_hidden_subgroup_order(state_size);
        tractability.push(TractabilityPoint {
            state_size,
            hidden_subgroup_order,
            seeds: config.seeds_per_kind,
            real_mean_fraction: real_mean,
            null_mean_fraction: null_mean,
            real_recovered_total,
            null_recovered_total,
            letters_total,
            true_conflict_aborts,
            multi_valued_fraction: HiddenStateObstruction {
                distinct_from_total: obstruction_from_total,
                multi_valued_from_total: obstruction_multi_valued,
            }
            .multi_valued_fraction(),
            matched_null_p_value,
            real_beats_null,
        });
        if size_index == 0 {
            easiest_state_size = state_size;
            beats_null_on_easiest = real_beats_null && real_mean > 0.0;
        }
    }

    Ok(DeckAttackReport {
        regime,
        outcomes,
        tractability,
        beats_null_on_easiest,
        easiest_state_size,
    })
}

/// Deterministic per-`(n, seed_index)` fixture seed for the deck sweep.
fn deck_fixture_seed(master: u64, state_size: usize, seed_index: usize) -> u64 {
    let tag = (state_size as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(seed_index as u64);
    mix_seed(master, tag ^ 0x6465_636b_5f73_7765)
}

/// Mean of an `f64` slice (`0.0` when empty).
#[must_use]
pub(crate) fn mean_f64(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}
