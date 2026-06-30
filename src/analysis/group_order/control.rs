//! Synthetic `C3 × H` positive controls and the eps-only matched null that
//! validate the element-order discriminator end to end.
//!
//! The generator simulates the convention-B (post-compose, top-card readout)
//! hidden-state GAK: state `(deck, rotor)`, each letter post-composes a deck
//! permutation drawn from `H` and advances the rotor, and the visible symbol is
//! `deck[0] * rotor_mod + rotor`. A planted repeated phrase reproduced after a
//! connector letter realizes a chosen **context** `g ∈ H` between the two
//! occurrences: the connector is solved analytically so the deck just before the
//! second occurrence equals `g ∘ (deck before the first)`, which makes the
//! induced deck-channel map exactly `g` regardless of the running deck. Driving
//! `g` through representatives of each cycle type, and through `D4`/`A4`/`S4`,
//! lets the self-test assert that the discriminator recovers the planted element
//! orders and reaches the right group verdict — while the eps-only null (a repeat
//! whose second occurrence freezes the deck) must be rejected.

use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

use super::scan::{compose, invert, is_even};
use super::{GroupScanError, GroupScanSelfTest, GroupVerdict, group_scan};

/// Rotor modulus of the synthetic controls (the `C3` factor).
const ROTOR_MOD: usize = 3;
/// Deck size of the synthetic controls (four cards).
const DECK_SIZE: usize = 4;
/// Visible alphabet size of the synthetic controls (`DECK_SIZE * ROTOR_MOD`).
const ALPHABET: usize = DECK_SIZE * ROTOR_MOD;
/// Minimum consistent-prefix length used when scanning the controls. Also the
/// difference-channel anchor threshold, so within-phrase self-repeats shorter
/// than this are never enumerated as anchors.
const SELF_TEST_MIN_ANCHOR: usize = 8;
/// Phrase length of a planted repeated span (longer than `SELF_TEST_MIN_ANCHOR`
/// so the cross-occurrence repeat clears the threshold with margin).
const PHRASE_LEN: usize = 18;

/// The identity permutation of the four cards.
fn identity() -> Vec<usize> {
    (0..DECK_SIZE).collect()
}

/// Closure of `generators` under composition, starting from the identity.
fn group_closure(generators: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let mut elements = vec![identity()];
    let mut changed = true;
    while changed {
        changed = false;
        let snapshot = elements.clone();
        for generator in generators {
            for element in &snapshot {
                let product = compose(generator, element);
                if !elements.contains(&product) {
                    elements.push(product);
                    changed = true;
                }
            }
        }
    }
    elements.sort();
    elements
}

/// The symmetric group `S4` (all 24 permutations of four points).
pub(crate) fn s4() -> Vec<Vec<usize>> {
    group_closure(&[vec![1, 2, 3, 0], vec![1, 0, 2, 3]])
}

/// The alternating group `A4` (the 12 even permutations).
pub(crate) fn a4() -> Vec<Vec<usize>> {
    s4().into_iter().filter(|p| is_even(p)).collect()
}

/// The dihedral group `D4` of order 8 (symmetries of the cycle `0-1-2-3`).
pub(crate) fn d4() -> Vec<Vec<usize>> {
    group_closure(&[vec![1, 2, 3, 0], vec![0, 3, 2, 1]])
}

/// One GAK letter: a rotor increment and a deck permutation (post-composed).
struct Letter {
    eps: usize,
    perm: Vec<usize>,
}

/// A running convention-B GAK simulation that accumulates visible symbols.
struct Sim {
    deck: Vec<usize>,
    rotor: usize,
    symbols: Vec<u16>,
}

impl Sim {
    fn new() -> Self {
        Self {
            deck: identity(),
            rotor: 0,
            symbols: Vec::new(),
        }
    }

    fn emit(&mut self, letter: &Letter) {
        self.rotor = (self.rotor + letter.eps) % ROTOR_MOD;
        self.deck = compose(&self.deck, &letter.perm);
        let top = self.deck.first().copied().unwrap_or(0);
        let symbol = top * ROTOR_MOD + self.rotor;
        self.symbols.push(u16::try_from(symbol).unwrap_or(0));
    }

    fn emit_letters(&mut self, letters: &[Letter]) {
        for letter in letters {
            self.emit(letter);
        }
    }
}

/// Longest substring occurring at two different offsets within `pattern`.
fn longest_self_repeat(pattern: &[usize]) -> usize {
    let n = pattern.len();
    let mut best = 0;
    for i in 0..n {
        for j in (i + 1)..n {
            let mut len = 0;
            while pattern
                .get(i + len)
                .is_some_and(|x| pattern.get(j + len) == Some(x))
            {
                len += 1;
            }
            best = best.max(len);
        }
    }
    best
}

/// A pseudo-random eps pattern (values in `{1,2}`, the two allowed rotor moves)
/// whose longest self-repeat is below `SELF_TEST_MIN_ANCHOR`. The difference
/// channel is binary, so a periodic eps pattern would seed within-phrase
/// self-isomorphisms (read as spurious `stepping^period` contexts); an aperiodic
/// pattern leaves the cross-occurrence repeat as the only enumerated anchor.
fn segment_eps(seed: u64) -> Result<Vec<usize>, GroupScanError> {
    for attempt in 0..128 {
        let mut rng = SplitMix64::new(mix_seed(seed, attempt));
        let mut pattern = Vec::with_capacity(PHRASE_LEN);
        for _ in 0..PHRASE_LEN {
            pattern.push(1 + random_index_below(2, &mut rng)?);
        }
        if longest_self_repeat(&pattern) < SELF_TEST_MIN_ANCHOR {
            return Ok(pattern);
        }
    }
    // Deterministic overlap-free Thue-Morse fallback.
    Ok((0..PHRASE_LEN)
        .map(|k| 1 + (k.count_ones() as usize % 2))
        .collect())
}

/// Distinct top-card values the phrase's running deck visits, simulated from the
/// identity. Coverage is independent of the running deck (a global bijection), so
/// this equals the number of distinct deck-channel sources the phrase exposes.
fn phrase_top_coverage(letters: &[Letter]) -> usize {
    let mut deck = identity();
    let mut seen = [false; DECK_SIZE];
    for letter in letters {
        deck = compose(&deck, &letter.perm);
        if let Some(slot) = deck.first().and_then(|&top| seen.get_mut(top)) {
            *slot = true;
        }
    }
    seen.iter().filter(|s| **s).count()
}

/// Builds a phrase: `PHRASE_LEN` letters with an aperiodic eps pattern and
/// **varying** deck permutations drawn from `group`. Varying perms make the
/// deck-channel walk aperiodic (like real plaintext), so a gap-shifted match of
/// the repeat cannot masquerade as a clean context — only the true alignment
/// recovers a permutation. Redraws until the phrase exposes at least
/// `DECK_SIZE - 1` distinct top-card values (enough to fix a permutation).
fn build_phrase(
    group: &[Vec<usize>],
    eps_seed: u64,
    perm_seed: u64,
) -> Result<Vec<Letter>, GroupScanError> {
    let eps = segment_eps(eps_seed)?;
    for attempt in 0..64 {
        let mut rng = SplitMix64::new(mix_seed(perm_seed, attempt));
        let mut letters = Vec::with_capacity(PHRASE_LEN);
        for &e in &eps {
            let idx = random_index_below(group.len(), &mut rng)?;
            let perm = group.get(idx).cloned().unwrap_or_else(identity);
            letters.push(Letter { eps: e, perm });
        }
        if phrase_top_coverage(&letters) >= DECK_SIZE - 1 {
            return Ok(letters);
        }
    }
    Err(GroupScanError::SelfTestFailed)
}

/// Appends `count` random filler letters drawn from `group` (keeps the deck in
/// `H` and separates planted segments so they do not cross-match).
fn append_filler(
    sim: &mut Sim,
    group: &[Vec<usize>],
    count: usize,
    seed: u64,
) -> Result<(), GroupScanError> {
    let mut rng = SplitMix64::new(seed);
    for _ in 0..count {
        let idx = random_index_below(group.len(), &mut rng)?;
        let perm = group.get(idx).cloned().unwrap_or_else(identity);
        let eps = 1 + random_index_below(2, &mut rng)?;
        sim.emit(&Letter { eps, perm });
    }
    Ok(())
}

/// Appends a `[phrase, connector, phrase]` segment whose two phrase occurrences
/// are related by the context `g`. The connector is solved so the deck just
/// before the second occurrence is `g ∘ (deck before the first)`, which makes the
/// induced deck-channel map exactly `g` regardless of the running deck.
fn append_context_segment(sim: &mut Sim, phrase: &[Letter], g: &[usize]) {
    let deck_before = sim.deck.clone();
    sim.emit_letters(phrase);
    let deck_after = sim.deck.clone();
    let deck_target = compose(g, &deck_before);
    let connector = compose(&invert(&deck_after), &deck_target);
    sim.emit(&Letter {
        eps: 1,
        perm: connector,
    });
    sim.emit_letters(phrase);
}

/// Builds a single-context control stream (one planted context `g`, group `H`).
fn build_single_context_stream(
    group: &[Vec<usize>],
    g: &[usize],
    seed: u64,
) -> Result<Vec<u16>, GroupScanError> {
    let mut sim = Sim::new();
    let phrase = build_phrase(group, mix_seed(seed, 7), mix_seed(seed, 8))?;
    append_filler(&mut sim, group, 6, mix_seed(seed, 1))?;
    append_context_segment(&mut sim, &phrase, g);
    append_filler(&mut sim, group, 6, mix_seed(seed, 2))?;
    Ok(sim.symbols)
}

/// Builds a multi-context control stream (one segment per planted context).
fn build_group_stream(
    group: &[Vec<usize>],
    contexts: &[Vec<usize>],
    seed: u64,
) -> Result<Vec<u16>, GroupScanError> {
    let mut sim = Sim::new();
    for (i, g) in contexts.iter().enumerate() {
        let phrase = build_phrase(
            group,
            mix_seed(seed, i as u64 * 4 + 1),
            mix_seed(seed, i as u64 * 4 + 2),
        )?;
        append_filler(&mut sim, group, 8, mix_seed(seed, i as u64 * 4 + 3))?;
        append_context_segment(&mut sim, &phrase, g);
    }
    append_filler(&mut sim, group, 8, mix_seed(seed, 0xffff))?;
    Ok(sim.symbols)
}

/// Builds the eps-only matched null: a repeat whose second occurrence freezes the
/// deck (identity perms) so the difference-channel anchor exists but the deck
/// channel carries no consistent permutation.
fn build_eps_only_stream(group: &[Vec<usize>], seed: u64) -> Result<Vec<u16>, GroupScanError> {
    let mut sim = Sim::new();
    let phrase = build_phrase(group, mix_seed(seed, 3), mix_seed(seed, 4))?;
    append_filler(&mut sim, group, 6, mix_seed(seed, 1))?;
    // Occurrence A: the deck walks with the phrase's varying permutations.
    sim.emit_letters(&phrase);
    sim.emit(&Letter {
        eps: 1,
        perm: identity(),
    });
    // Occurrence B: same eps pattern (the difference-channel anchor survives) but
    // the deck is frozen (identity perms), so the deck channel carries no
    // consistent permutation — the eps-only repeat the gate must reject.
    let frozen: Vec<Letter> = phrase
        .iter()
        .map(|letter| Letter {
            eps: letter.eps,
            perm: identity(),
        })
        .collect();
    sim.emit_letters(&frozen);
    append_filler(&mut sim, group, 6, mix_seed(seed, 2))?;
    Ok(sim.symbols)
}

/// Scans a control stream with the self-test parameters.
fn scan_control(stream: &[u16], seed: u64) -> Result<super::GroupScanReport, GroupScanError> {
    group_scan(
        stream,
        ALPHABET,
        ROTOR_MOD,
        SELF_TEST_MIN_ANCHOR,
        16,
        64,
        seed,
    )
}

/// Runs the full self-test: cycle-type recovery, the `D4`/`A4`/`S4` group
/// verdicts, and the eps-only matched-null rejection.
pub(crate) fn self_test(seed: u64) -> Result<GroupScanSelfTest, GroupScanError> {
    let s4 = s4();

    // 1. Cycle-type recovery: each representative permutation is recovered exactly.
    let representatives = [
        vec![0, 1, 2, 3], // identity, cycle type 1+1+1+1
        vec![1, 0, 2, 3], // transposition (01), cycle type 2+1+1
        vec![1, 0, 3, 2], // double (01)(23), cycle type 2+2
        vec![1, 2, 0, 3], // 3-cycle (012), cycle type 3+1
        vec![1, 2, 3, 0], // 4-cycle (0123), cycle type 4
    ];
    let mut cycle_recovery_passed = true;
    for (i, g) in representatives.iter().enumerate() {
        let stream = build_single_context_stream(&s4, g, mix_seed(seed, 100 + i as u64))?;
        let report = scan_control(&stream, mix_seed(seed, 200 + i as u64))?;
        let recovered: Vec<Vec<usize>> = report
            .readings
            .iter()
            .filter_map(|reading| reading.permutation.clone())
            .collect();
        let ok = !recovered.is_empty() && recovered.iter().all(|perm| perm == g);
        cycle_recovery_passed = cycle_recovery_passed && ok;
    }

    // 2. Group-level verdicts on planted C3 x {D4, A4, S4} streams.
    let d4_stream = build_group_stream(
        &d4(),
        &[vec![1, 2, 3, 0], vec![2, 3, 0, 1], vec![3, 0, 1, 2]],
        mix_seed(seed, 300),
    )?;
    let d4_report = scan_control(&d4_stream, mix_seed(seed, 301))?;
    let d4_excludes_a4 = matches!(d4_report.verdict, GroupVerdict::ExcludesA4 { .. })
        && d4_report.observed_cycle_lengths.iter().all(|&l| l != 3);

    let a4_stream = build_group_stream(
        &a4(),
        &[vec![1, 2, 0, 3], vec![1, 0, 3, 2], vec![2, 0, 1, 3]],
        mix_seed(seed, 400),
    )?;
    let a4_report = scan_control(&a4_stream, mix_seed(seed, 401))?;
    let a4_excludes_d4 = matches!(a4_report.verdict, GroupVerdict::ExcludesD4 { .. })
        && a4_report.observed_cycle_lengths.iter().all(|&l| l != 4);

    let s4_stream = build_group_stream(
        &s4,
        &[vec![1, 2, 0, 3], vec![1, 2, 3, 0], vec![1, 0, 3, 2]],
        mix_seed(seed, 500),
    )?;
    let s4_report = scan_control(&s4_stream, mix_seed(seed, 501))?;
    let s4_verdict = matches!(s4_report.verdict, GroupVerdict::S4);

    // 3. Eps-only matched null must be rejected (no consistent determined context).
    let null_stream = build_eps_only_stream(&s4, mix_seed(seed, 600))?;
    let null_report = scan_control(&null_stream, mix_seed(seed, 601))?;
    let long_anchor_rejected = null_report.readings.iter().any(|reading| {
        reading.anchor.length >= SELF_TEST_MIN_ANCHOR && reading.permutation.is_none()
    });
    let null_rejected = matches!(null_report.verdict, GroupVerdict::NoDeckSignal)
        && null_report.consistent_contexts == 0
        && null_report.anchors_examined > 0
        && long_anchor_rejected;

    let passed =
        cycle_recovery_passed && d4_excludes_a4 && a4_excludes_d4 && s4_verdict && null_rejected;

    Ok(GroupScanSelfTest {
        cycle_recovery_passed,
        d4_excludes_a4,
        a4_excludes_d4,
        s4_verdict,
        null_rejected,
        passed,
    })
}
