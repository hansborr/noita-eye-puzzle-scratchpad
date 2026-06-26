//! Thread G1 — known-answer validation of the GAK recovery machinery against
//! **externally-sourced** practice puzzles whose structure is known.
//!
//! Until this module, [`solve_gctak`](crate::gak_attack::solver::solve_gctak)'s
//! only positive controls were the *synthetic* fixtures in
//! [`super::generator`], whose ground truth the generator itself produced — the
//! weakest form of validation. The practice corpus
//! (`research/data/practice-puzzles/`) contains two samples the maintainer
//! gathered externally that are GAK-family ciphers, so they are the first
//! **non-self-generated** known-answer targets for the recovery path:
//!
//! - **`one`** — a `±1` walk on `C5`, i.e. a *cyclic GCTAK* (trivial hidden
//!   subgroup, bijective readout). Ground truth: the state group is `C5`, the two
//!   plaintext "letters" are the `+1` and `-1` generators, and the keystream is the
//!   sequence of `±1` steps. The solver should recover both generators and the
//!   exact step partition. (Per the practice-puzzle README this carries **no
//!   readable English message**; the deliverable is the recovered C5 structure, not
//!   a decode.)
//! - **`two`** — a 12-symbol GAK *with hidden state* (the visible readout is
//!   many-valued: every symbol has out-degree 8). GCTAK's bijective-readout
//!   assumption does not hold, so `solve_gctak` is expected to **fail** — a
//!   legitimate, reported negative that pins where recovery dies.
//!
//! Honesty discipline (binding): the `one` positive control is paired with a
//! matched within-message shuffle null (the recovery must be the *cipher
//! structure*, not the solver always emitting two classes); `two`'s failure is
//! reported as a structural obstruction, never forced into a positive.

use crate::gak_attack::solver::solve_gctak;
use crate::null::{SplitMix64, fisher_yates};
use crate::trigram::TrigramValue;
use std::collections::{BTreeMap, BTreeSet};

/// A recovered ciphertext-alphabet permutation as a `prev -> next` edge map
/// (mirrors the solver's `EdgeMap`).
type Perm = BTreeMap<u8, u8>;

/// Parses a single-line digit/letter puzzle into ciphertext symbol values by
/// position in `alphabet` (characters outside the alphabet, e.g. newlines, are
/// dropped).
fn parse(text: &str, alphabet: &str) -> Vec<TrigramValue> {
    let index: BTreeMap<char, u8> = alphabet
        .chars()
        .enumerate()
        .map(|(i, c)| (c, u8::try_from(i).expect("alphabet under 256 symbols")))
        .collect();
    text.chars()
        .filter_map(|c| index.get(&c).copied())
        .map(|v| TrigramValue::new(v).expect("symbol within base-5 trigram range"))
        .collect()
}

/// Canonicalizes a letter stream by first-occurrence order (so two streams are
/// equal iff they induce the same *partition* of positions into letters).
fn canonical(letters: &[usize]) -> Vec<usize> {
    let mut remap: BTreeMap<usize, usize> = BTreeMap::new();
    let mut next = 0usize;
    letters
        .iter()
        .map(|&letter| {
            *remap.entry(letter).or_insert_with(|| {
                let assigned = next;
                next = next.saturating_add(1);
                assigned
            })
        })
        .collect()
}

/// The `C5` cyclic-shift permutation `i -> (i + step) mod 5` (a ground-truth GCTAK
/// generator for puzzle `one`).
fn c5_cycle(step: u8) -> Perm {
    (0u8..5).map(|i| (i, (i + step) % 5)).collect()
}

/// The ground-truth `±1` step sequence of a `C5` walk: `1` for `+1`, `4` for `-1`.
fn one_steps(vals: &[TrigramValue]) -> Vec<usize> {
    let mut steps = Vec::new();
    for pair in vals.windows(2) {
        if let [a, b] = pair {
            let delta = (i32::from(b.get()) - i32::from(a.get())).rem_euclid(5);
            steps.push(usize::try_from(delta).expect("non-negative residue"));
        }
    }
    steps
}

/// The set of distinct recovered permutations, order-independent.
fn distinct_perms(perms: &[Perm]) -> BTreeSet<Perm> {
    perms.iter().cloned().collect()
}

// =====================================================================
// `one` — cyclic GCTAK on C5: the positive control (must FIRE).
// =====================================================================

/// `solve_gctak` recovers the full `C5` cyclic-GCTAK keystream of puzzle `one`:
/// both ground-truth generators (`+1` and `-1` cycles), a clean decode of every
/// transition, and a recovered plaintext partition that **exactly** equals the
/// ground-truth `±1`-step partition.
///
/// This is the GAK machinery's first known-answer external positive control.
#[test]
fn one_recovers_c5_cyclic_gctak_keystream() {
    let vals = parse(
        include_str!("../../../research/data/practice-puzzles/one"),
        "01234",
    );
    assert_eq!(vals.len(), 266, "puzzle one is 266 symbols");

    // Ground truth: a pure ±1 walk on C5 (every transition is +1 or -1 mod 5).
    let steps = one_steps(&vals);
    assert_eq!(steps.len(), 265);
    assert!(
        steps.iter().all(|&d| d == 1 || d == 4),
        "every C5 transition must be +1 or -1"
    );
    assert_eq!(steps.iter().filter(|&&d| d == 1).count(), 125, "+1 steps");
    assert_eq!(steps.iter().filter(|&&d| d == 4).count(), 140, "-1 steps");
    let truth_partition = canonical(&steps);

    let first = vals.first().expect("non-empty").get();
    // A GENUINE C5 predecessor as the entry state, so the prepended transition is a
    // real +1 edge rather than a self-loop. This is the faithful analogue of the
    // gate's key-derived `initial_state_readout` (it only affects the dropped first
    // transition); choosing a self-loop entry instead injects a spurious fixed-point
    // permutation into the recovery, which is a driver artifact, not a solver bug.
    let initial = TrigramValue::new((first + 4) % 5).expect("C5 residue");
    let plus = c5_cycle(1);
    let minus = c5_cycle(4);

    for phrase_len in [4usize, 6, 8] {
        let solution = solve_gctak(&vals, initial, phrase_len, 5);
        let perms = &solution.recovered_permutations;

        // Both ground-truth generators are recovered...
        assert!(
            perms.contains(&plus),
            "phrase_len={phrase_len}: recovered set must contain the +1 generator"
        );
        assert!(
            perms.contains(&minus),
            "phrase_len={phrase_len}: recovered set must contain the -1 generator"
        );
        // ...and they are the ONLY distinct permutations recovered (a clean C5
        // recovery: the two cyclic-shift generators, nothing spurious).
        let distinct = distinct_perms(perms);
        assert_eq!(
            distinct,
            BTreeSet::from([plus.clone(), minus.clone()]),
            "phrase_len={phrase_len}: distinct recovered perms must be exactly {{+1, -1}}"
        );

        // Every real transition decodes onto a recovered permutation (no sentinels).
        let tail: Vec<usize> = solution.canonical_letters.iter().skip(1).copied().collect();
        assert_eq!(tail.len(), 265);
        assert!(
            tail.iter().all(|&letter| letter < perms.len()),
            "phrase_len={phrase_len}: every transition must decode onto a recovered permutation"
        );

        // The recovered plaintext partition exactly matches the ±1 keystream.
        assert_eq!(
            canonical(&tail),
            truth_partition,
            "phrase_len={phrase_len}: recovered partition must equal the ±1 step partition"
        );
    }
}

/// Matched negative control for `one`: a within-message multiset shuffle destroys
/// the `C5` Cayley structure, so the *same* pipeline never reproduces the
/// ground-truth `±1` partition. This proves the recovery above is the cipher
/// structure, not an artifact of the solver always emitting two classes.
#[test]
fn one_matched_null_does_not_recover() {
    let vals = parse(
        include_str!("../../../research/data/practice-puzzles/one"),
        "01234",
    );
    let truth_partition = canonical(&one_steps(&vals));
    let first = vals.first().expect("non-empty").get();
    let initial = TrigramValue::new((first + 4) % 5).expect("C5 residue");

    let mut reproductions = 0usize;
    let trials = 12usize;
    for seed in 0..trials {
        let mut shuffled = vals.clone();
        let mut rng =
            SplitMix64::new(u64::try_from(seed).expect("small seed") ^ 0x6f6e_655f_6e75_6c6c);
        fisher_yates(&mut shuffled, &mut rng).expect("non-empty shuffle");
        let solution = solve_gctak(&shuffled, initial, 6, 5);
        let tail: Vec<usize> = solution.canonical_letters.iter().skip(1).copied().collect();
        if canonical(&tail) == truth_partition {
            reproductions = reproductions.saturating_add(1);
        }
    }
    assert_eq!(
        reproductions, 0,
        "matched shuffle null reproduced the ±1 partition {reproductions}/{trials} times; recovery would be vacuous"
    );
}

// =====================================================================
// `two` — REAL GAK with hidden state: an honest negative (recovery DIES).
// =====================================================================

/// Replicates the solver's per-column seed clustering for a window length and
/// returns `(aligned_occurrences, seed_columns, functional_columns,
/// max_functional_partial)`.
///
/// A seed column is FORWARD-FUNCTIONAL when, across all aligned occurrences of the
/// largest equality-pattern phrase, each `prev` symbol maps to a single `next`
/// symbol. For a true GCTAK (bijective readout) every aligned column is one fixed
/// letter, so columns are functional and complete to the group order. For a GAK
/// with hidden state the visible readout is many-valued, so the columns conflict —
/// this is exactly the obstruction the count exposes.
fn column_diag(walk: &[TrigramValue], window_len: usize) -> (usize, usize, usize, usize) {
    use crate::isomorph::PatternSignature;
    let mut by_signature: BTreeMap<Vec<usize>, Vec<usize>> = BTreeMap::new();
    for (start, window) in walk.windows(window_len).enumerate() {
        let signature = PatternSignature::from_window(window);
        if signature.has_repeated_symbol() {
            by_signature
                .entry(signature.values().to_vec())
                .or_default()
                .push(start);
        }
    }
    let Some(starts) = by_signature.into_values().max_by_key(Vec::len) else {
        return (0, 0, 0, 0);
    };
    if starts.len() < 2 {
        return (0, 0, 0, 0);
    }
    // Spacing filter (>= window_len apart), mirroring `aligned_phrase_starts`.
    let mut filtered: Vec<usize> = Vec::new();
    let mut last: Option<usize> = None;
    for &start in &starts {
        if last.is_none_or(|prev| start >= prev.saturating_add(window_len)) {
            filtered.push(start);
            last = Some(start);
        }
    }

    let mut functional = 0usize;
    let mut max_partial = 0usize;
    for col in 1..window_len {
        let mut map: Perm = BTreeMap::new();
        let mut ok = true;
        for &start in &filtered {
            let transition = start.saturating_add(col).saturating_sub(1);
            let (Some(prev), Some(next)) =
                (walk.get(transition), walk.get(transition.saturating_add(1)))
            else {
                continue;
            };
            match map.get(&prev.get()) {
                Some(existing) if *existing != next.get() => {
                    ok = false;
                    break;
                }
                _ => {
                    let _old = map.insert(prev.get(), next.get());
                }
            }
        }
        if ok {
            functional = functional.saturating_add(1);
            max_partial = max_partial.max(map.len());
        }
    }
    (
        filtered.len(),
        window_len.saturating_sub(1),
        functional,
        max_partial,
    )
}

/// `two` is a real GAK with hidden state, so `solve_gctak` (a GCTAK solver) cannot
/// recover it. This records the honest negative AND pins exactly where it dies: the
/// visible readout is many-valued (out-degree 8 on 12 symbols), so the per-column
/// seed clusters are non-functional and are dropped before any per-letter
/// permutation can be built — recovery returns zero complete permutations at every
/// plausible state-group order.
#[test]
fn two_real_gak_dies_at_seeding_honest_negative() {
    let vals = parse(
        include_str!("../../../research/data/practice-puzzles/two"),
        "ABCDEFGHIJKL",
    );
    assert_eq!(vals.len(), 698, "puzzle two is 698 symbols");

    // The hidden-state signature: every symbol has out-degree exactly 8 (a clean
    // GCTAK would have out-degree = number of letters and each edge a single
    // letter).
    let mut out: BTreeMap<u8, BTreeSet<u8>> = BTreeMap::new();
    for pair in vals.windows(2) {
        if let [a, b] = pair {
            let _inserted = out.entry(a.get()).or_default().insert(b.get());
        }
    }
    assert_eq!(out.len(), 12, "two uses all 12 symbols");
    assert!(
        out.values().all(|successors| successors.len() == 8),
        "every symbol has out-degree 8 (the hidden-state, many-valued readout)"
    );

    // No complete permutation is recovered at any plausible state-group order.
    let first = vals.first().expect("non-empty").get();
    let initial = TrigramValue::new(first).expect("symbol in range");
    for group_order in [6usize, 8, 11, 12] {
        for phrase_len in [4usize, 6, 8, 10, 12] {
            let solution = solve_gctak(&vals, initial, phrase_len, group_order);
            assert!(
                solution.recovered_permutations.is_empty(),
                "two: solve_gctak unexpectedly recovered {} permutation(s) at order={group_order}, phrase_len={phrase_len}",
                solution.recovered_permutations.len()
            );
        }
    }

    // The death point: per-column seed clusters are non-functional (multivalued).
    let mut walk = vec![initial];
    walk.extend_from_slice(&vals);
    for window_len in [4usize, 6, 8, 10] {
        let (occurrences, columns, functional, _max_partial) = column_diag(&walk, window_len);
        assert!(occurrences >= 2, "window_len={window_len}: a phrase aligns");
        assert!(
            columns > 0,
            "window_len={window_len}: there are seed columns"
        );
        assert_eq!(
            functional, 0,
            "window_len={window_len}: hidden state makes every seed column multivalued, so all clusters are dropped"
        );
    }
}
