# 02 - known-plaintext unknown-base recovery, `s = 1`

**Status:** built 2026-07-07 on branch
`agent/gak-unknown-base-recovery-01`.

## Scope

This is the second rung of `gak-unknown-base-recovery/`: a small exhaustive
known-plaintext solver for hidden-base top-card-swap keys with swap budget
`s = 1`.

It is not an eyes run and it does not score language. It consumes
known plaintext/ciphertext pairs and accepts a candidate only when the recovered
mapping re-encrypts the known ciphertext exactly.

## Exact Cipher Convention

The solver uses the same Lymm deck convention as task 01 and
`gak-swap-recover`.

```text
compose(p1, p2)[i] = p2[p1[i]]
state = compose(perm(L), state)
emit  ct_alphabet[state[0]]
perm(L) = B o (0,k_L)
```

Each message starts from identity. The ciphertext in `KnownPlaintextPair` is the
compressed emission stream: one ciphertext symbol per plaintext-alphabet event.

## Landed API and Instrument

Library API:

- `HiddenBaseS1SolverConfig`
- `HiddenBaseS1GeneratorFamily`
- `HiddenBaseS1RecoveryState`
- `HiddenBaseS1RecoveredKey`
- `HiddenBaseS1RecoveryReport`
- `recover_hidden_base_s1_known_plaintext`
- `recover_hidden_base_s1_known_plaintext_with_audit`

The primary solver API takes known plaintext/ciphertext pairs, deck size,
plaintext/ciphertext alphabets, the top-card-swap generator family, and `s = 1`.
It does not take `B` or the planted per-letter mapping. The `_with_audit` wrapper
uses an optional planted base only after the no-base search, to classify
synthetic controls.

Recovery states are explicit:

- `RecoveredPlantedBase`
- `RecoveredEquivalentKey`
- `AmbiguousEquivalentClass`
- `NoCandidate`
- `SearchCapExceeded`

CLI/report instrument:

```sh
cargo run --locked --bin noita-eye -- gak-hidden-base-s1-recover \
  --n 7 \
  --messages 8 \
  --message-len 48 \
  --trials 8
```

The CLI plants synthetic hidden-base `s=1` fixtures, runs the no-base solver,
and reports states, exact candidate counts, tested base counts versus `n!`, wall
time, and the representative hidden-base audit.

## Algorithm

This rung deliberately stays exhaustive over candidate bases.

For each candidate base `B` in lexicographic order:

1. Start every message from the identity state.
2. For each plaintext event with target ciphertext value `c`, derive the only
   possible top-swap index for a first-seen letter:

   ```text
   state[B[k]] = c
   k = B^-1[state^-1[c]]
   ```

3. Reuse the same `k_L` on later occurrences of that plaintext letter.
4. Reject the base immediately if a later occurrence requires a different
   `k_L` or emits the wrong top card.
5. Fill unobserved letters with the identity top swap for the final mapping.
6. Accept only if exact compressed re-encryption of all pairs succeeds.
7. Feed the representative exact mapping into `audit_hidden_base_mapping` for
   planted/equivalent/ambiguous classification.

So the per-letter domain is size `n`, but for fixed `B` and `s=1` the replay
derives at most one consistent `k_L` per observed letter. The remaining cost is
the explicit hidden-base enumeration, measured against `n!`.

## Controls

The library tests reuse the task-01 fixture/audit surface and add solver-specific
positive and matched-null checks:

| control | expected | measured outcome |
| --- | --- | --- |
| planted `s=1` positive | `RecoveredPlantedBase` | exact candidate count `1`, planted base recovered |
| ciphertext-label-shuffle null | `NoCandidate` | exhaustive `n=7` search found `0` exact candidates |
| over-budget `s=2` fixture attacked as `s=1` | `NoCandidate` | exhaustive `n=7` search found `0` exact candidates |
| underspecified one-symbol fixture | `AmbiguousEquivalentClass` | all `5!` bases exact; representative audit has an equivalent base class |
| capped `n=7` positive | `SearchCapExceeded` | stops at the requested base cap |

Focused test command:

```sh
cargo test --locked hidden_base_s1_solver -- --nocapture
```

CLI controls on the default `n=7` surface:

```text
hidden-base s1 controls: PASS
  planted-positive: PASS expected=recovered-planted-base observed=recovered-planted-base exact-candidates=1 tested=5040
  ciphertext-label-shuffle-null: PASS expected=no-candidate observed=no-candidate exact-candidates=0 tested=5040
  over-budget-key-null: PASS expected=no-candidate observed=no-candidate exact-candidates=0 tested=5040
```

## Measured Results

These are synthetic known-plaintext fixtures. They are model-conditional
measurements, not claims about the real eyes.

| command shape | state summary | base candidates vs `n!` | exact candidates | wall time |
| --- | --- | ---: | ---: | ---: |
| `n=7, messages=8, len=48, trials=8` | `8/8` `RecoveredPlantedBase` | `5040/5040` per trial | `1` per trial | total `39.588 ms`; trial 0 `4.967 ms` |
| `n=8, messages=8, len=48, trials=4` | `4/4` `RecoveredPlantedBase` | `40320/40320` per trial | `1` per trial | total `155.390 ms`; trial 0 `38.548 ms` |
| `n=5, pt=A, messages=1, len=1, trials=1` | `AmbiguousEquivalentClass` | `120/120` | `120` | total `533 us` |
| `n=11, messages=8, len=48, trials=1, cap=10000` | `SearchCapExceeded` | `10000/39916800` | cap-limited `0` | `9.853 ms` |

Interpretation:

- On the random full-signal `n=7` and `n=8` fixtures, the planted base is
  uniquely recovered and the representative audit reports one compatible base.
- With only one observed symbol, exact re-encryption is massively
  non-identifying: every base is an exact candidate for some one-letter mapping.
- The first exhaustive rung is intentionally small. The `n=11` cap result is a
  limit measurement, not a negative solve.

## Limits

- This is still factorial in the hidden base. It is useful as a correctness
  baseline and identifiability surface, not as a scalable method for `n=83`.
- `RecoveredEquivalentKey` is distinct from `RecoveredPlantedBase`; an exact
  re-encrypting key is not automatically a planted-base recovery.
- Unobserved letters are filled with an identity perturbation only to satisfy the
  complete-mapping encryption API. They are not recovered from data.
- The solver supports only the top-card-swap family at `s=1`.
- No eyes corpus and no language-scored ciphertext-only attack was run.

## Next Rung (completed)

Task 03 used this exact-acceptance baseline to build and calibrate a
base-marginalized substitution-first method for `s=2..3`; see
[`03-base-marginalized-local-search.md`](03-base-marginalized-local-search.md).
It preserves the distinction between planted-base recovery, equivalent exact
keys, ambiguity, and search limits.
