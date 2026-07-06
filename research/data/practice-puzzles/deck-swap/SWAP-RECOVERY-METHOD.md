# Recovering the per-letter swaps in Lymm's deck cipher — a known-plaintext method

*A self-contained technical writeup of a substitution-first coordinate-descent attack
on the GAK "deck / swap" practice puzzles, with an independent byte-for-byte
verification of the recovered keys.*

## The question this answers

The practice puzzles (`1_swap_ct.txt`, `2_swap_ct.txt`, `3_swap_ct.txt`) encrypt the
**same known plaintexts** under 1, 2, and 3 top-card swaps per letter respectively. The
community question was: *given the known plaintext, can we generate a general method
for recovering which swaps map to which letter?* — i.e. recover the key, not just for
1 swap but for the harder `num_swaps = 3` case where the search space explodes.

Short answer: **yes.** Solving the *substitution* (which card ends up on top) for each
letter first, then refining the far swaps, recovers the full observed key for `s = 1, 2,
3` in seconds, and the recovered keys re-encrypt the plaintext to the ciphertext
byte-for-byte. This document explains why the naive view makes `s = 3` look hard, the
insight that dissolves it, the algorithm in full, and the honest limits of what it
proves.

> **Scope up front.** This is a **known-plaintext** attack on the **practice** puzzles.
> It recovers the swaps for the letters that actually occur in the corpus (24 of 26
> here — `J` and `Z` never appear, so their swaps are unconstrained). It does **not**
> touch the real Noita eye-glyph puzzle, which is ciphertext-only with no crib — a
> fundamentally different and much harder problem. Nothing here weakens or solves the
> eyes.

---

## 1. The cipher, precisely

All arithmetic is mod `N = 83`. A permutation `p` is an array where `p[i]` is the image
of `i`. Composition follows the vendor convention:

```
compose(p1, p2)[i] = p2[p1[i]]          # "apply p1, then read through p2"
```

**Public base permutation** (`shift = 26`, `decimation = 3`):

```
base[i] = ((i + 26) mod 83) * 3 mod 83
```

**Per-letter permutation.** Each plaintext letter `L` is assigned a permutation
`perm_L` built from `base` by applying exactly `num_swaps` *top-card swaps*. A top-card
swap with parameter `k` exchanges deck positions `0` and `k`:

```
top_swap(perm, k):  swap perm[0] and perm[k]      # k = 0 is the identity swap
```

so `perm_L = base` with `num_swaps` such swaps applied. (Because `k = 0` is allowed, a
`num_swaps = 3` key can express an *effective* 1- or 2-swap permutation too.)

**Encryption is stateful and only ever leaks position 0.** The deck starts at identity
and, per plaintext letter, is updated and the new top card is emitted:

```
state = identity                        # reset at the start of every message
for each plaintext letter L:
    state = compose(perm_L, state)      # i.e. new_state[i] = state[perm_L[i]]
    emit  ct_symbol( state[0] )         # ciphertext alphabet is chr(33 + value)
```

Non-alphabet characters pass through untouched and do **not** advance the deck. Each of
the 8 messages resets the deck to identity, and **all 8 messages share one key** (the
same `perm_L` per letter).

**The key we want to recover** is `perm_L` for every letter `L` — equivalently, the
`num_swaps` swap parameters per letter.

### Notation used below

| symbol | meaning |
|---|---|
| `perm_L` | the permutation assigned to plaintext letter `L` (the unknown, per letter) |
| `perm_L[0]` | the **substitution layer** for `L` — the card forced to the top when `L` acts on an identity deck |
| `state` | the running deck order within a message (starts at identity, resets per message) |
| *anchor* | the first letter of each message: its pre-state is identity, so its emitted symbol equals `perm_L[0]` exactly |

---

## 2. Why `num_swaps = 3` *looks* hard

Two things make the direct view discouraging:

1. **Only `state[0]` leaks.** The output reveals one card per step. The *far* swaps (the
   `perm_L[k]` for `k ≠ 0`) are invisible in the current step; they matter only through
   how they reshuffle the deck for *future* letters. So far-swap detail is weakly
   observable.

2. **The candidate space explodes.** The number of distinct permutations reachable from
   `base` by exactly `num_swaps` top swaps grows fast:

   | `num_swaps` | distinct candidate perms per letter |
   |---:|---:|
   | 1 | 83 |
   | 2 | 6,725 |
   | 3 | **541,406** |

   A left-to-right systematic search (DFS / constraint propagation / SAT-style conflict
   learning) over 24 letters × half a million candidates, coupled through shared deck
   state across 8 messages, is where "the wall" comes from: one wrong permutation
   desyncs all later state, so a forward search thrashes.

The trap is to conclude from *"systematic search is expensive"* that *"the problem is
hard."* It isn't — you were searching in the wrong order.

---

## 3. The insight: two layers, substitution first

Split each unknown `perm_L` into two parts:

- the **substitution layer** `perm_L[0]` — the single card `L` forces to the top; and
- the **far swaps** — everything else in `perm_L`, which only affects *future* state.

Two facts make this decomposition powerful:

**(a) Exact anchors pin the substitution for free at message starts.** The first letter
of each message acts on an identity deck, so its emitted ciphertext symbol *is*
`perm_L[0]`. Every message start hands you one substitution value with certainty.

**(b) The substitution is what the objective is really sensitive to.** If you re-simulate
the corpus with the wrong `perm_L[0]` for some letter, that letter emits the wrong symbol
*and* corrupts the deck for everything after it — an avalanche. But if the substitution
layer is right for every letter, the outputs line up and the remaining freedom (the far
swaps) refines cleanly to zero mismatches, because the far swaps only have to reproduce
the *downstream* deck evolution, which the abundant repeated text over-determines.

So: **settle `perm_L[0]` for every letter first**, then refine the far swaps. That order
defuses the avalanche — far-swap noise can't poison the score before the substitution is
even right, which is exactly what sinks a naive joint local search.

---

## 4. The algorithm

### 4.0 Precompute

- **Enumerate candidates** by BFS from `base`, applying a top swap `num_swaps` times,
  deduplicating permutations. Bucket them by their top value: `by_top[t]` is the list of
  all candidate perms with `perm[0] = t`. (For `s = 3` this is the 541,406-perm set.)
- **Single-swap representatives.** For each possible top value `t`, build one cheap
  permutation `rep[t] = base` with positions `0` and `base⁻¹[t]` swapped, so
  `rep[t][0] = t`. These are used to *rank* substitution choices cheaply (83 evals)
  before committing to a half-million-perm bucket.
- **Anchors.** For each message, set `forced[firstLetter] = firstCiphertextSymbol`.

### 4.1 Scoring

The objective is the total number of **output mismatches** when the whole corpus is
re-simulated under a candidate assignment (one perm per letter):

```
mismatches(assignment):
    m = 0
    for each message:
        state = identity
        for (i, L) in message.plaintext:
            state = compose(assignment[L], state)
            if state[0] != message.ciphertext[i]: m += 1
    return m
```

Because 8 long, repetitive messages massively over-determine the key, almost all search
runs on a **short prefix** of each message (e.g. the first ~90 symbols) for speed; the
full corpus is used only to finish and to accept. A single-letter override variant scores
"assignment but with letter `X` replaced by candidate `c`" so per-letter moves are cheap.

### 4.2 Substitution-first coordinate descent

```
for a few rounds:
    for each non-anchored letter L:
        # (i) choose the substitution: pick the top-value t whose cheap
        #     representative rep[t] scores best on the prefix
        t = argmin_t  mismatches(assignment with L := rep[t])            # ~83 evals
        # (ii) refine the far swaps within that bucket
        assignment[L] = argmin_{c in by_top[t]}  mismatches(assignment with L := c)
    for anchored letters: t is fixed by the anchor; do step (ii) only
    stop early if full-corpus mismatches == 0
```

Step (i) co-optimises the substitution layer against the current best guess of everything
else; step (ii) then searches only the perms that *have that top card*, which is where
the true perm must live once the substitution is right. Descending substitution-first is
the whole trick.

### 4.3 Polish, then finish

Run a couple more descent passes restricted to each letter's currently-best top-value
bucket — first on the prefix (cheap), then on the full corpus (exact). This is where the
far swaps lock in.

### 4.4 Basin hopping (only if needed)

If a pass stalls above zero, perturb: take the letters currently contributing the most
mismatches ("blame"), randomly reassign a few of the *non-anchored* ones to a random
candidate, and restart from the best-so-far. Use a **deterministic** PRNG (e.g. a fixed
seed xorshift/SplitMix) so runs are reproducible. In practice the practice-puzzle
instances converge on the **first** descent with no hopping needed.

### 4.5 Acceptance — the only thing that counts

```
accept(assignment)  iff  re-encrypting the known plaintext under `assignment`
                          reproduces the ciphertext byte-for-byte (mismatches == 0)
```

This is the crux of the honesty story. Acceptance is **exact re-encryption**, never a
score. A high-but-nonzero score is *not* a solve; local search is incomplete and may
fail to find a key — but it can never report a *wrong* key as a success, because the
exact re-encryption gate rejects any assignment that does not reproduce every emitted
symbol.

---

## 5. Results and independent verification

Running the method on the three vendored files:

| file | `num_swaps` | candidate perms/letter | wall time | residual | exact re-encryption |
|---|---:|---:|---:|---:|---|
| `1_swap_ct.txt` | 1 | 83 | ~0.03 s | 0 | ✅ all 8 messages, byte-for-byte |
| `2_swap_ct.txt` | 2 | 6,725 | ~0.11 s | 0 | ✅ all 8 messages, byte-for-byte |
| `3_swap_ct.txt` | 3 | 541,406 | ~14 s | 0 | ✅ all 8 messages, byte-for-byte |

(Timings are single-run on a commodity multi-core box; each converged on the first
descent — no basin hopping was needed.)

The result was checked with **three independent conditions**, using a fresh
re-implementation of the cipher (not the solver's own scoring):

1. **Re-encrypt.** Feed the recovered per-letter perms back through the vendor cipher and
   confirm the output equals the ciphertext for every message, symbol for symbol.
2. **Decrypt from scratch.** Using only the recovered key (never peeking at the
   plaintext), decrypt the ciphertext and confirm it reproduces the plaintext — which
   reads as the coherent English source text about numeral systems.
3. **Key legitimacy.** Confirm every recovered `perm_L` is actually reachable from `base`
   by exactly `num_swaps` top-card swaps, and that the `perm_L[0]` values are distinct
   across letters (as the cipher's reversibility/no-doubles construction requires).

All three hold for `s = 1, 2, 3`.

---

## 6. Honest limits

- **Known-plaintext only.** The method needs the plaintext. It answers "recover the
  swaps given the crib," which is the practice-puzzle setting and the community question
  — not a ciphertext-only break.
- **Observed letters only.** It recovers the swaps for letters that *occur* in the
  corpus. In these files the plaintext never uses `J` or `Z`, so their swaps are
  unconstrained by the data and are reported as **unrecovered** — not guessed. "Full key"
  here means "all 24 letters that appear."
- **Incomplete search, exact acceptance.** Local search can fail to find a key on a hard
  instance; it just reports a non-exact residual when it does. It cannot emit a *false*
  key, because only exact byte-for-byte re-encryption is accepted. A zero residual is a
  genuine recovery; a nonzero residual is an honest "didn't find it," not evidence the
  key doesn't exist.
- **Not the eyes.** Worth repeating: the real Noita eye puzzle has no known plaintext.
  This technique does not apply to it.

---

## 7. Reproducing it

**Inputs.** You need, per message: the plaintext as letter indices `0..25`, and the
ciphertext as deck values `0..82` (subtract 33 from each displayed ASCII symbol). The
public `base` and `num_swaps` are given above.

**Reference cipher** (everything you need to score, re-encrypt, and decrypt):

```python
N = 83
def compose(p1, p2):                 # p2[p1]
    return [p2[p1[i]] for i in range(N)]

def base_perm():
    return [((i + 26) % N) * 3 % N for i in range(N)]

def encrypt(pt_letter_perms):        # pt_letter_perms[i] = perm for the i-th plaintext letter
    state, out = list(range(N)), []
    for perm in pt_letter_perms:
        state = compose(perm, state) # new_state[i] = state[perm[i]]
        out.append(state[0])
    return out                       # compare to ciphertext values byte-for-byte
```

**Steps.**
1. Enumerate the `num_swaps`-top-swap closure of `base`, bucketed by `perm[0]`.
2. Pin anchors: for each message, `perm[firstLetter][0] = firstCtValue`.
3. Substitution-first coordinate descent (§4.2) on a prefix; then polish on the full
   corpus (§4.3); basin-hop if needed (§4.4).
4. Accept **only** on exact re-encryption (§4.5); report unobserved letters as
   unrecovered.

The heavy step is scoring half a million candidates per unanchored letter for `s = 3`,
which parallelises trivially across candidates — but keep the reduction deterministic
(break ties by a stable candidate index) so runs are reproducible.

A reference implementation exists as a runnable, self-validating CLI instrument
(`gak-swap-recover --strategy local-search`, which auto-routes `num_swaps = 3` to this
engine) with planted-positive and matched-null controls and tests that recover a planted
`s = 3` key end-to-end. The full internal results log lives alongside this file in
`SWAP-RECOVERY-RESULTS.md`.

---

## 8. Credits

The substitution-first coordinate-descent approach documented here is a community method;
this writeup is an **independent verification** of it — reproduced against the vendored
practice files and checked by byte-for-byte re-encryption, decrypt-from-scratch, and key
legitimacy, with the scope stated honestly. Corrections and improvements welcome.
