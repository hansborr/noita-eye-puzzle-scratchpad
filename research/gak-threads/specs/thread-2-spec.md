# Thread 2 — AGL stress-test: implementation spec (gated Rust)

**Status:** specification only. No `src/` file is modified by this document; it is
the blueprint a future implementer follows so the change lands inside the
existing gate (`make verify` / `make check`) with no surprises.

**Honesty ceiling (must appear verbatim in the report's `Interpretation:`
paragraph).** The strongest defensible claim about the eyes is: *deterministic,
engine-generated, strikingly structured data of unknown meaning; unsolved; no
primary developer source confirms recoverable plaintext.* Nothing this module
prints — Part A feasibility, Part B fit-or-no-fit — may be stated more strongly.
A structural AGL fit (Part B success) is a **hypothesis to kill with held-out
isomorphs, not a decode.**

**Mapping independence.** Every predicate uses only ciphertext-symbol *equality*
and group/coset structure. Where a plaintext-letter→group-element assignment
appears, it is an existence witness for the feasibility question or a free
unknown in the bounded search — never a claimed symbol→meaning mapping. Any such
choice is labelled *assumed/guessed* in the report.

**Provenance of the model.** The AGL(1,83)-GAK conceptual model and the exact
resync condition this spec encodes were derived and exhaustively brute-verified
in `research/gak-threads/notes/thread-2-agl-verification.md` (Part 1 model;
Part 2a/2b condition + 0-violation enumeration). This spec ports that result; it
does not re-derive it. There is no `notes/thread-2-empirical.md` in the tree at
spec time — the empirical anchors come from the verified note plus `perseus.rs`
and `corpus.rs`.

---

## 0. Wiki pages under test (cite these exactly; preserve "tentative")

| Predicate / claim encoded | Wiki page (Lymm's eye-messages wiki, github.com/Lymm37/eye-messages/wiki) |
| --- | --- |
| AGL(1,83) group, `ax+b`, order `φ(n)(n-1)`, semidirect `C_n ⋊ (C_n)ˣ` | `Affine-General-Linear-Group-(AGL).md` |
| Six transitive groups for 83; hidden-subgroup sizes `{1,2,41,82,82!/2,82!}`; `C₈₃:C₄₁`, `C₈₃:C₈₂` candidates | `The-Transitivity-Restriction-(6-Groups-for-83).md` |
| GAK definition; output `c` constant on **right** cosets `Hg` under **left-mult** update `g_{i+1}=p(aᵢ)∘gᵢ` (lines 19, 26–34); the **right-mult / left-coset** equivalence (line 34) | `Group-Autokey-(GAK).md` |
| Hidden subgroup must be non-normal; point stabilizer in AGL is non-normal | `Hidden-State.md` |
| "First trigram different… values all over the place… resync the state" tentative exclusion | `Message-Starts.md` |
| "Shared sections… longest ~24 chars in East1/West1/East2… almost certainly shared plaintext" | `Shared-Sections.md` |
| Isomorphic cipher hierarchy / soft AGL exclusion | `Isomorphic-Cipher-Hierarchy.md` |
| GAK perfect isomorphism (Part B held-out check) | `Proof-that-GAK-has-perfect-isomorphism.md`, `Perfect-Isomorphism.md` |
| The rigorous-kill analogue (element orders / chaining), referenced as the cleaner path | `Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher.md` |

**The claim under test is tentative in the wiki.** `Message-Starts.md` /
`Isomorphic-Cipher-Hierarchy.md` exclude AGL only by "not generally able …
unless … finetuned to … resync." The note's verdict (Part 2c/2d) is that this is
a *sound-but-overstated necessary condition*, **not a proof**. The module must
report the AGL exclusion as **unsettled by message-starts** unless the
9-message simultaneous test (Part A) produces an inconsistency; it must not
upgrade "tentative" to "excluded" on a single pair.

---

## 1. The verified model the cipher encodes (frozen — do not re-derive)

From `notes/thread-2-agl-verification.md` Part 1, the **self-consistent** model
whose output is the moved reference point is the **right-multiplication /
left-coset** variant (this is the GAK wiki line-34 equivalence, *not* its main
left-mult definition — mixing the two is the exact mis-model the thread warns
about):

```
state group:    G = AGL(1,83) = { (a,b) : a ∈ Z₈₃*, b ∈ Z₈₃ },  |G| = 82·83 = 6806
group op:       (a,b)·(c,d) = (a·c mod 83, a·d + b mod 83)        (compose ax+b)
action on pt:   (a,b).x = a·x + b mod 83
identity:       (1,0);   inverse of (a,b) = (a⁻¹,  neg_mod(a⁻¹·b, 83))
                         where neg_mod(t,n) = (n − (t mod n)) mod n   ← non-underflowing −t
reference pt:   x₀ = 0  (fixed)
hidden subgrp:  H = Stab(x₀) = { (a,0) : a ∈ Z₈₃* },  |H| = 82  (C₈₃:C₈₂ case)
state update:   g_{i+1} = g_i · p(aᵢ)                 ← RIGHT multiplication
CT output:      c_i = (g_{i+1}).x₀ = b-component when x₀=0   ← MOVED REFERENCE POINT
coset frame:    c is constant on LEFT cosets gH;  c(g)=c(g') ⟺ g⁻¹g' ∈ H
```

> **Unsigned-arithmetic discipline (load-bearing — the repo forbids panics, and a
> debug build PANICS on `usize` overflow/underflow).** Every operand is reduced
> `mod n` first, so it lies in `0..n`. Then:
> - `add`: `(a + b) % n` — safe (`a + b < 2n`, no overflow for these small `n`).
> - `mul`: `(a * b) % n` — safe (`a * b < n²` ≤ `82·82` ≪ `usize::MAX`).
> - **`sub`/`neg`: NEVER write `a − b` or `1 − d_a` directly — both underflow in
>   `usize` whenever the result would be negative (e.g. `1 − d_a` for `d_a > 1`).
>   Use the wrap-free forms below.** A `usize` `a − b` with `b > a` panics in
>   debug and yields a wrong residue (`usize::MAX − …`) in release; `% n` does
>   **not** repair it (`(usize::MAX) % 83 ≠ (a − b) mod n`).
>
> ```
> sub_mod(a, b, n) = (a + n − (b mod n)) % n     // a,b already < n ⇒ a + n − b ≥ 0
> neg_mod(t, n)    = (n − (t mod n)) % n          // = sub_mod(0, t, n); neg_mod(0,n)=0
> ```
>
> Equivalently use a checked/`rem_euclid` construction (e.g. cast to a wide signed
> type, `rem_euclid(n)`, cast back) — but the `sub_mod`/`neg_mod` forms above stay
> in `usize` and are the canonical recipe for this spec. The `% n`-after-each-op
> rule (§2.3, §7) covers ONLY `*` and `+`; subtraction/negation **must** use
> `sub_mod`/`neg_mod`.

For **`C₈₃:C₄₁`**: restrict the multiplier `a` to the order-41 multiplicative
subgroup of `Z₈₃*` (the quadratic residues). Then `|G|=3403`, `|H|=41`,
`|C|=3403/41 = 83`. Both variants still emit **83** ciphertext symbols
(`= |G|/|H|`), matching the eye alphabet.

**The exact resync condition (frozen from Part 2a; brute-verified 0 violations,
`agl_resync2.py`).** For two messages with post-first-letter states `g₁ᴹ, g₁ᴺ`,
let `D := (g₁ᴹ)⁻¹·g₁ᴺ` be the discrepancy and `K_t` the shared running key:

- differing first symbol ⟺ `c(g₁ᴹ) ≠ c(g₁ᴺ)` ⟺ `D ∉ H`;
- agreement at run-step `t` ⟺ `D ∈ K_t H K_t⁻¹ = Stab(K_t.x₀)` ⟺ `D` fixes the
  point `z_t := K_t.x₀`, i.e. `D.z_t = z_t`.

`D=(d_a,d_b)` is affine: its fixed-point set is `{ d_b/(1−d_a) }` if `d_a≠1`,
**empty** if `d_a=1, d_b≠0` (pure translation), all of `Z₈₃` only if `D=id`
(excluded). Hence a shared run of length `L` after a differing start is
achievable **iff (i)** `D` is not a pure translation (`d_a≠1`, so a unique fixed
point `y*=d_b/(1−d_a)` exists) **and (ii)** the shared key pins the reference at
`y*` for the whole run (`K_t.x₀ = y*` for all `t=1…L`): the first shared letter
resyncs `x₀→y*`, every later shared letter lies in `H`. The simultaneous
9-message form is: **all nine post-first-letter states lie in one common left
coset of a single point-stabilizer `Stab(y*)`.** This is the genuine,
falsifiable constraint Part A tests.

> **Fixed-point computation — exact panic-free recipe (load-bearing).** `1 − d_a`
> underflows in `usize` for every `d_a ∈ {2,…,n−1}`, and `d_a = 1` is a
> divide-by-zero. Compute `y*` as:
> ```
> // d_a, d_b already reduced into 0..n
> let denom = sub_mod(1, d_a, n);              // = (1 + n − d_a) % n, never underflows
> if denom == 0 {                              // d_a == 1: NO fixed point (pure translation)
>     // condition (i) fails ⇒ no shared section; do NOT divide. Return "no y*".
> } else {
>     let inv = mul_inverse_mod(denom, n)?;    // n prime ⇒ denom is a unit (denom ≠ 0)
>     let y_star = (d_b * inv) % n;            // d_b/(1−d_a)
> }
> ```
> The `denom == 0` guard is exactly the `d_a == 1` pure-translation branch
> (condition (i) failure): it must be tested **before** calling `mul_inverse_mod`,
> so `mul_inverse_mod` is only ever invoked on a nonzero (hence invertible)
> argument and `agl_apply`/the division never hit a zero denominator. `d_b/(1−d_a)`
> is `d_b · (1−d_a)⁻¹ mod n`; never written as a literal `/`.

---

## 2. Deliverable (a): `AglGakKey` primitive in `src/ciphers.rs`

Mirror `DeckCipherKey` (`ciphers.rs:384`) in shape, validation discipline, and
the exact-round-trip test contract. Add to the **existing** `ciphers.rs`; reuse
`CipherError`, `validate_alphabet_size`, the `Glyph` type, `Direction`, and the
`EYE_READING_ALPHABET_SIZE = 83` constant already there.

### 2.1 New `CipherError` variants (documented; extend the existing enum)

```rust
/// The AGL multiplier was not a unit modulo the prime alphabet size.
NonUnitMultiplier { multiplier: usize, modulus: usize },
/// The alphabet size for an AGL key was not prime (AGL(1,n)-GAK as modelled
/// requires prime n so the multiplicative group is cyclic C_{n-1}).
AlphabetNotPrime { alphabet_size: usize },
/// The chosen multiplier subgroup was not C82 (full) or C41 (quadratic
/// residues) for the prime alphabet.
UnsupportedMultiplierSubgroup { order: usize },
```

Add `From` nothing new — `AglGakKey::new` returns `CipherError` directly. Keep
`Display` arms for the three new variants (the enum already `impl fmt::Display`).

### 2.2 The key type and constructors

```rust
/// Which multiplicative subgroup the AGL multiplier `a` ranges over.
///
/// `Full` is `C₈₃:C₈₂` (all 82 units); `QuadraticResidues` is the index-2
/// subgroup `C₈₃:C₄₁` (the 41 quadratic residues).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AglMultiplierSubgroup { Full, QuadraticResidues }

/// Key for an AGL(1,n)-GAK stream cipher in the verified right-multiplication /
/// left-coset convention (output = moved reference point x₀).
///
/// State is an affine map `(a,b): x ↦ a·x + b (mod n)`; the cipher emits, at
/// each step, the image of the fixed reference point `x₀` under the updated
/// state. Cross-reference: research/gak-threads/notes/thread-2-agl-verification.md.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AglGakKey {
    alphabet_size: usize,
    subgroup: AglMultiplierSubgroup,
    reference_point: usize,                 // x₀, default 0
    initial_state: (usize, usize),          // g₀ = (a₀, b₀)
    letter_elements: Vec<(usize, usize)>,   // p: plaintext letter → group element
}
```

Constructors (each documented with `# Errors`; no panics, no
`unwrap`/`indexing_slicing`):

- `pub fn new(alphabet_size, subgroup, reference_point, initial_state,
  letter_elements) -> Result<Self, CipherError>`:
  - `validate_alphabet_size(alphabet_size, 3)?`;
  - assert primality via a private `fn is_prime(usize) -> bool` →
    `AlphabetNotPrime` otherwise (83 is prime; small test alphabets must be
    prime too — use 5 or 7, *not* a small `S_N` deck size);
  - `reference_point < alphabet_size` else `SymbolOutsideAlphabet`;
  - validate `initial_state` and every `letter_elements[i]` is a legal group
    element (`gcd(a,n)=1` i.e. `a≠0`; `a` in the chosen subgroup else
    `NonUnitMultiplier` / membership failure; `b < n`);
  - **reversibility guard (GAK wiki line 36):** the `letter_elements` must lie
    in **distinct left cosets of `H`** (so no two letters collide and no letter
    sits in the identity coset if doubles are to be avoided). Reuse the coset
    label `coset_of(g) = (a⁻¹·(x₀·? ))` — concretely `c(g)=g.x₀`; for injective
    *decryption* what's required is that the **per-step output is invertible to
    the letter**: enforce that the map `letter ↦ c((current)·p(letter))` is a
    bijection onto its image for the identity context, which (by GAK perfect
    reversibility) is equivalent to `p(letter)` landing in distinct cosets of
    `H`. Validate distinct-coset directly; return `DuplicatePermutationSymbol`
    (reuse) / a new `InternalInvariant` context on failure.
- `pub fn identity(alphabet_size, subgroup) -> Result<Self, CipherError>`:
  `reference_point=0`, `initial_state=(1,0)`, and `letter_elements` a default
  injective coset-spread (e.g. the `min(alphabet_size, |C|)` translations
  `(1, k)` for `k=1..` skipping the identity coset) — a convenience analogous to
  `DeckCipherKey::identity`, used only to exercise the round-trip control.
- `#[must_use] pub const` accessors: `alphabet_size`, `subgroup`,
  `reference_point`, `initial_state`, and `pub fn letter_elements(&self) ->
  &[(usize,usize)]`.

### 2.3 Group + coset helpers (private free fns in `ciphers.rs`)

```rust
fn agl_compose(g: (usize,usize), h: (usize,usize), n: usize) -> (usize,usize);   // g·h
fn agl_inverse(g: (usize,usize), n: usize) -> Option<(usize,usize)>;             // None if a not invertible
fn agl_apply(g: (usize,usize), x: usize, n: usize) -> usize;                     // a·x+b
fn agl_coset_symbol(g: (usize,usize), x0: usize, n: usize) -> usize;             // c(g) = g.x0  (MOVED REF POINT)
fn mul_inverse_mod(a: usize, n: usize) -> Option<usize>;                         // n prime → a^(n-2)
fn sub_mod(a: usize, b: usize, n: usize) -> usize;                               // (a + n − (b%n)) % n  (no underflow)
fn neg_mod(t: usize, n: usize) -> usize;                                         // (n − (t%n)) % n      (no underflow)
fn quadratic_residues_mod(n: usize) -> Vec<usize>;                               // the 41-subgroup for n=83
```

**Modular-arithmetic recipe (binding for ALL of §2–§4; the repo forbids panics
and a debug build panics on `usize` overflow/underflow).** Reduce every operand
`mod n` first (so it is in `0..n`), then:

- **`*` and `+`:** `(a * b) % n`, `(a + b) % n` — safe in `usize` for these `n`
  (`a*b < n² ≤ 82·82`; `a+b < 2n`), as before.
- **`−` and unary negation:** **never** write `a − b` or `1 − d_a` in `usize`.
  Use `sub_mod(a, b, n) = (a + n − (b % n)) % n` and
  `neg_mod(t, n) = (n − (t % n)) % n`. With operands already reduced, `a + n − b
  ≥ 0`, so no underflow; `% n` then gives the correct residue. (Writing `a − b`
  panics in debug when `b > a` and wraps to a wrong residue in release — `% n`
  cannot repair it.)

Critical-path uses that **must** go through these helpers:

- `agl_inverse(g=(a,b), n)`: `a⁻¹ = mul_inverse_mod(a, n)?`; the translation part
  is `neg_mod((a⁻¹ * b) % n, n)` — i.e. `−a⁻¹·b mod n`, **not** `n − a⁻¹·b` and
  **not** a bare `−`. Return `None` iff `mul_inverse_mod` returns `None`.
- the fixed point `d_b/(1−d_a)`: denominator is `sub_mod(1, d_a, n)`; see the
  panic-free recipe under §1 (guard `denom == 0` ⇒ `d_a==1` ⇒ no fixed point,
  **before** any inverse/division).

`mul_inverse_mod` via Fermat: `Some(pow_mod(a % n, n − 2, n))` when `n ≥ 2` **and**
`a % n != 0`; `None` otherwise (so the `n − 2` exponent never underflows and the
result is only ever used as a genuine inverse). Implement `pow_mod` by
square-and-multiply with the accumulator reduced `% n` after **every** multiply
(each factor `< n`, so each product `< n²`, no overflow); `pow_mod(_, 0, n) = 1 %
n`. This avoids extended-Euclid edge cases and never panics. No `indexing_slicing`
(use `.get`).

### 2.4 Encrypt / decrypt (free fns, mirroring `deck_cipher_encrypt/_decrypt`)

```rust
/// Encrypts with the AGL(1,n)-GAK stream cipher (right-mult / left-coset).
///
/// Starting from `g = key.initial_state`, for each plaintext letter `a_i`:
/// `g ← agl_compose(g, p(a_i))`; emit `c_i = agl_coset_symbol(g, x₀)`.
///
/// # Errors
/// [`CipherError::SymbolOutsideAlphabet`] for an out-of-range plaintext symbol;
/// [`CipherError::InternalInvariant`] if a validated group element loses its
/// invariant (e.g. a non-invertible multiplier survives validation).
pub fn agl_gak_encrypt(plaintext: &[Glyph], key: &AglGakKey)
    -> Result<Vec<Glyph>, CipherError>;

/// Decrypts an AGL(1,n)-GAK ciphertext back to plaintext.
///
/// Replays the same state recurrence: at each step the next CT symbol uniquely
/// identifies the coset of `g·p(letter)`, hence (by distinct-coset validation)
/// the letter; recover it by the precomputed inverse map `c-of-step → letter`,
/// then advance `g ← agl_compose(g, p(letter))`.
///
/// # Errors
/// [`CipherError::SymbolOutsideAlphabet`] for an out-of-range ciphertext symbol;
/// [`CipherError::InternalInvariant`] if no letter matches the observed coset
/// (which cannot happen for a key that passed construction).
pub fn agl_gak_decrypt(ciphertext: &[Glyph], key: &AglGakKey)
    -> Result<Vec<Glyph>, CipherError>;
```

Decryption is well-defined because, from a known current state `g`, the map
`letter ↦ agl_coset_symbol(agl_compose(g, p(letter)), x₀)` is injective (distinct
cosets), so the observed CT symbol pins the letter. Build a per-step lookup
`BTreeMap<usize, usize>` (coset-symbol → letter index) from the current `g`;
`InternalInvariant` if a symbol is absent. No `unwrap`.

### 2.5 Exact round-trip control test (the contract from `ciphers.rs:1224`)

In `#[cfg(test)] mod tests`, add `agl_gak_round_trips_random_plaintexts()`
mirroring `deck_cipher_round_trips_random_plaintexts`:

- small **prime** keys: `AglGakKey::identity(7, Full)`, `identity(7,
  QuadraticResidues)`, and a `new(...)` with a hand-built injective letter map;
- eye keys: `AglGakKey::identity(EYE_READING_ALPHABET_SIZE, Full)` and `(…,
  QuadraticResidues)`;
- random plaintexts over **`0..min(alphabet_size, |C|)`** via the existing
  `random_plaintext(seed, len, k)` helper (letters index into
  `letter_elements`, so the bound is the letter-alphabet size, not `n`);
- `assert_eq!(agl_gak_decrypt(&agl_gak_encrypt(p)?, key)?, p)`.

This is the primitive's correctness gate and must be green before any analysis
trusts it.

---

## 3. Deliverable (d): null + positive controls (BEFORE the eyes)

### 3.1 Hand-checked tiny synthetic AGL example (the pitfall guard)

A `#[cfg(test)]` test `agl_gak_matches_hand_computed_n5()` over `n=5`,
`Full` (`|G|=20`, `|H|=4`, `|C|=5`), `x₀=0`, `g₀=(1,0)`:

- pick `p`: letter 0 → `(1,1)` (a translation, coset of point 1), letter 1 →
  `(1,2)`, letter 2 → `(2,0)` (a decimation). Hand-compute, e.g. plaintext
  `[0,0]`: `g₁=(1,0)·(1,1)=(1,1)`, `c₁=g₁.0=1`; `g₂=(1,1)·(1,1)=(1,2)`, `c₂=2`.
  Plaintext `[2,0]`: `g₁=(2,0)`, `c₁=0`; `g₂=(2,0)·(1,1)=(2,2)`, `c₂=2`.
- `assert_eq!` the full emitted CT vector against the **literal hand-computed
  values written into the test** (not recomputed by the code under test). This
  is the moved-reference-point convention check the thread demands "before
  trusting it on the eyes."
- A second tiny test asserts the **wrong** convention (left-mult update with
  `g.x₀` output) would give a *different* vector for at least one input — a
  guard that the convention is the verified one, not the mis-model.

### 3.2 Positive control for the feasibility harness (must fire on known signal)

The harness's job is to detect *whether a differing-first-then-shared run is AGL-
realizable*. Plant a **known-realizable** witness and a **known-impossible** one:

- **Known-realizable (control fires "feasible"):** synthesize, with a chosen key
  and per-message initial states obeying the common-stabilizer-coset condition,
  three ciphertexts with **distinct first symbols** then an identical length-≥6
  shared run (the note already built a length-7 triple-shared witness with first
  symbols `5,51,14`, `agl_multi.py`). The harness must classify this **feasible**
  and recover the witnessing `y*` / common coset.
- **Known-impossible (control fires "infeasible"):** force a **pure-translation
  discrepancy** (`d_a=1, d_b≠0`) between two messages. By Part 2a this admits
  **no** shared section. The harness must classify it **infeasible**. (Note 2b:
  0 agreements across all 82 such `D` × 6806 contexts.)

A control that misclassifies either ⇒ `PositiveControlFailed` error variant
(methodology suspect, not data) — same discipline as `cipher_attack.rs:1173`.

### 3.3 Matched null (structural-negative framing)

The decisive Part-A question is **exhaustive enumeration, not statistics** — the
state space is 6806 / 3403, so the common-stabilizer-coset feasibility for the
real 9 starts is *settled*, not sampled. The null therefore serves a *calibration*
role: it answers "is `feasible` cheap?" — i.e. does the 9-message constraint pass
for *random* first-symbol vectors too, making a pass uninformative?

- **Null model:** draw random 9-tuples of distinct first symbols (uniform over
  the `83`-symbol alphabet, via `null::SplitMix64` + `random_index_below`,
  per-trial seed from `null::mix_seed(seed, trial)`), and run the same
  common-stabilizer-coset feasibility test. Report the **fraction of random
  start-vectors that pass**. Per note 2c the *pairwise* pass rate is ≈98.78%, so
  a *9-message* pass is expected to be common unless the eyes' starts are special;
  the null quantifies exactly how special (if at all). Frame and report this as a
  tail/exceedance, **not** a verdict (`cipher_attack.rs` module-doc lines 14–18).
- Aggregate within-message / within-start-vector only; **no** cross-message
  bigrams/lags. The shared-run *lengths* come from `perseus.rs` anchors (real
  data), held fixed across null draws.

---

## 4. Deliverable (b): feasibility / enumeration logic — where it lives

New analysis module **`src/agl_gak.rs`** (alphabetically between `analysis` and
`chaining` in `lib.rs`; one `pub mod agl_gak;` line). It owns `Config`, `Report`,
`Error`, the `run_agl_gak` entry point, the null, the positive control, and
tests — exactly the engine module shape of `pyry_conditions.rs` /
`cipher_attack.rs` (one of `Config`/`Report`/`Error`/`run_*` entry point plus
null, controls, and tests per file). The `AglGakKey` *primitive* lives in
`ciphers.rs` (§2); the *enumeration/feasibility* logic lives here.

### 4.1 Public surface (every item documented)

```rust
pub const DEFAULT_SEED: u64 = 0x6167_6c5f_6761_6b00;   // "agl_gak"
pub const DEFAULT_NULL_TRIALS: usize = 10_000;

/// Which Part(s) to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AglGakMode { FeasibilityOnly, FeasibilityAndFit }   // Part A, A+B

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AglGakConfig {
    pub seed: u64,
    pub null_trials: usize,
    pub mode: AglGakMode,            // default FeasibilityOnly (Part B is opt-in)
    pub subgroup: ciphers::AglMultiplierSubgroup,  // run both via two invocations / a sweep
}
impl Default for AglGakConfig { /* fills from DEFAULT_* ; mode=FeasibilityOnly */ }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AglGakError {
    Grid(orders::GridError),
    Cipher(ciphers::CipherError),
    Random(crate::null::RandomBoundError),
    Perseus(perseus::PerseusError),   // from shared-run reconstruction
    ZeroTrials,
    PositiveControlFailed { which: &'static str },
}
// From<GridError>, From<CipherError>, From<RandomBoundError>, From<PerseusError>
// so `?` works. Display + std::error::Error if main holds &error.

pub struct AglGakReport { /* see §4.3 */ }

/// Runs the AGL-GAK stress test (Part A always; Part B if mode requests it).
/// # Errors
/// Returns [`AglGakError`] on corpus/grid failure, cipher construction failure,
/// PRNG bound failure, or a failing positive control.
pub fn run_agl_gak(config: AglGakConfig) -> Result<AglGakReport, AglGakError>;
```

### 4.2 Part A algorithm (port of `agl_resync2.py` / `agl_multi.py` / `agl_null.py`)

1. **Corpus, read-only, no mapping** (read the shared corpus fixtures directly):
   `let grids = orders::corpus_grids()?;`
   `let order = orders::accepted_honeycomb_order();`
   `let message_values = orders::read_corpus_message_values(&grids, order)?;`
   Never re-select a reading order.
2. **Anchors from `perseus.rs`** — reuse `perseus::build_shared_partition(keys,
   &message_values)?` (it is `pub(crate)`; either call it from within the crate
   or, if `agl_gak.rs` is a sibling module, it already has crate visibility).
   From the returned `SharedPartition` take:
   - the **first symbol** of each message (`message_values[m][0]`) — the
     differing message-starts (`Shared-Sections.md`/`Message-Starts.md`);
   - the **shared-run lengths/offsets** for the East1/West1/East2 family (the
     `selected_pair_runs` whose `role` is leading-family; longest ≈24 per
     `Shared-Sections.md`). These are the `L` values the resync condition must
     satisfy. Hold the *lengths*, not any symbol→meaning content.
3. **Feasibility (exhaustive, both subgroups):** for the chosen
   `subgroup`, enumerate the point-stabilizer cosets. Per the frozen condition
   (§1), the 9-message test reduces to:
   *does there exist a target point `y* ∈ Z₈₃` and one common left coset of
   `Stab(y*)` such that each message's required post-first-letter state — i.e.
   some state whose `c(·)=` that message's first symbol — can lie in that coset,
   while a single shared key parks the reference at `y*` for the full observed
   run length `L`?* Operationally:
   - For each candidate `y*` (83 values), and each pair (message m, message m'),
     compute the discrepancy class and test condition (i) (`D` not a pure
     translation) + (ii) (`K_t.x₀ = y*` realizable for `t=1…L`). Compute
     `D = (g₁ᴹ)⁻¹·g₁ᴺ` via `agl_inverse` + `agl_compose` and any fixed point via
     the §1 panic-free recipe; **never** open-code `−` / `1 − d_a` here (use
     `sub_mod`/`neg_mod`). Condition (i) is the comparison `d_a != 1` (no
     arithmetic); the `d_a == 1` case is "pure translation ⇒ fails (i)". Because the key
     map is free, (ii) is always satisfiable once (i) holds and the first symbols
     are realizable from a common `Stab(y*)` coset (note 2c). So the **decisive**
     test is: **is there a single `y*` whose stabilizer coset realizes all nine
     first symbols simultaneously** with non-pure-translation pairwise
     discrepancies? Enumerate `y*`; for each, check all nine first symbols are in
     the 82 (or 40) realizable values of that coset (note 2c: one coset realizes
     82 of 83 first symbols) **and** pairwise discrepancies are not pure
     translations. Record pass/fail and the witnessing `y*`(s).
   - This is `O(83 · 9)` per subgroup after the cosets are precomputed —
     trivially exhaustive.
4. **Classify** (the framed output the thread asks for): emit
   *"AGL(1,83):C₈₂ (resp. C₄₁) reproduces the 9-message differing-start + shared
   run pattern **iff** {the common-`y*` condition holds}; for the real eye starts
   the condition is {satisfied / violated} by {witness `y*` / the obstructing
   message pair}."* Then state the honesty caveat (§6).
5. **Null** (§3.3): repeat step 3's pass/fail on `null_trials` random distinct
   9-start vectors; report the pass fraction as calibration (tail framing).

### 4.3 Part B (optional; `mode = FeasibilityAndFit`) — bounded guided search

Goal (thread Part B): attempt an actual AGL-GAK that *reproduces the real
ciphertext*, using the isomorph structure as simultaneous constraints. Reuse
**`isomorph.rs`**:

- `isomorph::detect_isomorphs(&message_values_concat_or_per_message, window,
  min_period, max_period)` (or `PatternSignature::from_window`) to extract
  repeated-equality constraints: positions sharing an isomorph signature ⇒ equal
  running-key element-products under the GAK reading (`repeated plaintext ⇒
  repeated element products`, thread Part B).
- Unknowns: per-letter group elements `p(·)` (bounded — at most 83 elements,
  each in `|C|=83` cosets) and per-message initial states (in one common
  `Stab(y*)` coset from Part A). Propagate the isomorph equalities as
  coset/element constraints; **fail fast** on contradiction.
- A **failed exhaustive** Part B is itself a result: it upgrades the tentative
  exclusion toward a real one ("no AGL(1,83)-GAK reproduces the pattern"). A
  **success** is a *candidate structural hypothesis only* — §6.
- Report holds: `fit_attempted: bool`, `fit_found: bool`, and if found, the
  number of held-out isomorphs it must still survive (do **not** print recovered
  plaintext; there is no plaintext claim).

### 4.4 `AglGakReport` fields (documented)

```rust
pub struct AglGakReport {
    pub config: AglGakConfig,
    pub order: orders::ReadingOrder,
    pub message_first_symbols: Vec<(&'static str, usize)>,   // 9 differing starts
    pub shared_run_lengths: Vec<usize>,                      // from perseus anchors
    pub subgroup: ciphers::AglMultiplierSubgroup,
    pub feasible: bool,                                      // 9-message common-coset pass
    pub witness_targets: Vec<usize>,                         // y* values that pass (may be empty)
    pub obstruction: Option<(&'static str, &'static str)>,   // first conflicting message pair if infeasible
    pub null_pass_fraction: f64,                             // calibration (tail framing)
    pub positive_control_feasible_ok: bool,
    pub positive_control_infeasible_ok: bool,
    pub fit_attempted: bool,
    pub fit_found: bool,
}
```

---

## 5. Deliverable (e): CLI subcommand + report wiring (the four-file pattern)

Following the engine's four-file wiring pattern, exactly four files change; the
gate discovers everything through them. No `Cargo.toml`/`Makefile`/CI edits.

1. **`src/agl_gak.rs`** — the module above.
2. **`src/lib.rs`** — add `pub mod agl_gak;` (keep block sorted: it goes between
   `analysis` and `chaining`) and one `///`-doc line in the module list.
3. **`src/report.rs`** — add to the alphabetical `use crate::{…}` list; add
   `#[must_use] pub fn format_agl_gak_error(error: &agl_gak::AglGakError) ->
   String` (match every variant, no panic) and `pub fn
   print_agl_gak_report(report: &agl_gak::AglGakReport)` (println! only;
   private `fn print_*` sub-sections). The report **must** end with an
   `Interpretation:` paragraph carrying the honesty ceiling (§6) and a
   `Multiplicity note:` if both subgroups / several `y*` tails are reported, and
   it **must cite** `Affine-General-Linear-Group-(AGL).md`,
   `The-Transitivity-Restriction-(6-Groups-for-83).md`, `Message-Starts.md`,
   `Shared-Sections.md`, and `Isomorphic-Cipher-Hierarchy.md`, preserving the
   word "tentative" for the wiki's AGL exclusion.
4. **`src/main.rs`** — add `agl_gak` to the `use noita_eye_puzzle::{…}` import;
   a `Command::AglGak(AglGakArgs)` variant with a `///` help line and
   `#[command(name = "agl-gak")]`; an `AglGakArgs` struct; a `From<AglGakArgs>
   for agl_gak::AglGakConfig`; a `run_agl_gak` dispatch fn; and the match arm.

```rust
#[derive(Clone, Copy, Debug, Args)]
struct AglGakArgs {
    #[arg(long, default_value_t = agl_gak::DEFAULT_SEED)]
    seed: u64,
    #[arg(long, default_value_t = agl_gak::DEFAULT_NULL_TRIALS)]
    null_trials: usize,
    /// Run Part B bounded fit as well as Part A feasibility.
    #[arg(long, default_value_t = false)]
    fit: bool,
    /// Restrict the multiplier to the order-41 quadratic-residue subgroup (C83:C41).
    #[arg(long, default_value_t = false)]
    quadratic_residues: bool,
}
impl From<AglGakArgs> for agl_gak::AglGakConfig {
    fn from(args: AglGakArgs) -> Self {
        Self {
            seed: args.seed,
            null_trials: args.null_trials,
            mode: if args.fit { agl_gak::AglGakMode::FeasibilityAndFit }
                  else { agl_gak::AglGakMode::FeasibilityOnly },
            subgroup: if args.quadratic_residues {
                ciphers::AglMultiplierSubgroup::QuadraticResidues
            } else { ciphers::AglMultiplierSubgroup::Full },
            ..Self::default()
        }
    }
}

fn run_agl_gak(config: agl_gak::AglGakConfig) -> ExitCode {
    let report = match agl_gak::run_agl_gak(config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("AGL-GAK error: {}", report::format_agl_gak_error(&error));
            return ExitCode::FAILURE;
        }
    };
    report::print_agl_gak_report(&report);
    ExitCode::SUCCESS
}
// in main(): Command::AglGak(args) => run_agl_gak(args.into()),
```

(Cover **both** `C₈₃:C₈₂` and `C₈₃:C₄₁` either by two CLI runs with/without
`--quadratic-residues`, or by having `run_agl_gak` loop over both subgroups and
the report carry both — pick the loop so a single invocation tests the whole
candidate pair, matching the thread's "carry all nine / both groups" requirement.)

---

## 6. Deliverable (g): success / failure criteria + honesty caveat

**Part A — confirms the wiki (the note's expected outcome by message-starts is
that it does NOT cleanly confirm; see 2c).** If the 9-message common-`y*`
condition is **violated** (no single stabilizer coset realizes all nine first
symbols with non-pure-translation discrepancies), AGL is **rigorously excluded by
message-starts** and the candidate set collapses to `{A₈₃, S₈₃}`. Deliverable:
the precise violated condition + the obstructing message pair + a positive
control showing the test fires on the planted feasible/infeasible witnesses.

**Part A — breaks the wiki (the note judges this the likely message-starts
outcome).** If the condition is **satisfied** (some `y*` realizes all nine
starts — plausible, since one coset realizes 82/83 symbols, note 2c), then the
message-starts argument does **not** exclude AGL. Report it as **"AGL not
excluded by message-starts; remains a brute-forceable candidate"**, escalate, and
explicitly defer the *rigorous* kill to the **element-order / chaining** route
(note 2d; `Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher.md`) which is
Thread 1 / Thread 5 territory — do **not** claim a kill the message-starts test
cannot deliver.

**Part B — failed exhaustive search:** strengthens the exclusion ("no AGL(1,83)-
GAK reproduces the message-start + shared-section pattern under the isomorph
constraints"). Report as a bounded-search negative, not a proof, unless the
search is provably exhaustive over the stated space.

**Part B — a fit is found:** report it as a **candidate structural hypothesis,
explicitly NOT a decode.** It must be killed/kept by **held-out isomorphs** (the
isomorphs not used to constrain the fit) and later by Thread 3's perfect-
isomorphism scan (`Proof-that-GAK-has-perfect-isomorphism.md`). Print **no
plaintext** and assert **no symbol→meaning mapping**. The required closing
sentence: *the eyes remain deterministic, engine-generated, strikingly structured
data of unknown meaning; unsolved; no primary developer source confirms
recoverable plaintext.*

**Honesty caveat (mandatory in the report).** A structural AGL fit with no
language constraint can be a coincidence (thread Pitfalls). The two-message
demonstration neither confirms nor refutes the exclusion — the constraint is
simultaneous across all nine messages, so the report must carry all nine.

---

## 7. Deliverable (f): lint compliance checklist (`-D warnings` in CI)

- `missing_docs`: every `pub` item incl. struct fields and enum variants gets a
  `///` doc; `run_agl_gak` and both cipher fns get `# Errors` sections (rustdoc
  runs `-D warnings`).
- No `unwrap`/`expect`/`panic`/`indexing_slicing`/`string_slice`/`integer_arithmetic`
  overflow in lib/CLI: index via `.get(i)` + `let Some(x) = … else { return
  Err(CipherError::InternalInvariant{ context }) }`. **Modular arithmetic:** `% n`
  after each `*`/`+` keeps those in range, **but subtraction/negation must use
  `sub_mod`/`neg_mod` (§1, §2.3) — a bare `a − b` / `1 − d_a` in `usize` panics in
  debug (the gate runs debug tests) and yields a wrong residue in release.** Guard
  `mul_inverse_mod` so the Fermat exponent `n − 2` (needs `n ≥ 2`) and the
  divide-by-`(1−d_a)` never hit zero (`denom == 0` ⇒ `d_a == 1` ⇒ no fixed point;
  return before dividing). Relaxed only inside `#[cfg(test)]`.
- `unused_results`/`let_underscore_must_use`: bind dropped `#[must_use]`
  results (`let _inserted = map.insert(k, v);`).
- `panic_in_result_fn`: the `-> Result<…>` fns must not panic.
- `float_cmp`/`lossy_float_literal`: compare `null_pass_fraction` with
  `total_cmp`/tolerance, never `==`.
- `map_err_ignore`: rely on `From` impls + `?`, don't discard error sources.
- `allow_attributes_without_reason`: any `#[allow(...)]` carries `reason = "…"`.
- `cognitive-complexity-threshold = 20`, `too-many-arguments-threshold = 7`,
  `max-struct-bools = 3`: split the feasibility loop into private helpers; bundle
  args into a small `struct` (cf. `PairRunInput` in `perseus.rs`, `PairInput` in
  `pyry_conditions.rs`); `AglGakReport` has 2 bool fields (ok).
- `wildcard_imports`: name every import explicitly.
- `--locked`; `unsafe` forbidden crate-wide; new module needs no new dependency
  (in-crate `null::SplitMix64` is the only PRNG).

## 8. Test checklist for `agl_gak.rs` (`#[cfg(test)] mod tests`)

- **Determinism:** `run_agl_gak(cfg) == run_agl_gak(cfg)` for a fixed seed.
- **Eye pin:** the nine `message_first_symbols` are the known corpus first
  values and are pairwise-distinct (9 distinct starts), and `shared_run_lengths`
  matches the perseus East1/West1/East2 leading-family anchors (longest ≈24).
- **Positive controls fire:** planted feasible witness → `feasible=true` with a
  recovered `y*`; planted pure-translation witness → `feasible=false`. A
  misclassification ⇒ `PositiveControlFailed`.
- **Cipher round-trip** (in `ciphers.rs` tests): exact encrypt→decrypt over
  small prime + 83 alphabets, both subgroups (§2.5).
- **Hand-checked convention** (in `ciphers.rs` tests): n=5 literal CT vector;
  wrong-convention divergence guard (§3.1).
- **Null calibration sanity:** `0.0 ≤ null_pass_fraction ≤ 1.0`; with the verified
  98.78% pairwise figure, the 9-message null pass fraction is reported, not
  asserted to a specific value (data-dependent).

---

## 9. Reuse map (deliverable (c)) — concrete anchors

| Need | Reuse | Location |
| --- | --- | --- |
| Cipher-key template (struct/validate/accessors/round-trip test) | `DeckCipherKey` | `ciphers.rs:384`; round-trip `ciphers.rs:1224` |
| Error type, alphabet validation, `Direction`, `EYE_READING_ALPHABET_SIZE=83`, `Glyph` | existing `ciphers.rs` | `ciphers.rs:20,26,636` |
| Corpus, no remapping | `orders::corpus_grids` / `read_corpus_message_values` / `accepted_honeycomb_order`; `READING_LAYER_ALPHABET_SIZE=83` | `orders.rs:183,483,24`; usage `perseus.rs:324–331` |
| Shared-run anchors + differing first symbols | `perseus::build_shared_partition` → `SharedPartition.selected_pair_runs` / `leading_start` (`same_offset_common_runs`) | `perseus.rs:396,407,466`; `corpus.rs` messages east1/west1/east2 = ids 0,1,2 |
| Part B isomorph constraints | `isomorph::detect_isomorphs` / `PatternSignature::from_window` | `isomorph.rs:212,38` |
| Null PRNG (deterministic) | `null::{SplitMix64, random_index_below, fisher_yates, shuffled_permutation, stateless_splitmix, mix_seed}` | `null.rs:27,112,132,148,70,91` |
| Module/CLI/report wiring | the four-file pattern; `run_perseus`/`run_pyry` as cleanest templates | `lib.rs:62–88`; `main.rs:242,609,684`; `report.rs` format/print fns |
| New | `AglGakKey` + `agl_gak_encrypt/_decrypt` (ciphers.rs); `agl_gak.rs` feasibility/enumeration + null + controls | — |

---

## 10. What this module must NOT do

- Must not print recovered plaintext or assert any symbol→meaning mapping
  (mapping-independent rule).
- Must not upgrade the wiki's *tentative* AGL exclusion to "excluded" on the
  strength of one pair or of message-starts alone; a true kill is element-order /
  chaining (note 2d), flagged but out of this module's scope.
- Must not report any number more strongly than its construction supports; the
  feasibility result is exhaustive (bounded state space, "exact"), the null
  fraction is calibration, the Part B fit (if any) is an unverified hypothesis.
