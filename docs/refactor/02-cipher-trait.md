# 02 — Cipher trait + ciphers.rs refactor

> One-line: introduce the crate's first trait — `Cipher` (with associated `Key`) and an `AnyCipher` dispatch enum — over the seven existing cipher families, so the solve engine (brief 04) can drive heterogeneous ciphers through one interface without touching any reported statistic or decode.
> Status: not started · Depends on: 01 (golden-master safety net) · Blocks: 04 (solve pipeline) · Size: M

## Goal & why it matters

`ciphers.rs` exposes seven families as fourteen bespoke free functions (`caesar_encrypt`/`caesar_decrypt`, …, `gak_encrypt`/`gak_decrypt`) keyed off seven unrelated `*Key` structs. There is **no `Cipher` trait** — the crate has zero traits — so any consumer that wants to "run *some* cipher chosen at runtime" must hand-write a `match` over fourteen functions. Brief 04's solve engine needs exactly that: drive a heterogeneous list of cipher+key pairs (`Candidate { cipher: AnyCipher, … }` in the overview, `00-OVERVIEW.md` §"5. The solve pipeline — the prize (brief 04)", the `Candidate` struct) through one `encrypt`/`decrypt` surface.

This brief delivers the shared spine from `00-OVERVIEW.md` §"1. `trait Cipher` — unify the cipher zoo (brief 02)": `trait Cipher { type Key; … }` plus an object-safe-substitute `AnyCipher` enum. It is **purely additive**: the seven free-function pairs stay as the canonical implementation, the trait/enum delegate to them, and every existing round-trip test and every downstream caller keeps compiling and producing identical results. No statistic, no decode, no key-validation behavior changes.

## Current state (grounded, with file:line)

Module is declared flat in `src/lib.rs:77` (`pub mod ciphers;`).

**Seven `*Key` types** (all in `src/ciphers.rs`), each with its own `new`/getters and validation in `Key::new`:
- `CaesarKey` — `src/ciphers.rs:375` (fields `alphabet_size`, `shift`; `Copy`).
- `VigenereKey` — `src/ciphers.rs:412` (fields `alphabet_size`, `shifts: Vec<usize>`).
- `IncrementingWheelKey` — `src/ciphers.rs:460` (fields `alphabet_size`, `start`, `step`; `Copy`).
- `ChaocipherKey` — `src/ciphers.rs:511` (fields `alphabet_size`, `left`, `right`).
- `DeckCipherKey` — `src/ciphers.rs:585` (fields `alphabet_size`, `deck`, `control_a`, `control_b`).
- `AglGakKey` — `src/ciphers.rs:675` (fields incl. `subgroup: AglMultiplierSubgroup` at `src/ciphers.rs:662`, `letter_elements: Vec<(usize, usize)>`).
- `GakKey` — `src/ciphers.rs:961` (fields `ciphertext_alphabet_size`, `state_size`, `plaintext_letters`, `initial_state`, `coset_readout: CosetReadout` at `src/ciphers.rs:777`; built via `GakKey::new` `src/ciphers.rs:984` or `GakKey::deck`).

**The seven `encrypt`/`decrypt` free-function pairs** (the canonical implementations the trait will wrap), `src/ciphers.rs:1106-1394`:
- `caesar_encrypt` `:1106` / `caesar_decrypt` `:1122`
- `vigenere_encrypt` `:1139` / `vigenere_decrypt` `:1156`
- `incrementing_wheel_encrypt` `:1176` / `incrementing_wheel_decrypt` `:1196`
- `chaocipher_encrypt` `:1218` / `chaocipher_decrypt` `:1235`
- `deck_cipher_encrypt` `:1251` / `deck_cipher_decrypt` `:1267`
- `agl_gak_encrypt` `:1284` / `agl_gak_decrypt` `:1311`
- `gak_encrypt` `:1344` / `gak_decrypt` `:1374`

All fourteen share the signature shape `fn(&[Glyph], &SomeKey) -> Result<Vec<Glyph>, CipherError>` (note the order: **sequence first, key second**). `CipherError` is at `src/ciphers.rs:36`, with `Display` at `:212` and `std::error::Error` at `:368`.

**Round-trip / known-vector tests** live in `#[cfg(test)] mod tests` (`src/ciphers.rs:2200`), importing the free functions at `:2201-2208`. Deterministic known-vector tests: `caesar_known_tiny_vector` `:2214`, `vigenere_known_tiny_vector` `:2223`, `incrementing_wheel_known_tiny_vector` `:2232`, `chaocipher_known_tiny_vector` `:2244`, `chaocipher_matches_classic_published_vector` `:2253`, `deck_cipher_known_tiny_vector` `:2267`, `agl_gak_matches_hand_computed_n5` `:2276`. Random property round-trips: `caesar_round_trips_random_plaintexts` `:2322`, `vigenere…` `:2340`, `incrementing_wheel…` `:2358`, `chaocipher…` `:2379`, `deck_cipher…` `:2402`, `agl_gak…` `:2426`, `gak_round_trips_random_plaintexts_small_and_eye` `:2457`. These tests use `.unwrap()` (allowed in tests via `clippy.toml`) and call the **free functions by name** — they must keep doing so unchanged.

**Downstream consumers of the free functions** (call sites that must keep compiling and behaving identically):
- `src/cipher_attack.rs:26-30` imports `caesar_decrypt`, `caesar_encrypt`, `chaocipher_decrypt`, `deck_cipher_decrypt`, `incrementing_wheel_decrypt`, `vigenere_decrypt`, `vigenere_encrypt`; call sites at `:630, :656, :699, :729, :772, :1180, :1192`. (This file also has its own `CipherFamily` enum with `label()` strings — `"Caesar"`, `"incrementing-wheel"`, `"Vigenere"`, `"Chaocipher"`, `"S_N deck"` — at `src/cipher_attack.rs:207-218`, covering five of the seven; `Cipher::name()` strings should be chosen consistently but this enum is **not** changed here.)
- `src/modular_diff.rs:14-15` imports + uses `incrementing_wheel_encrypt` `:1023`, `vigenere_encrypt` `:1034`, `deck_cipher_encrypt` `:1055`.
- `src/pyry_conditions.rs:17-18` uses `vigenere_encrypt` `:940`, `deck_cipher_encrypt` `:968`, `incrementing_wheel_encrypt` `:987`.
- `src/agl_gak.rs:9-12` imports the lower-level AGL group helpers (`agl_apply`, `agl_compose`, `agl_coset_symbol`, …) and `AglMultiplierSubgroup` — **not** `agl_gak_encrypt`/`decrypt`. It is *not* a consumer of the family free functions and needs no change.
- `src/gak_attack.rs:63-64` imports `gak_encrypt` (plus `GakKey`, `GakKeyOptions`, `CosetReadout`, `CipherError`, and — since 71d25fe's E1 dedup — the shared `compose_permutations`); production call sites at `:915, :2252`; its test module `:6433` additionally imports `gak_decrypt` at `:6443` and calls both (`gak_decrypt` `:6460, :6790, :6959, :7030, :7311`; `gak_encrypt` `:6465, :7053, :7054`).

The associated-type constraint is real and material — but the precise reason it forces an enum is subtler than "object-unsafe." An associated type does **not** outright forbid trait objects: you *can* name `dyn Cipher<Key = CaesarKey>` by binding the associated type. The problem is that binding it **pins a single key type**, so such a trait object can only ever represent **one family's** key, while each of the seven families has a *different* `Key` (`CaesarKey`, `VigenereKey`, …, `GakKey`). No single `dyn Cipher<Key=…>` binding spans families, so it gives **no heterogeneous dispatch** across them. The overview already anticipates this (`00-OVERVIEW.md` §"1. `trait Cipher` — unify the cipher zoo (brief 02)", the `AnyCipher` dispatch enum): heterogeneous search therefore goes through an `AnyCipher` **enum**, which owns each variant's concrete key, rather than any `dyn Cipher` / `Box<dyn Cipher>` form.

## Target design (concrete API / types / layout)

All additions land in the single `src/ciphers.rs`. Two layout moves are explicitly out of scope here (see Out-of-scope): the **thin move** `ciphers.rs` → `ciphers/mod.rs` (content unchanged) is **brief 07B**; the physical **one-file-per-family split** of `ciphers.rs` is a **deferred follow-up not owned by any current brief** (a future brief-02 extension) — it is **not** brief 07B.

### 1. `trait Cipher`

Matches `00-OVERVIEW.md` §"1. `trait Cipher` — unify the cipher zoo (brief 02)" (the `trait Cipher` sketch) exactly:

```rust
/// A cipher family: encrypts/decrypts `Glyph` sequences under a family-specific key.
///
/// Implementors are zero-sized family markers (the per-instance configuration
/// lives in [`Cipher::Key`]); the canonical transforms remain the module's
/// free functions, which these methods delegate to byte-for-byte.
pub trait Cipher {
    /// Family-specific key type (e.g. [`CaesarKey`]).
    type Key;
    /// Encrypts `plaintext` under `key`. See the family's free `*_encrypt`.
    /// # Errors
    /// Propagates the underlying [`CipherError`] unchanged.
    fn encrypt(&self, key: &Self::Key, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError>;
    /// Decrypts `ciphertext` under `key`. See the family's free `*_decrypt`.
    /// # Errors
    /// Propagates the underlying [`CipherError`] unchanged.
    fn decrypt(&self, key: &Self::Key, ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError>;
    /// Short, stable family name (used in candidate reports).
    fn name(&self) -> &'static str;
}
```

Note the **argument order differs from the free functions**: the trait takes `(key, sequence)` per the overview, while the free fns take `(sequence, key)`. The trait impls bridge this (`free_fn(plaintext, key)`), so there is no behavior change — only an ergonomic re-ordering at the trait surface. Keep this discrepancy documented in a `// ` comment on each impl so a cold reader does not "fix" it.

### 2. Seven zero-sized family markers + impls

One unit struct per family, each `impl Cipher` delegating to the existing free function:

```rust
/// Family marker for the Caesar additive shift cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caesar;
impl Cipher for Caesar {
    type Key = CaesarKey;
    fn encrypt(&self, key: &CaesarKey, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        caesar_encrypt(plaintext, key) // free fn is (seq, key); trait is (key, seq)
    }
    fn decrypt(&self, key: &CaesarKey, ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        caesar_decrypt(ciphertext, key)
    }
    fn name(&self) -> &'static str { "Caesar" }
}
```

…and analogously `Vigenere`/`VigenereKey`, `IncrementingWheel`/`IncrementingWheelKey`, `Chaocipher`/`ChaocipherKey`, `DeckCipher`/`DeckCipherKey`, `AglGak`/`AglGakKey`, `Gak`/`GakKey`. `name()` strings (proposed, stable, lowercase-free, human-readable): `"Caesar"`, `"Vigenere"`, `"incrementing-wheel"`, `"Chaocipher"`, `"deck"`, `"AGL-GAK"`, `"GAK"`. (These are *new* strings; they need not equal `cipher_attack::CipherFamily::label()` — that enum is untouched — but choosing the same five where they overlap is a courtesy. If brief 04 needs them to match, reconcile there.)

### 3. `AnyCipher` dispatch enum (the object-safety resolution)

Because `Cipher`'s associated `Key` type pins one key per `dyn Cipher<Key=…>` binding (so a single trait object cannot span the seven families' distinct keys), heterogeneous collections use an enum that **owns the key** and exposes `encrypt`/`decrypt` taking only the sequence:

```rust
/// A cipher family together with its key, for heterogeneous search.
///
/// `Cipher` has an associated `Key` type. A `dyn Cipher<Key = …>` trait object
/// must bind that type, so it can carry only one family's key — it gives no
/// heterogeneous dispatch across the seven families (each has a different `Key`).
/// This enum recovers runtime polymorphism instead: each variant pairs a family
/// with its concrete key, and the inherent `encrypt`/`decrypt` dispatch over the
/// closed set of seven families.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyCipher {
    /// Caesar additive shift, with its key.
    Caesar(CaesarKey),
    /// Periodic additive Vigenere, with its key.
    Vigenere(VigenereKey),
    /// Additive-progressive incrementing wheel, with its key.
    IncrementingWheel(IncrementingWheelKey),
    /// Generalized two-alphabet Chaocipher, with its key.
    Chaocipher(ChaocipherKey),
    /// Generalized `S_N` deck-keystream cipher, with its key.
    DeckCipher(DeckCipherKey),
    /// AGL(1,n)-GAK stream cipher, with its key.
    AglGak(AglGakKey),
    /// General permutation-group GAK cipher, with its key.
    Gak(GakKey),
}

impl AnyCipher {
    /// Encrypts `plaintext` with the contained family/key.
    /// # Errors
    /// Propagates the underlying [`CipherError`].
    pub fn encrypt(&self, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        match self {
            Self::Caesar(k) => caesar_encrypt(plaintext, k),
            Self::Vigenere(k) => vigenere_encrypt(plaintext, k),
            Self::IncrementingWheel(k) => incrementing_wheel_encrypt(plaintext, k),
            Self::Chaocipher(k) => chaocipher_encrypt(plaintext, k),
            Self::DeckCipher(k) => deck_cipher_encrypt(plaintext, k),
            Self::AglGak(k) => agl_gak_encrypt(plaintext, k),
            Self::Gak(k) => gak_encrypt(plaintext, k),
        }
    }
    /// Decrypts `ciphertext` with the contained family/key.
    /// # Errors
    /// Propagates the underlying [`CipherError`].
    pub fn decrypt(&self, ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> { /* mirror, *_decrypt */ }
    /// Short, stable family name (delegates to the matching marker's [`Cipher::name`]).
    #[must_use]
    pub fn name(&self) -> &'static str { /* match → marker.name() or literal */ }
}
```

`AnyCipher` derives `Clone, Debug, PartialEq, Eq` only because **every** contained key already derives them (`CaesarKey` `:374`, `VigenereKey` `:411`, `IncrementingWheelKey` `:459`, `ChaocipherKey` `:510`, `DeckCipherKey` `:584`, `AglGakKey` `:674`, `GakKey` `:960` — verified). Do not add `Copy` (Vec-bearing keys are not `Copy`).

This is the cleanest of the overview's two sketches: dispatch over an owned-key enum, no `Box<dyn>`, no trait-object gymnastics. The `Cipher` trait remains useful for generic (monomorphized) call sites and as the documented contract each marker satisfies; `AnyCipher` is the runtime-heterogeneous front door brief 04 will consume.

## Implementation steps (ordered, each independently committable & green)

**Step 1 — Add `trait Cipher` + the seven markers + impls.** Insert after the free functions (around `src/ciphers.rs:1395`, before `enum Direction` at `:1397`). No call site changes; the trait is additive. Add a unit-test module section (or extend `mod tests`) with one trait-vs-free-fn equivalence test per family, e.g. `Caesar.encrypt(&key, &pt) == caesar_encrypt(&pt, &key)` and the decrypt mirror, reusing the existing tiny vectors. `make verify` green.

**Step 2 — Add `AnyCipher` enum + inherent `encrypt`/`decrypt`/`name`.** Insert directly after the markers. Add tests: for each variant, round-trip `AnyCipher::Foo(key).decrypt(&AnyCipher::Foo(key).encrypt(&pt)?)? == pt` reusing existing fixtures, and assert each variant's `encrypt` output byte-for-byte equals the corresponding free-fn output (so `AnyCipher` is proven to be a pure forwarder). `make verify` green.

**Step 3 (optional, behavior-preserving) — migrate one internal caller as a worked example.** Pick a single low-risk consumer that already imports a free fn pair — `gak_attack.rs` (`gak_encrypt` at `:915`) or one `cipher_attack.rs` site — and route it through `Cipher`/`AnyCipher`, asserting via golden-master (brief 01) that the produced statistic/decode is byte-identical. If brief 01's golden masters do not yet cover that path, **skip this step** and leave all callers on the free functions (the brief explicitly keeps free functions as the canonical path; migration is "incremental" and may defer entirely to brief 04). Document in the commit that no caller was forced. `make verify` (and `make check`) green.

Each step is a standalone commit; none removes a free function or alters a key constructor.

## Files to create / change / delete

- **Change** `src/ciphers.rs`: add `trait Cipher`, seven unit-struct markers + `impl Cipher`, `enum AnyCipher` + inherent methods, and new tests in `mod tests`. Add the needed imports to the test module's `use super::{…}` block (`:2201`) if the equivalence tests reference the new types. No existing item removed or signature-changed.
- **Change** `src/lib.rs`: nothing required (the new items are re-exported transitively via `pub mod ciphers`). If a crate-level convenience re-export is wanted, that is a brief-04 / 07B concern (the `lib.rs` role-directory move is 07B) — leave `lib.rs` untouched here.
- **No deletions.** The fourteen free functions stay exactly as-is (canonical impls + still imported by `cipher_attack.rs`, `modular_diff.rs`, `pyry_conditions.rs`, `gak_attack.rs`).
- **No new dependency** (so `deny.toml`/`cargo-machete` unaffected).

## Success criteria

- `pub trait Cipher` with `type Key` and `encrypt`/`decrypt`/`name` exists in `crate::ciphers`, matching `00-OVERVIEW.md` §"1. `trait Cipher` — unify the cipher zoo (brief 02)" (the `trait Cipher` sketch).
- Seven `impl Cipher` markers, each delegating to its free-fn pair; `pub enum AnyCipher` with seven variants and inherent `encrypt`/`decrypt`/`name`.
- Every existing test in `src/ciphers.rs` (known-vector `:2214-2301`, random round-trip `:2322-2484`) is **unchanged and passing**.
- New equivalence tests prove `Cipher`/`AnyCipher` output is byte-identical to the free functions for all seven families.
- All downstream files (`cipher_attack.rs`, `modular_diff.rs`, `pyry_conditions.rs`, `agl_gak.rs`, `gak_attack.rs`) compile unmodified (or, if Step 3 is taken, the one migrated caller produces golden-identical output).
- `missing_docs` satisfied: trait, every method, every marker struct, the enum, every variant, and every inherent method documented.

## Verification (exactly how to prove it)

- `make verify` green after **each** step (fmt-check + clippy `-D` + tests + rustdoc `-D` + cargo-deny). `make check` before final push.
- Brief-01 golden masters: run them before and after; the corpus base-7 cross-check and every null calibration must be byte-for-byte identical (they will be — no production path changes unless Step 3 migrates one, in which case its golden master must match).
- New tests assert exact-output equivalence (`assert_eq!(Caesar.encrypt(&k, &pt).unwrap(), caesar_encrypt(&pt, &k).unwrap())` etc.) and round-trips through `AnyCipher`.
- Confirm object-safety intuition is respected: do **not** add any `Box<dyn Cipher>`; a quick `grep -rn 'dyn Cipher' src/` must return nothing.
- `cargo doc` (via `make verify`'s `RUSTDOCFLAGS="-D warnings"`) must pass with the new doc items and intra-doc links (`[`CaesarKey`]`, `[`CipherError`]`, `[`Cipher::name`]`).

## Risks & honesty caveats

- **Argument-order trap.** `Cipher::encrypt(key, seq)` vs free `*_encrypt(seq, key)` is easy to mis-wire; a swapped pair would still type-check (both `&[Glyph]`/`&Key` are positionally distinct, so actually it would *not* type-check — good — but the *meaning* is what matters). The equivalence tests in Steps 1–2 are the guard; do not skip them.
- **`name()` strings are new metadata, not a finding.** They are cosmetic labels for candidate reports; they assert nothing about the puzzle. They need not equal `CipherFamily::label()`. Pick stable strings and note in the doc that they are display-only.
- **Behavior-preserving is mandatory.** This refactor must not change any statistic or decode (`00-OVERVIEW.md` §"Shared ground rules" ("Behavior-preserving")). Because the free functions remain canonical and the trait/enum only forward, the risk is confined to Step 3; if golden-master coverage is thin there, defer the migration rather than risk a silent drift.
- **No claim-ceiling impact.** This is plumbing for the *search* engine, not the engine itself; nothing here decodes or scores. The standing candidate-logging directive does not apply (no candidate cleartext is produced).
- **The pinned-`Key` constraint is the load-bearing design fact.** A future reader might "simplify" to `Box<dyn Cipher>`; that does not even compile without binding the associated type, and once bound (`dyn Cipher<Key = CaesarKey>`) it carries only one family's key — no heterogeneous dispatch across the seven. The `AnyCipher` enum exists precisely to recover that heterogeneity by owning each variant's concrete key — call it out in the enum doc comment.

## Out of scope / non-goals

- **Moving `ciphers.rs` into a `ciphers/` directory.** Two distinct moves, both out of scope here, must not be conflated:
  - The **thin move** `ciphers.rs` → `ciphers/mod.rs` (content unchanged — `mod.rs` holds today's file verbatim) is **brief 07B** (`00-OVERVIEW.md` §"Target module layout").
  - The physical **one-file-per-family split** of `ciphers.rs` (a separate file per cipher family) is a **deferred follow-up not owned by any current brief** — a future brief-02 extension, **not** brief 07B (07B's role-directory move is a thin move only and does not split families). Everything in *this* brief stays additive inside the single `src/ciphers.rs`.
- **The solve pipeline, `HypothesisSpace`, `Candidate`, mapping search** — **brief 04** (`00-OVERVIEW.md` §"5. The solve pipeline — the prize (brief 04)"). This brief only provides the `AnyCipher` it consumes.
- **Touching the `*Key` constructors, validation, or the AGL/GAK group helpers** (`agl_compose`, `agl_step_lookup`, `CosetReadout`, etc.) — out of scope; they are dependencies, not targets.
- **Refactoring `cipher_attack::CipherFamily`** or unifying its `label()` with `Cipher::name()` — leave it; revisit in brief 04/08 if the registry needs it.
- **Forcing all callers onto the trait.** Migration is incremental and optional here (Step 3); the free functions remain the supported API for this brief.
