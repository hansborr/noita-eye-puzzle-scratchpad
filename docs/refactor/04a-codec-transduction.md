# 04a — Codec / transduction layer

> One-line: build the missing **codec / transduction (grouping) layer** that sits between `decrypt` and the symbol→letter `mapping` — the component that lets a *small* cipher alphabet (5 digits, 12 letters, 6 digits) carry 26–29-letter natural language by first widening the value alphabet (e.g. base-5 trigram grouping, exactly the eye **honeycomb** reading layer) — so brief 04's `solve`, the general classical-cipher cracker, can attempt English recovery on the small-alphabet validation samples it explicitly defers (`research/data/practice-puzzles/` `one`/`two`/`six`).
> Status: not started · Depends on: 04 (`solve`/`Mapping`/`Candidate` it extends), 03 (ingest), 01 (golden-master safety net) · Reuses: 02 (`AnyCipher`) · Blocks: — · Size: L

## Goal & why it matters

Brief 04 builds the unified `solve` engine — the **general classical-cipher cracker** (cipher families × keys × symbol→letter mappings, three independent gates, auto-logged HYPOTHESIS candidates), whose correctness is validated on the external, English-recoverable corpus at `research/data/practice-puzzles/`. But brief 04's `Mapping` is a **direct** symbol→letter substitution, and a direct substitution presupposes **cipher-alphabet ≥ language-alphabet** (`04-solve-pipeline.md` "Transduction / codec layer (`codec`; designed in brief 04a)"). That is well-posed for the **eyes** (the 83-symbol reading layer exceeds the 29-symbol language alphabet) but **structurally impossible** for a small cipher alphabet: 5 digits cannot index 26–29 letters, 12 letters cannot index 26–29 letters, and 6 digits cannot index 26–29 letters, under any one-to-one or many-to-one *symbol→letter* map. Brief 04 therefore **retargets** small-alphabet English recovery to this brief and leaves a forward pointer; recovering the small-alphabet validation samples' English is **owned here**. These samples are the cracker's credibility ladder — an engine that reliably cracks them is one we can trust on the real target. The **eyes remain the primary end goal and the sole honest-negative** (decode BLOCKED on the unknown symbol→meaning mapping); broadening to the practice corpus does not dilute the eye-puzzle focus.

The missing component is a **codec / transduction layer**: it regroups/transduces the *decrypted* cipher-symbol stream into a (usually larger) value alphabet **before** the mapping runs, so a symbol→letter mapping can span a natural-language alphabet. This is codex review point #1 and the last undesigned piece of the small-alphabet recovery pipeline. The canonical real-world instance already lives in this crate: the eye **honeycomb** reading layer groups base-5 orientation digits into **trigrams** with raw value `0..=124`, of which the contiguous `0..=82` are the accepted reading-layer alphabet (`READING_LAYER_ALPHABET_SIZE = 83`, `src/orders.rs:24`; raw trigram range `0..=124` per `src/trigram.rs:28`/`:42`/`:52`, accepted `0..=82` per `src/orders.rs:835`/`:851`/`:879`; `EYE_READING_ALPHABET_SIZE = 83`, `src/ciphers.rs:20-21`). The codec generalizes exactly that operation — `k` consecutive base-`b` digits → one value in `0..b^k` — and applies it to the **decrypted** stream: `decrypt → codec → mapping → text`.

Why this matters for the three codec/grouping samples in the corpus — **and the honesty boundary that governs them** (see `research/data/practice-puzzles/README.md` for the verified-fact inventory; all "modes" are structural HYPOTHESES, not confirmed cipher identifications):

- **`one`** (`research/data/practice-puzzles/one`, formerly `/tmp/gak_cipher_example`) is an **EXTERNAL sample** (not ours), **hypothesized to be decryptable to English**, for which we do **not** currently have ground-truth cleartext. The only verified, reproducible facts: 266 symbols over `{0,1,2,3,4}` (no spaces), and **every one of the 265 transitions is ±1 mod 5** — a walk on the pentagon `C5`. That ±1-`C5` structure is an *observed property of the ciphertext* and a **search hint** (a Delta / grouping codec is the natural first attempt), **not** evidence of "no message" and **not** a trivial fixture. Recovering its English is a **GOAL / HYPOTHESIS**, never an established decode.
- **`two`** (`research/data/practice-puzzles/two`, formerly `/tmp/gak_example_two`) is an **EXTERNAL sample** whose English is **known to the maintainer but deliberately NOT committed** (so the engine cannot be tuned to it): 698 symbols over a 12-letter alphabet `{A..L}` (no spaces), near-flat marginal. Once the maintainer confirms a recovered candidate against the withheld cleartext we **promote it to a known-answer regression constant** and assert exact-match recovery; until then the criterion is that the pipeline runs and surfaces a high-scoring, held-out-validated English candidate, **logged as a labelled HYPOTHESIS**, with the exact-match assertion marked pending the (withheld) constant.
- **`six`** (`research/data/practice-puzzles/six`) is an **EXTERNAL sample**, **hypothesized to be decryptable to English**, and the **clearest base-N-grouping case** in the corpus: 417 symbols over 6 digits `{1..6}` **with preserved spaces** (3 data lines, word boundaries; `H1≈2.582/2.585`, not a pure walk). A single base-6 digit (alphabet 6) cannot index 26–29 letters, but **pairs of base-6 digits → values ≤36 ≥ 26** can host the language — exactly a `FixedGrouping { group_len: 2, base: 6 }` followed by a symbol→letter mapping. Its **preserved spaces also exercise transparent-symbol passthrough** (brief 04's transparent-symbol passthrough): the spaces are **transparent symbols**, not cipher symbols — they pass through the codec unchanged and are reinserted at their positions into `rendered_text` (brief 03's `CipherAlphabet`/`TransparentSet` ingest records them separately; the codec and mapping operate only on the cipher-digit stream; the bigram scorer skips them). Recovering its English is a **GOAL / HYPOTHESIS**, never an established decode.

None of these corpus samples is an honest-negative. The **sole honest-negative** in these briefs is the **eyes** — decode BLOCKED on the unknown symbol→meaning mapping (their codec is `Identity`; 83 ≥ 29). The claim ceiling is unchanged: *deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved* (`research/gak-threads/candidates/README.md:13-14`) — and the same ceiling governs the external samples (a scored candidate is never a decode until a human confirms it against ground truth). This brief tries genuinely to recover the corpus samples' English while never reporting a scored candidate as a decode: a codec just *widens* the alphabet — it is not a free decode, and every surviving candidate rides the same three gates plus a codec round-trip and is auto-logged as a labelled HYPOTHESIS.

## Current state (grounded, with file:line)

**The honeycomb grouping already exists — as analysis, not as a reusable codec.** `src/orders.rs` reconstructs the rendered grids and reads them under order families; the reading-layer alphabet is `READING_LAYER_ALPHABET_SIZE = 83` (`src/orders.rs:24`). Raw base-5 trigram values run `0..=124` (`src/trigram.rs:28` "the base-5 value in `0..=124`"; `TrigramValue` accepts `value <= 124`, `src/trigram.rs:52`); only the contiguous `0..=82` are the accepted reading-layer alphabet (`ReadingLayerSpread::is_contiguous_0_to_82`, `src/orders.rs:835-843`; the flatness stats count "trigrams outside the `0..=82` reading-layer alphabet", `src/orders.rs:851`/`:879`). `glyph_messages_from_values` then maps each accepted trigram value → `Glyph(value)` (`src/orders.rs:967`). This is exactly a `FixedGrouping` codec (`group_len = 3`, `base = 5`) followed by an accept-`0..=82` filter — but it is welded into the reading-order experiments and is **not** exposed as a `Codec` that `solve` can drive. There is **no `Codec` trait, no `AnyCodec` enum, no grouping codec, and no delta codec anywhere in the crate** — this brief creates them.

**The accepted-alphabet boundary `solve` consumes** — `cipher_attack`/`solve` reject any reading-layer value `≥ 83`: `glyph_messages_from_values` returns `CipherAttackError::ValueOutsideEyeAlphabet { value }` when `usize::from(raw) >= EYE_READING_ALPHABET_SIZE` (`src/cipher_attack.rs:471-475`). So a codec emitting raw `0..=124` trigram values would feed *out-of-alphabet* symbols downstream; the `FixedGrouping` instance that models the honeycomb must therefore pair grouping with an accept-`0..=82` policy (or document the value range it produces and let the alphabet-size sanity gate reject mismatches). The accepted eye reading alphabet is contiguous `0..=82` (`src/ciphers.rs:20` "values `0..=82`", `EYE_READING_ALPHABET_SIZE = 83`) — the same alphabet brief 03's `HoneycombReading` ingest layer loads (`03-external-ingest.md`; values `83..=124` are rejected as `InvalidToken`); raw `0..=124` ingest is a separate, out-of-scope layer there and here.

**The brief-04 pipeline this extends** — brief 04's `solve` produces, per `(cipher, key)`, `decrypted_symbols: Vec<Glyph>` (cipher-layer output, **not** language) gated by `crypto_round_trip_ok`, then a `Mapping` (`mapping: Mapping`, possibly many-to-one/non-invertible) producing `rendered_text`, scored in-sample (`score`), on a held-out fold (`heldout_mapping_score`), and against a matched null (`beats_null`) — see `04-solve-pipeline.md` `Candidate` struct and the "Three independent gates" section. Brief 04 already sets the `Candidate.codec: AnyCodec` field (Phases 1–2 use `AnyCodec::Identity`, correct when cipher-alphabet ≥ language-alphabet, e.g. the 83-symbol eyes) and points here for the codec search. This brief plugs a transduction stage *between* `decrypted_symbols` and `mapping`.

**The cipher dispatch (from brief 02)** — `AnyCipher` is the heterogeneous enum over the seven families (`02-cipher-trait.md` §3, wrapping `CaesarKey` `src/ciphers.rs:375` … `GakKey` `src/ciphers.rs:961` and the `*_encrypt`/`*_decrypt` free fns `src/ciphers.rs:1106-1394`). The codec round-trip composes with the cipher round-trip through this surface: re-encrypt requires re-expanding the transduced stream to cipher symbols, then `AnyCipher::encrypt`. **If brief 02 lands a different name/shape, follow brief 02 and update this brief's cross-references.**

**The ingest front door (from brief 03)** — `parse_sequence(text, layer)` / `load_sequence(input, layer)` over `enum Input<'a> { Str(&'a str), Path(&'a Path) }` (no `Stdin` variant; the CLI reads stdin) return a `ParsedSequence` (`.glyphs` is the cipher-symbol stream, `.transparent` the recorded pass-through marks) and cover the eye *digit* layers. Puzzle `one` (`{0..4}` digits) rides `parse_sequence`; puzzle `two` (`{A..L}`) rides `solve --alphabet ABCDEFGHIJKL --input-file research/data/practice-puzzles/two` → `Alphabet::from_chars` (`src/glyph.rs:165`) → `parse_sequence` with a `SequenceLayer::CipherAlphabet` layer; puzzle `six` (`{1..6}` digits **with spaces**) rides the same `CipherAlphabet`/`TransparentSet` transparent-symbol ingest path where its spaces are configured **transparent symbols** (recorded by position in `.transparent`, not `InvalidToken`), feeding only the cipher-digit stream (`.glyphs`) into the codec. `Glyph` is `pub struct Glyph(pub u16)` (`src/glyph.rs:140`). **At test time use the checked-in corpus files (`research/data/practice-puzzles/`), never `/tmp`.**

**The scorer + gate machinery to reuse** — `LanguageModel::score_indices` is the objective (the bigram mean log-likelihood), over the 29-symbol `DEFAULT_LANGUAGE_ALPHABET` via `english_model()`/`finnish_model()`; the held-out calibration test (`held_out_language_calibration_separates_english_and_finnish`, `src/language.rs:584+`) is the held-out pattern to mirror. Randomness flows through `SplitMix64` (`src/null.rs:38`); the matched null uses `null::fisher_yates` (`src/null.rs:143`) + `null::add_one_p_value` (`src/null.rs:91`), `shuffled_permutation` (`src/null.rs:159`) for restarts. The candidate-logging protocol (`research/gak-threads/candidates/README.md`) binds: claim ceiling verbatim (`:13-14`), held-out + matched-null kill order (`:37-53`), HYPOTHESIS-not-decode label, English **and** Finnish scores + caveats even if failing (`:70-72`), stable seed-derived filename (no clock, `:62-64`).

## Target design (concrete API / types / layout)

New module `crate::codec` (a new file `src/codec.rs` registered in `lib.rs`; the physical move under `src/attack/` is brief 07B's job — keep it a flat `pub mod codec;` for now). It is a peer of brief 04's `crate::solve`.

### Canonical Codec API (use these shapes verbatim — shared across 04 and 04a)

```rust
// crate::codec  (physical home under attack/ is brief 07B's move; flat pub mod for now)

/// Regroups/transduces a DECRYPTED cipher-symbol stream into a (usually larger)
/// value alphabet, so a symbol->letter mapping can span a natural-language
/// alphabet. This is the layer that lets a SMALL cipher alphabet (5 digits, 12
/// letters) carry English: a direct symbol->letter substitution cannot (5<26,
/// 12<26); a grouping/transduction first widens the alphabet. The eye honeycomb
/// reading layer (base-5 trigrams -> 0..=124, accepted 0..=82; orders.rs) is the
/// canonical instance.
pub trait Codec {
    /// Transduce decrypted symbols into the output value alphabet.
    /// # Errors
    fn transduce(&self, symbols: &[Glyph]) -> Result<Vec<Glyph>, CodecError>;
    /// Output value-alphabet size (the mapping's domain).
    fn output_alphabet_size(&self) -> usize;
    /// Stable family name for candidate reports.
    fn name(&self) -> &'static str;
    /// Whether transduce is invertible (enables a codec round-trip check).
    fn is_invertible(&self) -> bool;
}

/// Heterogeneous dispatch enum (same pattern as AnyCipher; Codec has no assoc type
/// here, but the enum keeps the closed family set explicit and searchable).
pub enum AnyCodec {
    /// Pass-through: output alphabet == input alphabet. Used when the cipher
    /// alphabet already >= the language alphabet (e.g. the 83-symbol eyes).
    Identity,
    /// Group `group_len` consecutive base-`base` digits into one value in
    /// 0..base^group_len (the honeycomb generalization). Invertible on
    /// full-length multiples.
    FixedGrouping(GroupingCodec),
    /// First-difference (mod `base`) of the stream, then an inner codec (usually
    /// Identity or FixedGrouping). Captures the ±1-walk structure of practice
    /// puzzle `one` (research/data/practice-puzzles/one). Invertible given a seed
    /// symbol.
    Delta(DeltaCodec),
}
pub struct GroupingCodec { pub group_len: usize, pub base: usize, pub order: DigitOrder, pub stride: usize }
pub struct DeltaCodec   { pub base: usize, pub then: Box<AnyCodec> }
pub enum DigitOrder { Msb, Lsb }
```

`AnyCodec` implements `Codec` by dispatching over the closed set (the same pattern brief 02's `AnyCipher` uses for ciphers). Semantics:

- **`Identity`** — `transduce` is the identity; `output_alphabet_size` == the input cipher-alphabet size; `is_invertible() == true`. This is the eyes' codec (the 83-symbol layer already exceeds the 29-symbol language alphabet, so no widening is needed). Brief 04's Phases 1–2 use exactly this.
- **`FixedGrouping(GroupingCodec)`** — group `group_len` consecutive base-`base` digits (in `DigitOrder::Msb`/`Lsb` order, advancing by `stride`) into one value in `0..base^group_len`; `output_alphabet_size() == base.pow(group_len)`. The honeycomb generalization: `group_len = 3`, `base = 5`, `stride = 3` (non-overlapping) reproduces the base-5 trigram grouping whose raw range is `0..=124` (`src/trigram.rs:28`). `is_invertible() == true` on full-length multiples of `group_len` (a trailing partial group is the only loss; document and reject/flag it). The honeycomb's accepted-`0..=82` filter (`src/cipher_attack.rs:471`, `EYE_READING_ALPHABET_SIZE`) is **not** part of grouping — it is the *alphabet-size sanity* policy below; a `FixedGrouping` that emits values `83..=124` is flagged/rejected for the accepted-eye-alphabet consumer, exactly as `cipher_attack`/`solve` reject value ≥ 83.
- **`Delta(DeltaCodec)`** — first-difference mod `base` of the stream, then the inner `then` codec (usually `Identity` or a `FixedGrouping`). This captures the **±1-walk structure of puzzle `one`** (`research/data/practice-puzzles/one`): differencing a `C5` walk yields a stream over `{+1, -1}` ≡ `{1, 4}` mod 5, collapsing the alphabet to the *moves* — a natural first hypothesis for a small-alphabet sample whose transitions are all ±1 mod 5 (the observed structural property, an explicit search hint, **not** a claim of "no message"). `is_invertible() == true` **given a seed symbol** (the first symbol, recorded so re-integration reproduces the original); `output_alphabet_size` is the inner codec's, computed over the differenced alphabet.

`CodecError` is a hand-written enum with `Display` + `std::error::Error` (mirroring `CipherError`/`CipherAttackError` style), with at least: `LengthNotGroupMultiple { len, group_len }`, `ValueOutsideBase { value, base }`, `EmptyInput`, and `NonInvertible` (for a codec-round-trip attempt on a lossy codec). No `unwrap`/`panic` in this code.

### `CodecStrategy` — the search space (bounded + logged caps)

```rust
pub enum CodecStrategy {
    /// Phase 1: a declared set of codecs. Round-trips + scores only, no search.
    Fixed(Vec<AnyCodec>),
    /// Phase 2: enumerate codec parameters; for each, run brief 04's mapping
    /// search on the transduced stream; rank by held-out + matched-null.
    Search(CodecSearch),
}

pub struct CodecSearch {
    pub max_group_len: usize,     // K_MAX: group_len in 1..=K_MAX
    pub try_delta: bool,          // delta in {off, on}
    pub orders: Vec<DigitOrder>,  // subset of {Msb, Lsb}
    pub seed: u64,                // drives SplitMix64; same seed => same enumeration
    // base is fixed to the cipher alphabet size (not searched).
}
```

- **`Fixed(Vec<AnyCodec>)`** — Phase 1: a declared set (`Identity`; the honeycomb `FixedGrouping { group_len: 3, base: 5, order: Msb, stride: 3 }`; a few `k`/`base`/`order`/`delta` variants). Round-trips + scores only.
- **`Search(CodecSearch)`** — Phase 2: enumerate `group_len ∈ 1..=max_group_len`, `base` = the **cipher alphabet size** (not searched — it is fixed by the sample, e.g. 5 for puzzle `one`, 12 for puzzle `two`, 6 for puzzle `six` where `group_len = 2` gives `6²=36 ≥ 26`), `order ∈ orders`, `delta ∈ {off, on}` (when `try_delta`). For **each** candidate codec, run **brief 04's mapping search** (`MappingStrategy::Search`) on the **transduced** stream (cipher symbols only — any transparent symbols are passed through per brief 04's transparent-symbol passthrough), then rank by `heldout_mapping_score` + matched null. **Bounded with logged caps:** every enumeration cap (`max_group_len`, the `base^group_len` output-alphabet ceiling beyond which a codec is skipped as too wide to map honestly, the order/delta subset) is documented and any skipped configuration is **`log()`-ed — no silent truncation** (overview ground rule + AGENTS.md "no silent failures"). Output-alphabet sanity (below) prunes codecs whose widened alphabet cannot host the language *or* explodes past the cap; record which and why.

### Candidate extension (lives in brief 04, restated here for the full pipeline)

Brief 04's `Candidate` carries `pub codec: AnyCodec` (the `Candidate.codec` field in brief 04's solve pipeline). The full pipeline is:

```
rendered_text = mapping.apply(codec.transduce(cipher.decrypt(key, ciphertext)))
```

`decrypted_symbols` stays the **pre-codec** cipher output (the cipher-layer round-trip gate operates on it unchanged). Optionally a `codec_round_trip_ok: bool` travels alongside `crypto_round_trip_ok`. The mapping's domain is now the **codec's** `output_alphabet_size()`, not the raw cipher alphabet — that is the whole point: a 5- or 12-symbol cipher alphabet becomes a wider value alphabet the mapping can map onto 26–29 letters.

## Gates (three from brief 04, plus the codec round-trip — never collapsed)

Brief 04's three gates carry through, now applied at the **transduced + mapped** level, with the codec round-trip added as a fourth structural check. They are independent and must not be conflated:

- **`codec_round_trip_ok` — codec invertibility consistency.** Where the codec `is_invertible()`, re-expand `transduced → symbols` (e.g. ungroup digits / re-integrate a delta from its seed symbol) and re-encrypt → ciphertext must reproduce it **byte-for-byte** (this combines with brief 04's cipher round-trip: `cipher.encrypt(key, expand(transduced)) == ciphertext`). Where the codec is **lossy** (e.g. a trailing partial group, or an accept-`0..=82` filter that drops `83..=124`), mark it `is_invertible() == false`, record `codec_round_trip_ok = false` honestly, and rely on the other gates. A codec round-trip proves only codec+cipher consistency — like the cipher round-trip, it says **nothing** about whether the mapping decodes anything.
- **Alphabet-size sanity.** The transduced alphabet must be **large enough to host the language**: a codec whose `output_alphabet_size()` is smaller than the language alphabet (29 for `DEFAULT_LANGUAGE_ALPHABET`) cannot carry that language under a symbol→letter mapping and is **rejected for that language** (document the threshold; for English/Finnish here it is the 29-symbol alphabet, or a reduced-alphabet language model if one is declared). Symmetrically, a codec whose output alphabet explodes past the search's logged ceiling is skipped (and logged). This is the gate that formalizes "5<26, 12<26 ⇒ you need a codec": `Identity` over a 5- or 12-symbol cipher alphabet **fails** alphabet-size sanity for 29-letter English, which is precisely why brief 04 defers small-alphabet recovery to here.
- **`heldout_mapping_score` + matched-null** — exactly as brief 04 (`04-solve-pipeline.md` "Three independent gates"), now computed on the transduced+mapped stream: fit/search the mapping on a train fold of the transduced stream, score on a disjoint held-out fold; rerun the **identical** codec+mapping search on a Fisher-Yates-shuffled ciphertext and require the real best to beat the matched-null best. On a single short stream the held-out fold may be uninformative; the matched null then carries the load. (The eye 83→29 mapping remains many-to-one ⇒ non-invertible; that is why these two gates, not a mapping round-trip, are load-bearing — unchanged from brief 04.)

Together: codec round-trip (codec/cipher consistency), alphabet-size sanity (the codec can host the language at all), held-out (mapping confidence on unseen data), matched null (search did not manufacture a winner). A high in-sample score with a failed sanity check, a flat held-out fold, or a beaten null is **overfit, not a decode**.

## Implementation steps (ordered, each independently committable & green)

> **Hand-off note:** Phase 1 (steps 1–4) builds the codec types + the round-trip/sanity gates + the `Fixed` pipeline wiring and is independently valuable. Phase 2 (steps 5–7) adds the `Search` enumeration on top of brief 04's mapping search. Steps 8–9 (positive controls + the two external samples + auto-logging) sit on top of Phase 2.

**Phase 1 — codec types, round-trip, sanity, fixed pipeline.**
1. **`Codec` trait + `AnyCodec`/`GroupingCodec`/`DeltaCodec`/`DigitOrder` + `CodecError`.** New `src/codec.rs` with the canonical API verbatim (above). Implement `transduce`/`output_alphabet_size`/`name`/`is_invertible` for `Identity` and `FixedGrouping`; `CodecError` as a hand-written enum with `Display` + `std::error::Error`. Document every public item. Unit-test: `Identity` is the identity; `FixedGrouping { 3, 5, Msb, 3 }` maps `[d0,d1,d2]` → the base-5 trigram value matching `src/trigram.rs` (cross-check a couple of hand values against the honeycomb), and a non-multiple length errors with `LengthNotGroupMultiple`. *(Green: compiles, `make verify`.)*
2. **`DeltaCodec` + the ±1-`C5` model.** Implement `Delta`: first-difference mod `base`, then the inner codec; record the seed symbol for inversion. Unit-test on a synthetic `C5` walk that differencing yields the move stream and re-integration from the seed reproduces the original. *(Green: delta round-trips on a synthetic ±1-`C5` stream; `make verify`.)*
3. **`codec_round_trip_ok` + alphabet-size sanity helpers.** Add the codec round-trip check (re-expand → compare; honest `false` for lossy codecs) and the alphabet-size sanity predicate (`output_alphabet_size() >= language_alphabet_size`, with the threshold documented). Unit-test: an invertible `FixedGrouping` on a full-multiple stream round-trips; `Identity` over a 5-symbol alphabet **fails** sanity for the 29-symbol language; a `FixedGrouping` emitting `83..=124` is flagged for the accepted-eye-alphabet consumer. *(Green: gate helpers tested; `make verify`.)*
4. **Wire `AnyCodec` into brief 04's pipeline (`Fixed`).** Insert the codec stage so `solve` computes `rendered_text = mapping.apply(codec.transduce(decrypted_symbols))` and carries `codec` + `codec_round_trip_ok` on the `Candidate`. Default codec is `Identity` (Phases 1–2 of brief 04 unchanged for the eyes). Add `CodecStrategy::Fixed(Vec<AnyCodec>)` to the `HypothesisSpace`. *(Green: a synthetic test plants English through a known `FixedGrouping` + known cipher + known mapping; `solve` with the matching `Fixed` codec recovers it as the top, round-trip-consistent candidate. The eyes path with `Identity` is byte-for-byte unchanged.)*

**Phase 2 — codec search.**
5. **`CodecStrategy::Search` + `CodecSearch` enumeration (bounded + logged).** Enumerate `group_len ∈ 1..=max_group_len`, `base` = cipher alphabet size, `order ∈ orders`, `delta ∈ {off,on}`; for each codec, prune by alphabet-size sanity and the logged output-alphabet ceiling (`log()` every skip — no silent truncation), then run brief 04's `MappingStrategy::Search` on the transduced stream. All randomness via `SplitMix64(seed)`. *(Green: a `Search` recovers the planted `FixedGrouping`+mapping on synthetic ground truth, reproducible for a fixed seed; a test asserts an out-of-budget codec is logged-and-skipped, not silently dropped.)*
6. **Held-out + matched-null at the transduced level.** Apply brief 04's held-out fold and Fisher-Yates matched null to the codec+mapping search (rerun the *identical* enumeration on shuffled ciphertext). *(Green: matched null stays flat under codec search — a codec search on noise does not manufacture a winner; held-out fold above the shuffled baseline on the synthetic plant.)*
7. **Delta-codec search path for the ±1-`C5` hint.** Ensure `try_delta` enumerates `Delta { base: 5, then: … }` for a 5-symbol sample (puzzle `one`); document the ±1-`C5` observation as the motivating hint in a code comment (an *observed ciphertext property*, not a decode). *(Green: on a synthetic delta-encoded plant, the delta path recovers it; reproducible.)*

**Phase 2 capstone — positive controls, external samples, auto-logging.**
8. **Synthetic plant-through-codec positive control (the real proof).** Plant a known English plaintext → **inverse codec** (e.g. expand letters into base-5 digit groups) → known cipher → ciphertext; assert `solve`+codec recovers the (cipher key + codec + mapping) and reproduces the **exact planted English**, round-trip-consistent + held-out-valid + beating the matched null (mirrors brief 04's `run_positive_controls`). This is the proof the codec search works end-to-end. *(Green: exact planted English recovered; `make verify`.)*
9. **Corpus codec/grouping samples (`one`/`two`/`six`) + auto-logging.** All three read from the **checked-in corpus files** under `research/data/practice-puzzles/` (includable like other `research/data/...` assets), never `/tmp`.
   - **Honest success criterion (binding, shared by all three):** since no cleartext is committed, the criterion is that `solve`+codec surfaces a **high-scoring, held-out-validated, human-readable English candidate** that beats the matched null, **logged as a labelled HYPOTHESIS** to `research/gak-threads/candidates/` for human readability confirmation — **NOT** an automated exact-match against a string we don't hold. **Lifecycle:** once a human confirms a puzzle's plaintext, **promote it to a known-answer regression constant** and add the exact-match assertion then. Automated tests may assert: the pipeline runs end-to-end, the four gates fire, a candidate is logged, and the winning candidate's language score exceeds the matched-null by a margin (statistical pass) — never a hard-coded plaintext.
   - **`one`** (`research/data/practice-puzzles/one`, formerly `/tmp/gak_cipher_example`; English HYPOTHESIZED, NO cleartext): `solve`+codec runs end-to-end and any surviving candidate (passes codec round-trip + held-out + matched null) is logged as a labelled HYPOTHESIS. The ±1-`C5` structure is noted as a search hint (Delta/grouping codec the natural first attempt). Provenance noted (external sample, hypothesized recoverable English, cleartext not available to us).
   - **`two`** (`research/data/practice-puzzles/two`, formerly `/tmp/gak_example_two`; English known to the maintainer but **withheld / NOT committed**): the held-out-validated English candidate is logged as a HYPOTHESIS; the **exact-match assertion stays pending** the maintainer's withheld cleartext constant (a `#[ignore]`'d or `// TODO(cleartext)` exact-match test alongside the pipeline-runs test). Provenance noted (external sample, maintainer-asserted English, deliberately not committed so the engine cannot be tuned to it).
   - **`six`** (`research/data/practice-puzzles/six`; English HYPOTHESIZED, NO cleartext): the **clearest base-N-grouping case** — `FixedGrouping { group_len: 2, base: 6 }` widens 6 digits to `6²=36 ≥ 26` so the mapping can host the language; its **preserved spaces exercise transparent-symbol passthrough** (brief 04's transparent-symbol passthrough — spaces recorded by position at ingest, passed through the codec unchanged, reinserted into `rendered_text`, skipped by the bigram scorer). `solve`+codec runs end-to-end and any surviving candidate is logged as a labelled HYPOTHESIS. Provenance noted (external sample, hypothesized recoverable English).
   - **Auto-log** every emitted candidate via `write_solve_candidate_record`/`render_solve_candidate_record` (brief 04's writer, mirroring `write_eyes_candidate_record`): stable seed-derived filename (no clock), claim ceiling verbatim, HYPOTHESIS-not-decode label, English **and** Finnish scores + caveats, and all four gate verdicts (`crypto_round_trip_ok`, `codec_round_trip_ok`, `heldout_mapping_score`, matched-null) plus the chosen codec's `name()`.
   *(Green: all three samples run end-to-end; each record is a labelled HYPOTHESIS, not a decode; the `six` record shows preserved spaces in `rendered_text`; checked-in corpus files only — no `/tmp` at test time; `make check`.)*

## Files to create / change

**Create**
- `src/codec.rs` — the codec layer (`Codec`, `AnyCodec`, `GroupingCodec`, `DeltaCodec`, `DigitOrder`, `CodecError`, `CodecStrategy`, `CodecSearch`, the round-trip + alphabet-size-sanity helpers).
- A `#[cfg(test)]` fixtures helper in `codec.rs` for synthetic plant-through-codec fixtures (English → inverse codec → known cipher → ciphertext). For the external corpus samples, read the **checked-in corpus files** under `research/data/practice-puzzles/` (no `/tmp` at test time): puzzle `two` (`{A..L}`; its English cleartext constant is added only once the maintainer confirms it, i.e. promoted to a known-answer regression), puzzle `one` (`{0..4}`), and puzzle `six` (`{1..6}` **with spaces** — the transparent-passthrough case), each with provenance noted as a comment.

**Change**
- `src/lib.rs` — add `pub mod codec;` (in the same `pub mod` block as brief 04's `solve`).
- `src/solve.rs` (brief 04) — add the codec stage to the pipeline and `codec: AnyCodec` (+ optional `codec_round_trip_ok: bool`) to `Candidate`; add `codec: CodecStrategy` to `HypothesisSpace`. **Coordinate with brief 04** — these `Candidate.codec`/`HypothesisSpace` field edits are brief 04's; this brief supplies the codec types brief 04 references. If brief 04 lands first with `AnyCodec` stubbed, fill in the implementations here.
- `src/main.rs` — extend `SolveArgs` with codec controls: a `--codec` selector for the `Fixed` set (e.g. `identity`, `honeycomb`) and a `--codec-search` flag that flips `CodecStrategy::Fixed` → `Search` (parallel to brief 04's `--mapping-search`). Keep `main.rs` thin; the resolution stays in the library.
- `research/gak-threads/candidates/README.md` — note that `solve`/codec records carry the codec `name()` and the codec-round-trip verdict alongside the existing gates (the protocol already covers the record shape).

**Delete** — none. `src/orders.rs`'s honeycomb analysis stays as-is (behavior-locked by brief 01); `codec.rs` is the new reusable layer, not a rewrite of `orders.rs`.

## Success criteria

- **Synthetic plant-through-codec positive control (the real proof):** `solve`+codec recovers the planted (cipher key + codec + mapping) from a known-English-through-codec ciphertext and reproduces the **exact** planted English — round-trip-consistent, held-out-valid, beating the matched null. (Phase-1 fixed codec, then Phase-2 searched codec.)
- **Corpus codec/grouping samples (`one`/`two`/`six`):** since no cleartext is committed, the criterion is that `solve`+codec surfaces a **high-scoring, held-out-validated, human-readable English candidate** beating the matched null, **logged as a labelled HYPOTHESIS** to `research/gak-threads/candidates/` for human confirmation — never a hard-coded decode. Once a human confirms a puzzle's plaintext it is **promoted to a known-answer regression constant** (exact-match added then). `two`'s exact-match stays pending the maintainer's **withheld** cleartext. `six` is the clearest base-N-grouping case (`FixedGrouping { group_len: 2, base: 6 }`, `6²=36 ≥ 26`) and also exercises **transparent-symbol passthrough** (preserved spaces survive into `rendered_text`, per brief 04's transparent-symbol passthrough). `one`'s ±1-`C5` structure is documented as a Delta/grouping search hint. All read from `research/data/practice-puzzles/`, never `/tmp`.
- **Codec round-trip:** every emitted candidate carries `codec_round_trip_ok`; where the codec `is_invertible()`, re-expand+re-encrypt reproduces the ciphertext byte-for-byte; lossy codecs are honestly marked `false` and rely on the other gates.
- **Alphabet-size sanity:** a codec whose output alphabet cannot host the language is rejected for that language (`Identity` over 5 or 12 symbols fails for 29-letter English) — formalizing why small-alphabet recovery needs a codec; the threshold is documented.
- **Held-out + matched-null at the transduced level:** every emitted candidate carries `heldout_mapping_score`; the identical codec+mapping search on a Fisher-Yates-shuffled ciphertext does **not** beat the real result. An at-chance held-out score or a beaten null is treated as overfit, never a decode.
- **Bounded + logged search:** every enumeration cap is documented and every skipped codec configuration is `log()`-ed — no silent truncation.
- **Auto-logging:** every emitted candidate is written to `research/gak-threads/candidates/` as a labelled HYPOTHESIS with the codec `name()`, English+Finnish scores, caveats, all four gate verdicts, and the verbatim claim ceiling; filenames are stable/seed-derived (no clock).
- **Eyes unchanged:** the eyes path uses `AnyCodec::Identity` (83 symbols ≥ 29-letter language), is byte-for-byte unchanged from brief 04, and remains the **sole honest-negative** — decode BLOCKED on the unknown mapping. This brief does **not** invent a codec/mapping for the eyes as a finding.
- **Determinism:** every codec search and matched null is bit-for-bit reproducible for a fixed seed.
- **`make verify` green at every step; `make check` green before the final push.** House invariants hold: no `unsafe`, no `unwrap`/`panic`/`indexing_slicing`/`unused_results` in library/CLI code, every public item documented, `--locked`.

## Verification (exactly how to prove it)

- `make verify` after every step; `make check` before the final push.
- **Golden master (brief 01):** confirm `run_cipher_attack`, the null calibrations, the corpus base-7 cross-check, **and the `orders.rs` honeycomb reading-layer statistics** are byte-for-byte unchanged — `codec.rs` must not perturb any existing reported number. Diff the golden-master outputs.
- **New tests in `codec.rs`:**
  - `Identity` identity; `FixedGrouping { 3, 5, Msb, 3 }` matches a couple of hand-computed base-5 trigram values (cross-checked against `src/trigram.rs`); non-multiple length → `LengthNotGroupMultiple`;
  - `Delta` differencing + seed-re-integration round-trips on a synthetic ±1-`C5` stream;
  - `codec_round_trip_ok` holds for an invertible `FixedGrouping` on a full-multiple stream and is honest `false` for a lossy partial group;
  - alphabet-size sanity rejects `Identity` over 5/12 symbols for 29-letter English and accepts a wide-enough `FixedGrouping`;
  - synthetic plant-through-codec → exact planted English recovered (fixed codec, then searched codec), round-trip-consistent + held-out-valid;
  - puzzle `two` (`research/data/practice-puzzles/two`, `{A..L}`, provenance noted) → pipeline runs + high-scoring held-out-validated English candidate logged as HYPOTHESIS; exact-match test present but **pending the maintainer's withheld cleartext constant**;
  - puzzle `one` (`research/data/practice-puzzles/one`, `{0..4}`, provenance noted) → pipeline runs end-to-end; any surviving candidate is logged as a labelled HYPOTHESIS (asserted via the record writer), **no** hard-coded decode string asserted;
  - puzzle `six` (`research/data/practice-puzzles/six`, `{1..6}` **with spaces**, provenance noted) → `FixedGrouping { 2, 6 }` recovery path runs end-to-end; transparent spaces are reinserted at their positions in `rendered_text` and skipped by the bigram scorer; any surviving candidate is logged as a labelled HYPOTHESIS, no hard-coded decode asserted;
  - matched-null-stays-flat under codec search; bounded-search logs-and-skips an out-of-budget codec;
  - determinism: two runs with the same seed produce identical candidates;
  - record renderer emits the claim ceiling + HYPOTHESIS label + both language scores + codec `name()` + all four gate verdicts (pure-string test, no filesystem).
- **CLI smoke (manual, not a test):** `cargo run --locked -- solve --alphabet 01234 --codec-search --input-file research/data/practice-puzzles/one` runs end-to-end and prints a ranked, labelled-HYPOTHESIS result; `cargo run --locked -- solve --alphabet ABCDEFGHIJKL --codec-search --input-file research/data/practice-puzzles/two` likewise; `cargo run --locked -- solve --alphabet 123456 --codec-search --input-file research/data/practice-puzzles/six` exercises the base-6 grouping + transparent-space passthrough. **At test time use the checked-in corpus files, not `/tmp`.**

## Risks & honesty caveats

- **A codec widens the alphabet — it is not a free decode.** A `FixedGrouping`/`Delta` codec just makes a small cipher alphabet *wide enough* for a symbol→letter mapping; it does not by itself read anything. Every surviving candidate still rides codec round-trip + alphabet-size sanity + held-out + matched-null, and is auto-logged as a labelled HYPOTHESIS (`research/gak-threads/candidates/README.md`). The claim ceiling (`:13-14`) is reproduced verbatim in every record.
- **Recovering the corpus samples' English is a GOAL / HYPOTHESIS, never an established decode.** Puzzles `one` and `six` have **no cleartext available to us**; their surviving candidates are logged for human readability confirmation, not asserted as a specific string. Puzzle `two`'s English is **known to the maintainer but withheld / not committed**, so its exact-match assertion stays **pending** that constant — the test must not pretend to know the plaintext before a human-confirmed constant lands (at which point the puzzle is promoted to a known-answer regression). The ±1-`C5` observation (`one`) is a *ciphertext property and a search hint*, **not** a claim of triviality or "no message." Likewise `six`'s preserved-space passthrough is plumbing for readability, not a decode.
- **The eyes remain the sole honest-negative.** This brief uses `AnyCodec::Identity` for the eyes (83 ≥ 29) and does **not** propose a codec or mapping for them as a finding. The eyes' strongest defensible statement is unchanged: *unsolved; decode blocked on the unknown symbol→meaning mapping.* The 83→29 mapping is many-to-one ⇒ non-invertible, so no mapping round-trip exists — held-out + matched-null carry the load there, exactly as in brief 04.
- **Lossy codecs must be honest.** A trailing partial group, or an accept-`0..=82` filter that drops raw `83..=124` values, makes a codec non-invertible: mark `is_invertible() == false`, set `codec_round_trip_ok = false`, and never claim a byte-for-byte round-trip it cannot provide. The raw-`0..=124`-vs-accepted-`0..=82` distinction is the same transcription-risk boundary brief 03's `HoneycombReading` ingest layer names (accepted `0..=82`; `83..=124` rejected) — never conflate the two alphabets.
- **No silent truncation in the search.** Every enumeration cap is documented and every skipped codec is `log()`-ed (overview ground rule + AGENTS.md "no panics or silent failures"). An undocumented skip could hide the very codec that reads a sample.
- **Determinism is a correctness property.** All randomness flows through `SplitMix64` seeded explicitly; never read the clock (records must be reproducible, `README.md:62-64`).
- **Finnish first.** Noita is Finnish; score and log Finnish at least as prominently as English (`README.md:70-72`). A candidate is logged even if low-confidence or failing.
- **Brief-02 / brief-04 / brief-07B coupling.** `AnyCipher` comes from 02; the `codec: AnyCodec` field and the pipeline stage live in brief 04's `Candidate`/`solve`; the repo-wide role-directory move (relocating `codec.rs` under `src/attack/`) is brief 07B. If 02's `AnyCipher` or 04's `Candidate`/`solve` shapes differ from these sketches, follow those briefs and update cross-references here.
- **No big-bang.** Each step lands green on its own; if a step cannot be made independently green it is mis-scoped — re-split it.

## Out of scope / non-goals

- **Inventing a codec/mapping for the EYES as a finding.** The eyes stay the BLOCKED honest-negative; `Identity` is their codec and the decode remains unsolved.
- **New cipher families (brief 02)** and **the symbol→letter mapping search itself (brief 04, reused here unchanged).** This brief adds only the transduction layer ahead of that mapping.
- **The physical move of `codec.rs` into `src/attack/` (brief 07B)** — keep it a flat `pub mod codec;`.
- **A raw `0..=124` trigram ingest layer.** This brief consumes accepted reading-layer symbols and the accept-`0..=82` policy; a general raw-trigram ingest is a separate, out-of-scope layer (brief 03's `HoneycombReading` ingest layer names the same boundary).
- **Changing any reported statistic or decode anywhere in the crate** (behavior-preserving is mandatory; brief 01 pins it, including the `orders.rs` honeycomb statistics).
- **The null/experiment-harness dedup (brief 05)** and **the clap-subcommand registry refactor (brief 08).** This brief reuses `null::fisher_yates`/`SplitMix64`/`add_one_p_value` directly and adds only codec flags to the existing `solve` subcommand.
