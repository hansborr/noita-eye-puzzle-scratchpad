# T01 — Transcription-perturbation harness (shared primitive)

**Tier:** 1 · **Size:** S · **Type:** code · **Status:** Todo
**Depends on:** none · **Conflicts with:** none · **Touches:** new
`src/analysis/perturbation.rs` (+ `src/lib.rs` module decl)

## Goal
A small reusable primitive that enumerates single-orientation-digit
transcription perturbations over a tiny fixed window of the rendered corpus, and
re-derives the reading-layer values so a caller can re-run a claim's verdict on
each what-if transcription.

Keep it minimal — a generator + a verdict-runner over a bounded window, not a
framework.

## Data model (verified — get this right)
- The corpus is `MESSAGES: [Message; 9]` in `src/data/corpus.rs`; each `Message`
  holds `digits: &'static str` — the rendered orientation string (digits
  `0..=4`, with `5` a non-rendered row delimiter). There is no mutable `Corpus`
  type — you perturb a `String` copy of `digits`.
- A *transcription error* is a mis-read orientation digit (`0..=4` → a different
  `0..=4`), at a non-delimiter position. Perturb at this source layer, never the
  reading layer.
- The claims consume reading-layer `TrigramValue`s built by the honeycomb walk:
  build a `GlyphGrid` from the perturbed digit string and read it via
  `orders::accepted_honeycomb_order()` + `orders::read_corpus_message_values`
  (see `src/analysis/orders.rs`). So the harness perturbs digits → rebuilds grid →
  yields reading-layer values; the caller's verdict closure consumes those.

## Steps
1. `struct DigitWindow { message: usize, start: usize, len: usize }` over
   non-delimiter digit indices. Keep windows tiny (the load-bearing AGL/Stutter
   regions are a handful of digits).
2. `fn single_digit_perturbations(window) -> impl Iterator<Item=PerturbedMessage>`:
   for each non-`5` digit in the window, yield the 4 alternative orientations.
   Count = `(non-delimiter digits in window) * 4`. Exhaustive and tiny.
3. (Optional, gated by a flag) double-digit perturbations — only over a window
   small enough that `C(k,2)*16` stays in the low hundreds; refuse / assert if
   the window would explode (this is the guardrail against the 2.36M-variant trap).
4. `fn certify<V: Fn(&[Vec<TrigramValue>]) -> bool>(window, max_changes, verdict)
   -> CertificateReport` re-deriving reading-layer values per variant and reporting:
   total variants, count still-holding, and the first break (message/digit-
   index/old→new), or "robust to all N".
5. Unit test on a trivial verdict (e.g. "first reading-layer symbol unchanged") that
   pins the variant count and the break-detection.

## Definition of done
- [ ] Compiles under `-D warnings`; rustdoc present; `make verify` green.
- [ ] Variant count asserted in a test; double-change explosion guard asserted.
- [ ] No new dependency; reuses `corpus.rs` / `orders.rs` types (no invented `Corpus`).
- [ ] `docs/deslop-audit` merged in; committed.

## Honesty guardrails
This produces counterfactual transcriptions for sensitivity analysis only.
Nothing here changes the verified, Ghidra-confirmed transcription or any standing
verdict. Label outputs "sensitivity / what-if," never as alternative glyph readings.

## Pointers
- `src/data/corpus.rs`: `Message`, `digits` (~:88-98), `orientations()` (~:136)
- `src/analysis/orders.rs`: `GlyphGrid` (`from_message`/`from_orientation_rows`),
  `accepted_honeycomb_order` (~:397), `read_corpus_message_values` (~:483)
- `src/nulls/` (style reference; do not import an RNG crate)
